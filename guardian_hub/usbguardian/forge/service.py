# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for Guardian Forge (Guardian Main only).

    forge.prepare  (forge.prepare)            build descriptor + package manifest, return digest
    forge.write    (forge.build, 1 touch)     the owner's deploy-namespace signature is the proof;
                                              write to a passed fd, read back, record in registry
    forge.list     (forge.prepare)            registry entries
    forge.retire   (forge.build, 1 touch)     mark a deployment retired at Main (D5 pending)

The code shipped is the broker's own code tree, which a root broker has
already verified as root-owned and protected (runtime/workers.py).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from ..common.canonical import canonical_dumps
from ..common.errors import IntegrityError, NotFound, ValidationError
from ..common.space import DEFAULT_POLICY, SpacePolicy
from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_DEPLOY, SCHEME, SigCheck
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.session import Session
from ..vault.custody import CustodyStore, utc_timestamp
from ..vault.operations import _check_fd, _Presigned
from ..vault.package import build_manifest, manifest_digest, readback_verify, write_package
from .descriptor import CODE_PREFIX, DESCRIPTOR_NAME, INSTANCE_ID_PATTERN, TRUST_LOG_NAME, build_descriptor, \
    collect_code
from .profiles import PLATFORMS, PROFILES, check_platform
from .registry import DeploymentRegistry

CODE_ROOT = Path(__file__).resolve().parents[2]  # directory holding guardian.py


def trust_log_bytes(envelopes: Iterable[Any]) -> bytes:
    return b"".join(canonical_dumps(e) + b"\n" for e in envelopes)


class ForgeService:
    def __init__(self, store: CustodyStore, trust: TrustStore, sig_check: SigCheck, registry: DeploymentRegistry,
                 instance_id: str, *, code_root: Path = CODE_ROOT, space_policy: SpacePolicy = DEFAULT_POLICY):
        self.store = store
        self.trust = trust
        self.sig_check = sig_check
        self.registry = registry
        self.instance_id = instance_id
        self.code_root = Path(code_root)
        self.space_policy = space_policy

    def _verifier(self) -> TrustVerifier:
        return TrustVerifier(self.trust.require_state(), self.sig_check, NS_DEPLOY)

    def prepare(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        check_platform(params["platform"])
        state = self.trust.require_state()
        if params["key_id"] not in state.active:
            raise ValidationError("key is not an active owner key")
        if params["instance_id"] == self.instance_id or self.registry.is_known(params["instance_id"]):
            raise ValidationError("instance id already used", code="INSTANCE_EXISTS")
        code_records = []
        code = []
        for rel, path in collect_code(self.code_root):
            rec = self.store.intake(path, CODE_PREFIX + rel)
            code_records.append(rec)
            code.append({"path": rel, "sha256": rec["sha256"], "length": rec["length"]})
        descriptor = build_descriptor(
            deployment_id=secrets.token_hex(16), instance_id=params["instance_id"], platform=params["platform"],
            profile=params["profile"], issued=utc_timestamp(),
            trust={"anchor": state.anchor, "head": state.head, "seq": state.seq},
            issuer_instance=self.instance_id, key_id=params["key_id"], code=code)
        records = [self.store.intake_bytes(canonical_dumps(descriptor), DESCRIPTOR_NAME),
                   self.store.intake_bytes(trust_log_bytes(self.trust.envelopes()), TRUST_LOG_NAME)] + code_records
        manifest = build_manifest(records, instance_id=self.instance_id, scheme=SCHEME, key_id=params["key_id"],
                                  transfer_id=descriptor["deployment_id"])
        session.put_pending("forge:" + descriptor["deployment_id"], (manifest, descriptor))
        return {"deployment_id": descriptor["deployment_id"], "digest": manifest_digest(manifest).hex(),
                "namespace": NS_DEPLOY, "instance_id": descriptor["instance_id"], "platform": descriptor["platform"],
                "profile": descriptor["profile"], "capabilities": descriptor["capabilities"],
                "code_files": len(code), "trust_seq": state.seq}

    def _pending(self, params: Dict[str, Any], session: Optional[Session]) -> Any:
        pending = session.get_pending("forge:" + params["deployment_id"]) if session is not None else None
        if pending is None:
            raise NotFound("no prepared deployment with this id on this connection")
        return pending

    def write_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        manifest, _ = self._pending(params, session)
        try:
            self._verifier().verify(SCHEME, manifest["sender"]["key_id"], manifest_digest(manifest),
                                    params["signature"].encode("ascii"))
        except (IntegrityError, UnicodeEncodeError):
            return False
        return True

    def write(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        manifest, descriptor = self._pending(params, session)
        fds = session.take_fds()
        try:
            st = _check_fd(fds[0], "file", writable=True)
            if st.st_size != 0:
                raise ValidationError("the output file must be empty")
            signer = _Presigned(manifest["sender"]["key_id"], manifest_digest(manifest),
                                params["signature"].encode("ascii"))
            written = write_package(fds[0], self.store, manifest, signer, space_policy=self.space_policy)
            readback_verify(fds[0], self._verifier(), written)
        finally:
            for fd in fds:
                os.close(fd)
        self.registry.add({"instance_id": descriptor["instance_id"], "deployment_id": descriptor["deployment_id"],
                           "platform": descriptor["platform"], "profile": descriptor["profile"],
                           "issued": descriptor["issued"], "package_sha256": written["package_sha256"],
                           "status": "active", "retired": None})
        session.drop_pending("forge:" + params["deployment_id"])
        return {"deployment_id": descriptor["deployment_id"], "instance_id": descriptor["instance_id"],
                "package_sha256": written["package_sha256"], "package_length": written["package_length"],
                "trust_anchor": descriptor["trust"]["anchor"], "readback_verified": True}

    def list(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return {"deployments": self.registry.entries()}

    def retire(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return self.registry.retire(params["instance_id"], utc_timestamp())

    def operations(self) -> Iterable[Operation]:
        did = S.Str(pattern=r"[0-9a-f]{32}", max_len=32)
        iid = S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64)
        return (
            Operation("forge.prepare", "forge.prepare",
                      S.Obj({"instance_id": iid, "platform": S.Enum(PLATFORMS), "profile": S.Enum(PROFILES),
                             "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71)}),
                      inline=self.prepare, session_aware=True),
            Operation("forge.write", "forge.build",
                      S.Obj({"deployment_id": did, "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}),
                      inline=self.write, session_aware=True, owner_proof=self.write_proof, fds=(1, 1)),
            Operation("forge.list", "forge.prepare", S.EMPTY, inline=self.list),
            Operation("forge.retire", "forge.build", S.Obj({"instance_id": iid}), inline=self.retire),
        )
