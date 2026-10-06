# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for custody and transfers (Stage 5 wiring of Stage 4).

Every payload arrives or leaves through a file descriptor the client opened
and passed (SCM_RIGHTS). The root broker never opens a path a client names,
so a client cannot use it to read or write files it could not access itself.
Payload bytes never travel inside JSON frames (D6).

    vault.intake       owner assertion (1 touch)   files -> custody records
    transfer.prepare   no owner factor             records -> manifest + digest to sign
    transfer.write     signed manifest (1 touch)   package -> writable fd, then read-back
    transfer.verify    no owner factor             full verification, nothing released
    transfer.release   owner assertion (1 touch)   verify, then release into a dir fd
"""

from __future__ import annotations

import fcntl
import os
import stat
from typing import Any, Dict, Iterable, Optional

from ..common.errors import IntegrityError, NotFound, ValidationError
from ..common.space import DEFAULT_POLICY, SpacePolicy
from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_TRANSFER, SCHEME, SigCheck
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.ipc import MAX_FDS
from ..runtime.session import Session
from .custody import MAX_SOURCE_NAME, CustodyStore
from .package import build_manifest, manifest_digest, readback_verify, verify_package, write_package
from .release import NAME_POLICIES, release_package

INSTANCE_ID_PATTERN = r"[a-z0-9][a-z0-9-]{0,63}"


def _check_fd(fd: int, kind: str, writable: bool = False) -> os.stat_result:
    st = os.fstat(fd)
    ok_type = stat.S_ISDIR(st.st_mode) if kind == "dir" else stat.S_ISREG(st.st_mode)
    access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    ok_access = access == os.O_RDWR if writable else access in (os.O_RDONLY, os.O_RDWR)
    if not ok_type or not ok_access:
        raise ValidationError("passed descriptor must be a %s opened %s" % (
            "directory" if kind == "dir" else "regular file", "read-write" if writable else "for reading"))
    return st


class _Presigned:
    """Signer that returns the signature the owner already made for this exact digest."""

    scheme = SCHEME

    def __init__(self, key_id: str, digest: bytes, signature: bytes):
        self.key_id = key_id
        self._digest = digest
        self._signature = signature

    def sign(self, digest: bytes) -> bytes:
        if digest != self._digest:
            raise IntegrityError("manifest changed after it was signed")
        return self._signature


class VaultService:
    def __init__(self, store: CustodyStore, trust: TrustStore, sig_check: SigCheck, instance_id: str, *,
                 space_policy: SpacePolicy = DEFAULT_POLICY):
        self.space_policy = space_policy
        self.store = store
        self.trust = trust
        self.sig_check = sig_check
        self.instance_id = instance_id

    def _verifier(self) -> TrustVerifier:
        return TrustVerifier(self.trust.require_state(), self.sig_check, NS_TRANSFER)

    # -- operations --------------------------------------------------------

    def intake(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        fds = session.take_fds()
        try:
            if len(fds) != len(params["names"]):
                raise ValidationError("one name per passed file is required")
            for fd in fds:
                _check_fd(fd, "file")
            return {"records": [self.store.intake(fd, name) for fd, name in zip(fds, params["names"])]}
        finally:
            for fd in fds:
                os.close(fd)

    def prepare(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        if params["key_id"] not in self.trust.require_state().active:
            raise ValidationError("key is not an active owner key")
        records = [self.store.load_record(rid) for rid in params["record_ids"]]  # re-verifies every object
        manifest = build_manifest(records, instance_id=self.instance_id, scheme=SCHEME, key_id=params["key_id"])
        session.put_pending(manifest["transfer_id"], manifest)
        return {"transfer_id": manifest["transfer_id"], "manifest": manifest,
                "digest": manifest_digest(manifest).hex(), "namespace": NS_TRANSFER}

    def _pending(self, params: Dict[str, Any], session: Optional[Session]) -> Dict[str, Any]:
        manifest = session.get_pending(params["transfer_id"]) if session is not None else None
        if manifest is None:
            raise NotFound("no prepared transfer with this id on this connection")
        return manifest

    def write_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        """The owner's signature over this exact manifest is the owner proof for writing it."""
        manifest = self._pending(params, session)
        try:
            self._verifier().verify(SCHEME, manifest["sender"]["key_id"], manifest_digest(manifest),
                                    params["signature"].encode("ascii"))
        except (IntegrityError, UnicodeEncodeError):
            return False
        return True

    def write(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        manifest = self._pending(params, session)
        fds = session.take_fds()
        try:
            st = _check_fd(fds[0], "file", writable=True)
            if st.st_size != 0:
                raise ValidationError("the output file must be empty")
            signer = _Presigned(manifest["sender"]["key_id"], manifest_digest(manifest),
                                params["signature"].encode("ascii"))
            written = write_package(fds[0], self.store, manifest, signer, space_policy=self.space_policy)
            readback = readback_verify(fds[0], self._verifier(), written)
        finally:
            for fd in fds:
                os.close(fd)
        session.drop_pending(params["transfer_id"])
        return {"transfer_id": written["transfer_id"], "package_sha256": written["package_sha256"],
                "package_length": written["package_length"], "manifest_digest": written["manifest_digest"],
                "readback_verified": readback["package_sha256"] == written["package_sha256"]}

    def verify(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        fds = session.take_fds()
        try:
            _check_fd(fds[0], "file")
            report = verify_package(fds[0], self._verifier(), start=params["offset"])
        finally:
            for fd in fds:
                os.close(fd)
        manifest = report.pop("manifest")
        report["objects"] = [{k: o[k] for k in ("sha256", "length", "source_name")} for o in manifest["objects"]]
        report["sender"] = manifest["sender"]
        return report

    def release(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        fds = session.take_fds()
        try:
            _check_fd(fds[0], "file")
            _check_fd(fds[1], "dir")
            return release_package(fds[0], self._verifier(), dest_fd=fds[1], owner=(session.uid, session.gid),
                                   name_policy=params["name_policy"], space_policy=self.space_policy)
        finally:
            for fd in fds:
                os.close(fd)

    def operations(self) -> Iterable[Operation]:
        names = S.List(S.Str(max_len=MAX_SOURCE_NAME), min_items=1, max_items=MAX_FDS)
        record_ids = S.List(S.Str(pattern=r"[0-9a-f]{32}", max_len=32), min_items=1, max_items=4096, unique=True)
        transfer_id = S.Str(pattern=r"[0-9a-f]{32}", max_len=32)
        return (
            Operation("vault.intake", "vault.write", S.Obj({"names": names}), inline=self.intake,
                      session_aware=True, fds=(1, MAX_FDS), requires_active=True, pause_class="intake"),
            Operation("transfer.prepare", "vault.prepare",
                      S.Obj({"record_ids": record_ids, "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71)}),
                      inline=self.prepare, session_aware=True),
            Operation("transfer.write", "vault.write",
                      S.Obj({"transfer_id": transfer_id, "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}),
                      inline=self.write, session_aware=True, owner_proof=self.write_proof, fds=(1, 1),
                      requires_active=True, pause_class="transfer_write"),
            Operation("transfer.verify", "vault.verify",
                      S.Obj({"offset": S.Int(min_value=0, max_value=2 ** 53 - 1)}),
                      inline=self.verify, session_aware=True, fds=(1, 1)),
            Operation("transfer.release", "vault.read", S.Obj({"name_policy": S.Enum(NAME_POLICIES)}),
                      inline=self.release, session_aware=True, fds=(2, 2), pause_class="release"),
        )


__all__ = ["VaultService", "INSTANCE_ID_PATTERN"]
