# SPDX-License-Identifier: GPL-3.0-or-later
"""Target side: verify a deployment package and extract its code.

Trust comes from outside the package. The owner brings the pinned anchor
and a trust log on known-good media (the Rescue USB, or an existing
installation's state). The package must verify against that, in the deploy
namespace, before any of its contents are used. The package's own trust
snapshot must agree with the brought log; if they diverge it is a fork and
the deployment is refused.
"""

from __future__ import annotations

import datetime
import os
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

from ..common.canonical import canonical_loads
from ..common.errors import GuardianError, IntegrityError, SecurityViolation, ValidationError
from ..common.fsutil import open_dir_nofollow, write_all
from ..common.names import validate_relative_path
from ..identity.sshkeys import HARDWARE_KEY_TYPES
from ..identity.sshsig import NS_DEPLOY, SigCheck
from ..identity.trust import TrustVerifier, check_extension, event_digest, replay
from ..vault.package import verify_package
from .descriptor import CODE_PREFIX, DESCRIPTOR_NAME, TRUST_LOG_NAME, check_descriptor

MAX_DESCRIPTOR = 1024 * 1024
MAX_TRUST_LOG = 8 * 1024 * 1024


def parse_trust_log(data: bytes) -> List[Any]:
    return [canonical_loads(line, require_canonical=True, max_bytes=256 * 1024) for line in data.split(b"\n") if line]


class _DeploymentSink:
    def __init__(self, extract_root: Optional[Path]):
        self.root_fd = open_dir_nofollow(extract_root) if extract_root is not None else None
        self.buffers: Dict[int, bytearray] = {}
        self.paths: List[str] = []
        self._out = -1
        self._index = -1

    def close(self) -> None:
        if self._out >= 0:
            os.close(self._out)
            self._out = -1
        if self.root_fd is not None:
            os.close(self.root_fd)
            self.root_fd = None

    def accept_manifest(self, manifest: Dict[str, Any]) -> None:
        names = [o["source_name"] for o in manifest["objects"]]
        if names[:2] != [DESCRIPTOR_NAME, TRUST_LOG_NAME] or len(names) < 3:
            raise SecurityViolation("not a Guardian deployment package", code="NOT_A_DEPLOYMENT")
        for name in names[2:]:
            if not name.startswith(CODE_PREFIX):
                raise SecurityViolation("unexpected object in deployment", code="NOT_A_DEPLOYMENT")
            validate_relative_path(name[len(CODE_PREFIX):])
            self.paths.append(name[len(CODE_PREFIX):])
        if len(set(self.paths)) != len(self.paths):
            raise SecurityViolation("duplicate code path", code="NOT_A_DEPLOYMENT")
        if manifest["objects"][0]["length"] > MAX_DESCRIPTOR or manifest["objects"][1]["length"] > MAX_TRUST_LOG:
            raise SecurityViolation("descriptor or trust log too large", code="NOT_A_DEPLOYMENT")

    def begin(self, index: int, obj: Dict[str, Any]) -> None:
        self._index = index
        if index < 2:
            self.buffers[index] = bytearray()
            return
        if self.root_fd is None:
            return
        parts = validate_relative_path(self.paths[index - 2])
        dir_fd = os.dup(self.root_fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=dir_fd)
                except FileExistsError:
                    pass
                nxt = open_dir_nofollow(part, dir_fd=dir_fd)
                os.close(dir_fd)
                dir_fd = nxt
            self._out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o644, dir_fd=dir_fd)
            os.fchmod(self._out, 0o644)
        finally:
            os.close(dir_fd)

    def write(self, data: bytes) -> None:
        if self._index < 2:
            self.buffers[self._index] += data
        elif self._out >= 0:
            write_all(self._out, data)

    def end(self, index: int) -> None:
        if self._out >= 0:
            os.fsync(self._out)
            os.close(self._out)
            self._out = -1


def _parse_time(ts: str) -> datetime.datetime:
    return datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def verify_deployment(fd: int, trust_envelopes: List[Any], anchor: str, sig_check: SigCheck, *,
                      allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES, expected_platform: Optional[str] = None,
                      extract_to: Optional[Path] = None, require_end: bool = True,
                      now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """Verify a deployment; with ``extract_to`` (an empty directory) also write its code there.

    On any failure the caller must discard ``extract_to``: files written before
    the failure was detected are not trustworthy.
    """
    state = replay(trust_envelopes, sig_check, anchor=anchor, allowed_types=allowed_types)
    sink = _DeploymentSink(extract_to)
    try:
        report = verify_package(fd, TrustVerifier(state, sig_check, NS_DEPLOY), sink=sink, require_end=require_end)
    finally:
        sink.close()
    try:
        descriptor = check_descriptor(canonical_loads(bytes(sink.buffers[0]), require_canonical=True,
                                                      max_bytes=MAX_DESCRIPTOR))
        package_log = parse_trust_log(bytes(sink.buffers[1]))
    except GuardianError as exc:
        raise IntegrityError("deployment descriptor or trust snapshot invalid: %s" % exc.message,
                             code="DEPLOYMENT_INVALID") from None
    if descriptor["deployment_id"] != report["transfer_id"] or descriptor["issuer"]["key_id"] != report["key_id"]:
        raise IntegrityError("descriptor does not match the signed package", code="DEPLOYMENT_INVALID")
    if descriptor["trust"]["anchor"] != anchor:
        raise IntegrityError("deployment was built for a different trust anchor", code="TRUST_ANCHOR_MISMATCH")
    shorter, longer = sorted((list(trust_envelopes), package_log), key=len)
    check_extension(shorter, longer)  # raises TRUST_FORK if the two logs diverge
    if not package_log or descriptor["trust"]["seq"] != len(package_log) - 1 or \
            descriptor["trust"]["head"] != event_digest(package_log[-1]["event"]).hex():
        raise IntegrityError("descriptor trust head does not match its snapshot", code="DEPLOYMENT_INVALID")
    objects = report["manifest"]["objects"][2:]
    inventory = [(c["path"], c["sha256"], c["length"]) for c in descriptor["code"]]
    shipped = [(o["source_name"][len(CODE_PREFIX):], o["sha256"], o["length"]) for o in objects]
    if inventory != shipped:
        raise IntegrityError("code inventory does not match the package", code="DEPLOYMENT_INVALID")
    if expected_platform is not None and descriptor["platform"] != expected_platform:
        raise ValidationError("deployment is for platform %s" % descriptor["platform"], code="WRONG_PLATFORM")
    if descriptor["expires"] is not None:
        current = now or datetime.datetime.now(datetime.timezone.utc)
        if current >= _parse_time(descriptor["expires"]):
            raise IntegrityError("deployment has expired", code="DEPLOYMENT_EXPIRED")
    return {"descriptor": descriptor, "package_sha256": report["package_sha256"], "trust_state": state,
            "package_trust_log": package_log}
