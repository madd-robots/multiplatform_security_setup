# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for Stage 8 device assurance.

    assurance.device          (assurance.read)            report on a device: what it exposes, what cannot
                                                          be verified, inconsistencies, drive registry status
    assurance.drives          (assurance.read)            the drive registry
    assurance.reports         (assurance.read)            list reports
    assurance.report          (assurance.read)            one report with its signatures (for export)
    assurance.sign            (assurance.manage, touch)   owner signature over a report digest
    assurance.artifacts_set   (assurance.manage, touch)   install an owner-signed trusted-artifact list
    assurance.artifacts       (assurance.read)            the current list
    assurance.artifact_verify (assurance.read)            hash a passed file and compare with the list

Erase-verification reports are created by ``erase_hook``, which the
surface test (device.surface_test) calls when it completes.

Artifact lists: an owner-signed document of (name, SHA-256, size, note),
for example installer images, firmware update files or tools the owner
checked on a trusted machine. A file matches only by its full hash and
size. A list signed by a key that has since been revoked is not used.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, IntegrityError, NotFound, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..common.text import display_text
from ..devices.assess import SEV_BLOCKING, SEV_REVIEW
from ..devices.handlers import KNAME_PATTERN
from ..devices.operations import REPORT_SPEC as DEVICE_REPORT_SPEC
from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_ARTIFACTS, NS_REPORT, SCHEME, SigCheck, check_armor
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.session import Session
from ..vault.custody import utc_timestamp
from ..vault.operations import _check_fd
from .drives import DriveRegistry
from .facts import analyse
from .reports import REPORT_ID, ReportStore

ARTIFACT_DOMAIN = "guardian/artifact-list/v1"
SHA = r"[0-9a-f]{64}"
ARTIFACT_LIST_SPEC = S.Obj({
    "format": S.Const("guardian-artifact-list"),
    "version": S.Const(1),
    "trust_anchor": S.Str(pattern=SHA, max_len=64),
    "created": S.Str(pattern=r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", max_len=20),
    "artifacts": S.List(S.Obj({"name": S.Str(pattern=r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,127}", max_len=128),
                               "sha256": S.Str(pattern=SHA, max_len=64),
                               "size": S.Int(min_value=0, max_value=2 ** 53 - 1),
                               "note": S.Str(max_len=200)}), min_items=1, max_items=4096),
})
ENVELOPE_SPEC = S.Obj({"list": S.Obj({}, allow_extra=True), "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                       "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)})
DEVICE_STATEMENT = [
    "Records what the device presents through USB, SCSI and MMC interfaces at the time of the check.",
    "Firmware indicators are labels the firmware reports about itself; controller firmware is not verified.",
    "A clean report does not prove the device is free of malicious firmware.",
]
ERASE_STATEMENT_PASSED = [
    "Every byte of the logical address space was overwritten with a pattern from a fresh random key and read "
    "back without the page cache; all of it matched, which also proves the advertised capacity.",
    "Spare and over-provisioned flash and the controller firmware are outside the logical address space and "
    "were not reached.",
]
ERASE_STATEMENT_FAILED = [
    "The overwrite or the read-back did not complete with matching data; the drive must not be used as a "
    "Guardian drive.",
]
ARTIFACT_STATEMENT = [
    "Compares the SHA-256 and size of the presented file with an owner-signed list of trusted artifacts.",
    "A match shows the file is the one the owner listed, not that the listed file is safe.",
]


def artifact_list_digest(doc: Dict[str, Any]) -> bytes:
    return canonical_digest(ARTIFACT_DOMAIN, doc)


class AssuranceService:
    def __init__(self, directory: Path, trust: TrustStore, sig_check: SigCheck, instance_id: str, *,
                 inspect_device: Callable[[str], Dict[str, Any]], audit: Optional[Any] = None):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.trust = trust
        self.sig_check = sig_check
        self.inspect_device = inspect_device
        self.reports = ReportStore(self.directory / "reports", instance_id, audit=audit)
        self.drives = DriveRegistry(self.directory / "drives")
        self.artifacts_path = self.directory / "artifacts.json"
        self._lock = threading.Lock()

    # -- devices ---------------------------------------------------------------------------------

    def device(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        report = S.validate(DEVICE_REPORT_SPEC, self.inspect_device(params["kname"]), "$.report")
        dev = report["device"]
        facts = analyse(dev)
        registry, changes = self.drives.check(dev, report["fingerprint"])
        findings = list(report["findings"]) + facts["findings"]
        if registry == "CHANGED":
            findings.append({"code": "IDENTITY_CHANGED_SINCE_VERIFIED", "severity": SEV_BLOCKING,
                             "detail": "this drive was verified with a different identity: " + "; ".join(changes)})
        elif registry == "REJECTED":
            findings.append({"code": "DRIVE_REJECTED", "severity": SEV_BLOCKING,
                             "detail": "this drive was rejected earlier"})
        severities = {f["severity"] for f in findings}
        result = "BLOCKED" if SEV_BLOCKING in severities else "REVIEW REQUIRED" if SEV_REVIEW in severities \
            else "PASS"
        usb = dev.get("usb") or {}
        subject = {"kname": params["kname"], "fingerprint": report["fingerprint"],
                   "vendor_id": usb.get("vendor_id"), "product_id": usb.get("product_id"),
                   "size_bytes": dev.get("size_bytes")}
        body = {"registry": registry, "registry_changes": changes, "findings": findings,
                "firmware_indicators": facts["firmware_indicators"],
                "advertised_capacity": facts["advertised_capacity"], "not_verifiable": facts["not_verifiable"],
                "identity": report.get("identity", {})}
        created = self.reports.create("device_assurance", principal=principal.name, subject=subject, result=result,
                                      body=body, statement=DEVICE_STATEMENT)
        return dict(created, subject=subject, body=body)

    def erase_hook(self, principal: str, before: Dict[str, Any], result: Dict[str, Any],
                   after: Dict[str, Any]) -> Dict[str, Any]:
        """Called by the surface test when it completes: erase-verification report, drive registry."""
        dev = after["device"]
        outcome = "CANCELLED" if result.get("cancelled") else "PASSED" if result.get("passed") else "FAILED"
        subject = {"kname": dev.get("kname"), "fingerprint": after["fingerprint"], "size_bytes": dev["size_bytes"]}
        body = {k: result.get(k) for k in ("size_bytes", "chunk_size", "chunks", "direct_io", "bytes_written",
                                           "write_error_offset", "bad_chunks", "unreadable_chunks", "bad_ranges",
                                           "bad_ranges_truncated", "first_bad_offset", "verified_bytes",
                                           "cancelled", "passed", "seconds")}
        body["fingerprint_before"] = before["fingerprint"]
        body["firmware_indicators"] = analyse(dev)["firmware_indicators"]
        created = self.reports.create("erase_verification", principal=principal, subject=subject, result=outcome,
                                      body=body,
                                      statement=ERASE_STATEMENT_PASSED if outcome == "PASSED" else ERASE_STATEMENT_FAILED)
        registry = None
        if outcome == "PASSED":
            registry = self.drives.record_verified(dev, after["fingerprint"], created["report_id"])["state"]
        return {"report_id": created["report_id"], "registry": registry}

    def drives_list(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return {"drives": self.drives.entries()}

    # -- reports ---------------------------------------------------------------------------------

    def report_list(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return {"reports": self.reports.list(params["since"], params["limit"])}

    def report_get(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return self.reports.get(params["report_id"])

    def sign_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        try:
            digest = bytes.fromhex(self.reports.get(params["report_id"])["digest"])
            TrustVerifier(self.trust.require_state(), self.sig_check, NS_REPORT).verify(
                SCHEME, params["key_id"], digest, check_armor(params["signature"].encode("ascii")))
        except (GuardianError, UnicodeEncodeError):
            return False
        return True

    def sign(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return self.reports.add_signature(params["report_id"], params["key_id"], params["signature"].encode("ascii"),
                                          self.trust.require_state(), self.sig_check)

    # -- artifacts -------------------------------------------------------------------------------

    def _check_list(self, envelope: Any) -> Dict[str, Any]:
        env = S.validate(ENVELOPE_SPEC, envelope, "$.envelope")
        doc = S.validate(ARTIFACT_LIST_SPEC, env["list"], "$.list")
        state = self.trust.require_state()
        if doc["trust_anchor"] != state.anchor:
            raise IntegrityError("artifact list belongs to another trust anchor", code="ARTIFACT_LIST_INVALID")
        try:
            TrustVerifier(state, self.sig_check, NS_ARTIFACTS).verify(
                SCHEME, env["key_id"], artifact_list_digest(doc), check_armor(env["signature"].encode("ascii")))
        except (GuardianError, UnicodeEncodeError) as exc:
            raise IntegrityError("artifact list signature invalid: %s" % getattr(exc, "message", exc),
                                 code="ARTIFACT_LIST_INVALID") from None
        return doc

    def artifacts_proof(self, principal: authz.Principal, params: Dict[str, Any],
                        session: Optional[Session]) -> bool:
        try:
            self._check_list(params["envelope"])
        except GuardianError:
            return False
        return True

    def artifacts_set(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        doc = self._check_list(params["envelope"])
        with self._lock:
            atomic_write(self.artifacts_path, canonical_dumps(params["envelope"]))
        return {"artifacts": len(doc["artifacts"]), "created": doc["created"]}

    def _current_list(self) -> Optional[Dict[str, Any]]:
        if not self.artifacts_path.exists():
            return None
        envelope = canonical_loads(read_file_bounded(self.artifacts_path, 4 * 1024 * 1024, require_private=True),
                                   require_canonical=True, max_bytes=4 * 1024 * 1024)
        return self._check_list(envelope)  # re-verified on every use: a revoked signer invalidates the list

    def artifacts(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        doc = self._current_list()
        return {"installed": doc is not None, "list": doc}

    def artifact_verify(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        fds = session.take_fds()
        try:
            st = _check_fd(fds[0], "file")
            h = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fds[0], 1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
        finally:
            for fd in fds:
                os.close(fd)
        if size != st.st_size and stat.S_ISREG(st.st_mode):
            raise IntegrityError("file changed while it was hashed", code="ARTIFACT_CHANGED")
        doc = self._current_list()
        if doc is None:
            raise NotFound("no trusted artifact list is installed", code="NO_ARTIFACT_LIST")
        digest = h.hexdigest()
        matches = [a for a in doc["artifacts"] if a["sha256"] == digest and a["size"] == size]
        name = params.get("name")
        if name is not None:
            listed = [a for a in doc["artifacts"] if a["name"] == name]
            result = "VERIFIED" if any(a in matches for a in listed) else "MISMATCH" if listed else "NOT LISTED"
        else:
            result = "VERIFIED" if matches else "NOT LISTED"
        subject = {"name": display_text(name, 128) if name else None, "sha256": digest, "size": size}
        body = {"matched": [a["name"] for a in matches], "list_created": doc["created"]}
        created = self.reports.create("artifact_verification", principal=principal.name, subject=subject,
                                      result=result, body=body, statement=ARTIFACT_STATEMENT)
        return dict(created, subject=subject, matched=body["matched"])

    def operations(self) -> Iterable[Operation]:
        rid = S.Str(pattern=REPORT_ID, max_len=24)
        return (
            Operation("assurance.device", "assurance.read", S.Obj({"kname": S.Str(pattern=KNAME_PATTERN, max_len=32)}),
                      inline=self.device),
            Operation("assurance.drives", "assurance.read", S.EMPTY, inline=self.drives_list),
            Operation("assurance.reports", "assurance.read",
                      S.Obj({"since": S.Int(min_value=0, max_value=10 ** 6), "limit": S.Int(min_value=1, max_value=64)}),
                      inline=self.report_list),
            Operation("assurance.report", "assurance.read", S.Obj({"report_id": rid}), inline=self.report_get),
            Operation("assurance.sign", "assurance.manage",
                      S.Obj({"report_id": rid, "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                             "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}),
                      inline=self.sign, owner_proof=self.sign_proof),
            Operation("assurance.artifacts_set", "assurance.manage", S.Obj({"envelope": S.Obj({}, allow_extra=True)}),
                      inline=self.artifacts_set, owner_proof=self.artifacts_proof),
            Operation("assurance.artifacts", "assurance.read", S.EMPTY, inline=self.artifacts),
            Operation("assurance.artifact_verify", "assurance.read",
                      S.Obj({"name": S.Str(pattern=r"[A-Za-z0-9][A-Za-z0-9 ._+-]{0,127}", max_len=128)},
                            optional=("name",)),
                      inline=self.artifact_verify, session_aware=True, fds=(1, 1)),
        )
