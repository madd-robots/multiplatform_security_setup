# SPDX-License-Identifier: GPL-3.0-or-later
"""Assurance reports: canonical documents, recorded in the audit ledger, optionally owner-signed.

A report states what Guardian observed and, in ``statement``, what that
does and does not show. Its digest (domain ``guardian/report/v1``) goes
into the audit ledger when it is created, so a later edit is detectable.
The owner can sign it (namespace ``guardian-report@v1``, one touch);
an exported report (document plus signatures) is checked on any instance
with ``verify_export`` against a pinned trust log, using public keys only.
"""

from __future__ import annotations

import os
import re
import secrets
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import APP_VERSION
from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, IntegrityError, NotFound, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..identity.sshkeys import HARDWARE_KEY_TYPES, KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_REPORT, SCHEME, SigCheck, check_armor
from ..identity.trust import TrustState, TrustVerifier, replay
from ..runtime import schema as S
from ..vault.custody import utc_timestamp

REPORT_DOMAIN = "guardian/report/v1"
KINDS = ("device_assurance", "erase_verification", "artifact_verification")
REPORT_ID = r"[0-9a-f]{24}"
MAX_REPORT = 512 * 1024

REPORT_SPEC = S.Obj({
    "format": S.Const("guardian-report"),
    "version": S.Const(1),
    "kind": S.Enum(KINDS),
    "report_id": S.Str(pattern=REPORT_ID, max_len=24),
    "created": S.Str(pattern=r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", max_len=20),
    "instance_id": S.Str(pattern=r"[a-z0-9][a-z0-9-]{0,63}", max_len=64),
    "guardian_version": S.Str(max_len=16),
    "principal": S.Str(max_len=64),
    "subject": S.Obj({}, allow_extra=True),
    "result": S.Str(pattern=r"[A-Z][A-Z_ ]{1,40}", max_len=40),
    "body": S.Obj({}, allow_extra=True),
    "statement": S.List(S.Str(max_len=400), max_items=16),
})
SIGNATURE_SPEC = S.List(S.Obj({"key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                               "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}), max_items=4)
EXPORT_SPEC = S.Obj({"report": S.Obj({}, allow_extra=True), "signatures": SIGNATURE_SPEC})


def report_digest(report: Dict[str, Any]) -> bytes:
    return canonical_digest(REPORT_DOMAIN, report)


class ReportStore:
    def __init__(self, directory: Path, instance_id: str, *, audit: Optional[Any] = None):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.instance_id = instance_id
        self.audit = audit
        self._lock = threading.Lock()

    def _path(self, report_id: str, suffix: str = ".json") -> Path:
        if not re.fullmatch(REPORT_ID, report_id):
            raise ValidationError("invalid report id")
        return self.directory / (report_id + suffix)

    def create(self, kind: str, *, principal: str, subject: Dict[str, Any], result: str, body: Dict[str, Any],
               statement: List[str]) -> Dict[str, Any]:
        report = S.validate(REPORT_SPEC, {
            "format": "guardian-report", "version": 1, "kind": kind, "report_id": secrets.token_hex(12),
            "created": utc_timestamp(), "instance_id": self.instance_id, "guardian_version": APP_VERSION,
            "principal": principal, "subject": subject, "result": result, "body": body, "statement": statement})
        digest = report_digest(report).hex()
        with self._lock:
            if self.audit is not None:
                # Recorded first: a report that is not in the ledger is not created.
                self.audit.append("report.created", exact={"report_id": report["report_id"], "kind": kind,
                                                           "result": result, "digest": digest})
            atomic_write(self._path(report["report_id"]), canonical_dumps(report))
        return {"report_id": report["report_id"], "digest": digest, "result": result}

    def get(self, report_id: str) -> Dict[str, Any]:
        path = self._path(report_id)
        if not path.exists():
            raise NotFound("no such report")
        report = S.validate(REPORT_SPEC, canonical_loads(read_file_bounded(path, MAX_REPORT, require_private=True),
                                                         require_canonical=True, max_bytes=MAX_REPORT))
        sig_path = self._path(report_id, ".sigs.json")
        sigs = canonical_loads(read_file_bounded(sig_path, 64 * 1024, require_private=True)) \
            if sig_path.exists() else []
        digest = report_digest(report).hex()
        ledger_match = None
        if self.audit is not None:
            recorded = [f.get("digest") for f in self.audit.find_fields("report.created")
                        if f.get("report_id") == report_id]
            ledger_match = recorded == [digest]
        return {"report": report, "signatures": S.validate(SIGNATURE_SPEC, sigs), "digest": digest,
                "ledger_match": ledger_match}

    def list(self, since: int, limit: int) -> List[Dict[str, Any]]:
        names = sorted((n for n in os.listdir(self.directory) if re.fullmatch(REPORT_ID + r"\.json", n)),
                       key=lambda n: os.stat(self.directory / n).st_mtime_ns)
        out = []
        for name in names[since:since + limit]:
            try:
                r = self.get(name[:24])["report"]
                out.append({k: r[k] for k in ("report_id", "kind", "created", "result")} | {"subject": r["subject"]})
            except GuardianError:
                out.append({"report_id": name[:24], "result": "UNREADABLE"})
        return out

    def add_signature(self, report_id: str, key_id: str, signature: bytes, trust: TrustState,
                      sig_check: SigCheck) -> Dict[str, Any]:
        with self._lock:
            entry = self.get(report_id)
            if entry["ledger_match"] is False:
                raise IntegrityError("report differs from the digest in the audit ledger", code="REPORT_ALTERED")
            TrustVerifier(trust, sig_check, NS_REPORT).verify(SCHEME, key_id, bytes.fromhex(entry["digest"]),
                                                              check_armor(signature))
            sigs = [s for s in entry["signatures"] if s["key_id"] != key_id]
            sigs.append({"key_id": key_id, "signature": signature.decode("ascii")})
            atomic_write(self._path(report_id, ".sigs.json"), canonical_dumps(sigs))
            if self.audit is not None:
                self.audit.append("report.signed", exact={"report_id": report_id, "key_id": key_id})
            return {"report_id": report_id, "signatures": len(sigs)}


def verify_export(export: Any, trust_envelopes: List[Any], anchor: str, sig_check: SigCheck, *,
                  allowed_types=HARDWARE_KEY_TYPES) -> Dict[str, Any]:
    """Check an exported report on any instance: at least one valid signature by an enrolled, active owner key."""
    export = S.validate(EXPORT_SPEC, export, "$.export")
    report = S.validate(REPORT_SPEC, export["report"], "$.report")
    state = replay(trust_envelopes, sig_check, anchor=anchor, allowed_types=allowed_types)
    digest = report_digest(report)
    valid = []
    for sig in export["signatures"]:
        try:
            TrustVerifier(state, sig_check, NS_REPORT).verify(SCHEME, sig["key_id"], digest,
                                                              check_armor(sig["signature"].encode("ascii")))
            valid.append(sig["key_id"])
        except (GuardianError, UnicodeEncodeError):
            continue
    if not valid:
        raise IntegrityError("no valid owner signature on this report", code="REPORT_UNSIGNED")
    return {"report_id": report["report_id"], "kind": report["kind"], "result": report["result"],
            "signed_by": valid, "digest": digest.hex()}
