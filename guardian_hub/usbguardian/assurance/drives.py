# SPDX-License-Identifier: GPL-3.0-or-later
"""Registry of Guardian drives (D4 step 5: check again on every insertion).

A drive enters the registry when an erase-verification passes. On a later
insertion its identity is compared with the record:

    KNOWN      same identity fingerprint as when it was verified
    CHANGED    same USB vendor, product and serial, but a different identity
               (for example a new firmware revision or different interfaces):
               the drive is marked REJECTED, because firmware that changes what
               it presents is exactly what D4 guards against
    REJECTED   previously rejected; it stays rejected
    UNKNOWN    never verified here

Matching by serial only works for drives with a usable serial number; a
drive without one can only be recognised by its full fingerprint.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import IntegrityError, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..devices.identity import identity_changes, identity_document
from ..runtime import schema as S
from ..vault.custody import utc_timestamp
from .facts import JUNK_SERIAL, firmware_indicators

MAX_DRIVES = 1024
ENTRY_SPEC = S.Obj({
    "fingerprint": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "weak_key": S.Nullable(S.Str(max_len=600)),
    "state": S.Enum(("verified", "rejected")),
    "size_bytes": S.Int(min_value=0, max_value=2 ** 53 - 1),
    "identity": S.Obj({}, allow_extra=True),
    "firmware_indicators": S.Obj({}, allow_extra=True),
    "history": S.List(S.Obj({"time": S.Str(max_len=20), "event": S.Str(max_len=40),
                             "report_id": S.Nullable(S.Str(max_len=24)), "detail": S.Str(max_len=600)}),
                      max_items=64),
})
REGISTRY_SPEC = S.Obj({"version": S.Const(1), "drives": S.List(ENTRY_SPEC, max_items=MAX_DRIVES)})


def weak_key(dev: Dict[str, Any]) -> Optional[str]:
    usb = dev.get("usb") or {}
    serial = (usb.get("serial") or "").strip()
    if not serial or JUNK_SERIAL.match(serial) or not usb.get("vendor_id"):
        return None
    return "%s:%s:%s" % (usb.get("vendor_id"), usb.get("product_id"), serial)


class DriveRegistry:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.path = self.directory / "drives.json"
        self._lock = threading.Lock()

    def _load(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            doc = canonical_loads(read_file_bounded(self.path, 16 * 1024 * 1024, require_private=True),
                                  require_canonical=True, max_bytes=16 * 1024 * 1024)
            return S.validate(REGISTRY_SPEC, doc)["drives"]
        except ValidationError as exc:
            raise IntegrityError("drive registry is malformed: %s" % exc.message) from None

    def _save(self, drives: List[Dict[str, Any]]) -> None:
        atomic_write(self.path, canonical_dumps({"version": 1, "drives": drives[-MAX_DRIVES:]}))

    def entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load()

    def record_verified(self, dev: Dict[str, Any], fingerprint: str, report_id: str) -> Dict[str, Any]:
        with self._lock:
            drives = self._load()
            entry = next((d for d in drives if d["fingerprint"] == fingerprint), None)
            if entry is not None and entry["state"] == "rejected":
                return entry  # a rejected drive is never re-admitted by another erase
            if entry is None:
                entry = {"fingerprint": fingerprint, "weak_key": weak_key(dev), "state": "verified",
                         "size_bytes": dev.get("size_bytes") or 0, "identity": identity_document(dev),
                         "firmware_indicators": firmware_indicators(dev), "history": []}
                drives.append(entry)
            entry["history"] = (entry["history"] + [{"time": utc_timestamp(), "event": "erase_verified",
                                                     "report_id": report_id, "detail": ""}])[-64:]
            self._save(drives)
            return entry

    def check(self, dev: Dict[str, Any], fingerprint: str) -> Tuple[str, List[str]]:
        """Compare an inserted drive with the registry; a CHANGED drive is marked rejected."""
        with self._lock:
            drives = self._load()
            exact = next((d for d in drives if d["fingerprint"] == fingerprint), None)
            if exact is not None:
                return ("REJECTED" if exact["state"] == "rejected" else "KNOWN"), []
            key = weak_key(dev)
            twin = next((d for d in drives if key is not None and d["weak_key"] == key), None)
            if twin is None:
                return "UNKNOWN", []
            changes = identity_changes(twin["identity"], identity_document(dev))[:20]
            if twin["state"] != "rejected":
                twin["state"] = "rejected"
                twin["history"] = (twin["history"] + [{"time": utc_timestamp(), "event": "identity_changed",
                                                       "report_id": None,
                                                       "detail": "; ".join(changes)[:600]}])[-64:]
                self._save(drives)
            return "CHANGED", changes
