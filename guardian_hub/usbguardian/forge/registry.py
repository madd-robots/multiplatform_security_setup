# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian Main's registry of the deployments it built.

The registry is local bookkeeping: which instance ids exist, what each one
received, and whether the owner has retired it. Retirement takes effect at
Main immediately; carrying it to an offline spinoff needs the revocation
and expiry design that is still pending (ROADMAP D5).
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import IntegrityError, NotFound, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..runtime import schema as S
from ..vault.custody import TIMESTAMP_PATTERN
from .descriptor import INSTANCE_ID_PATTERN
from .profiles import PLATFORMS, PROFILES

ENTRY_SPEC = S.Obj({
    "instance_id": S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64),
    "deployment_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "platform": S.Enum(PLATFORMS),
    "profile": S.Enum(PROFILES),
    "issued": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    "package_sha256": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "status": S.Enum(("active", "retired")),
    "retired": S.Nullable(S.Str(pattern=TIMESTAMP_PATTERN, max_len=20)),
})
REGISTRY_SPEC = S.Obj({"version": S.Const(1), "deployments": S.List(ENTRY_SPEC, max_items=4096)})


class DeploymentRegistry:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.path = self.directory / "registry.json"
        self._lock = threading.Lock()

    def _load(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            doc = canonical_loads(read_file_bounded(self.path, 4 * 1024 * 1024, require_private=True),
                                  require_canonical=True, max_bytes=4 * 1024 * 1024)
            return S.validate(REGISTRY_SPEC, doc)["deployments"]
        except ValidationError as exc:
            raise IntegrityError("deployment registry is malformed: %s" % exc.message) from None

    def _save(self, entries: List[Dict[str, Any]]) -> None:
        atomic_write(self.path, canonical_dumps({"version": 1, "deployments": entries}))

    def entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load()

    def is_known(self, instance_id: str) -> bool:
        return any(e["instance_id"] == instance_id for e in self.entries())

    def add(self, entry: Dict[str, Any]) -> None:
        entry = S.validate(ENTRY_SPEC, entry)
        with self._lock:
            entries = self._load()
            if any(e["instance_id"] == entry["instance_id"] for e in entries):
                raise ValidationError("instance id already used", code="INSTANCE_EXISTS")
            self._save(entries + [entry])

    def retire(self, instance_id: str, when: str) -> Dict[str, Any]:
        with self._lock:
            entries = self._load()
            for e in entries:
                if e["instance_id"] == instance_id:
                    if e["status"] == "retired":
                        raise ValidationError("deployment already retired")
                    e["status"], e["retired"] = "retired", when
                    self._save(entries)
                    return e
        raise NotFound("no deployment with this instance id")
