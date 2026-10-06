# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian Main's registry of the deployments it built.

The registry is Main's authoritative bookkeeping: which instance ids exist,
what each one received, whether the owner has retired it, and its lease
state (D5): the current generation, the machine binding, the spinoff key of
each generation and whether that generation is active, superseded or
revoked, the last sequence issued, and the last signed record (public, so
it can be handed to an obsolete spinoff when it reconnects).

Retirement and revocation take effect at Main immediately. An offline
spinoff learns of them only through a signed record or lease expiry.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Callable, Dict, List

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import IntegrityError, NotFound, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..identity.sshkeys import KEY_ID_PATTERN
from ..runtime import schema as S
from ..vault.custody import TIMESTAMP_PATTERN
from .descriptor import INSTANCE_ID_PATTERN
from .profiles import PLATFORMS, PROFILES

GENERATION_SPEC = S.Obj({
    "generation": S.Int(min_value=1, max_value=1_000_000),
    "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
    "status": S.Enum(("active", "superseded", "revoked")),
})
LEASE_SPEC = S.Obj({
    "generation": S.Int(min_value=0, max_value=1_000_000),
    "seq": S.Int(min_value=0, max_value=2 ** 40),
    "machine_id": S.Nullable(S.Str(pattern=r"[0-9a-f]{64}", max_len=64)),
    "spinoff_key": S.Nullable(S.Str(min_len=10, max_len=256)),
    "not_after": S.Nullable(S.Int(min_value=0, max_value=2 ** 40)),
    "generations": S.List(GENERATION_SPEC, max_items=256),
    "last_record": S.Nullable(S.Obj({}, allow_extra=True)),
})
ENTRY_SPEC = S.Obj({
    "instance_id": S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64),
    "deployment_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "platform": S.Enum(PLATFORMS),
    "profile": S.Enum(PROFILES),
    "issued": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    "package_sha256": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "status": S.Enum(("active", "retired")),
    "retired": S.Nullable(S.Str(pattern=TIMESTAMP_PATTERN, max_len=20)),
    "lease": LEASE_SPEC,
    "previous": S.List(S.Str(pattern=r"[0-9a-f]{32}", max_len=32), max_items=64),  # earlier deployment ids
})
REGISTRY_SPEC = S.Obj({"version": S.Const(2), "deployments": S.List(ENTRY_SPEC, max_items=4096)})
V1_SPEC = S.Obj({"version": S.Const(1), "deployments": S.List(S.Obj({}, allow_extra=True), max_items=4096)})


def empty_lease() -> Dict[str, Any]:
    return {"generation": 0, "seq": 0, "machine_id": None, "spinoff_key": None, "not_after": None,
            "generations": [], "last_record": None}


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
            doc = canonical_loads(read_file_bounded(self.path, 16 * 1024 * 1024, require_private=True),
                                  require_canonical=True, max_bytes=16 * 1024 * 1024)
            if isinstance(doc, dict) and doc.get("version") == 1:  # before D5: no lease state yet
                doc = {"version": 2, "deployments": [dict(e, lease=empty_lease(), previous=[])
                                                     for e in S.validate(V1_SPEC, doc)["deployments"]]}
            return S.validate(REGISTRY_SPEC, doc)["deployments"]
        except ValidationError as exc:
            raise IntegrityError("deployment registry is malformed: %s" % exc.message) from None

    def _save(self, entries: List[Dict[str, Any]]) -> None:
        atomic_write(self.path, canonical_dumps({"version": 2, "deployments": entries}))

    def entries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return self._load()

    def is_known(self, instance_id: str) -> bool:
        return any(e["instance_id"] == instance_id for e in self.entries())

    def get(self, instance_id: str) -> Dict[str, Any]:
        for e in self.entries():
            if e["instance_id"] == instance_id:
                return e
        raise NotFound("no deployment with this instance id")

    def update_lease(self, instance_id: str, expected_seq: int,
                     change: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
        """Compare-and-set: apply ``change`` only if nothing was issued since ``expected_seq``."""
        with self._lock:
            entries = self._load()
            for e in entries:
                if e["instance_id"] == instance_id:
                    if e["lease"]["seq"] != expected_seq:
                        raise ValidationError("the lease state changed since this record was prepared",
                                              code="LEASE_CONFLICT")
                    e["lease"] = S.validate(LEASE_SPEC, change(dict(e["lease"])), "$.lease")
                    self._save(entries)
                    return e
        raise NotFound("no deployment with this instance id")

    def add(self, entry: Dict[str, Any]) -> None:
        entry = S.validate(ENTRY_SPEC, dict(entry, lease=empty_lease(), previous=[]))
        with self._lock:
            entries = self._load()
            if any(e["instance_id"] == entry["instance_id"] for e in entries):
                raise ValidationError("instance id already used", code="INSTANCE_EXISTS")
            self._save(entries + [entry])

    def redeploy(self, instance_id: str, deployment: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new deployment package (code update or reinstall) for an existing, active instance.

        The lease state is kept: a reinstall that loses the spinoff key goes
        through a reissue (generation N+1, fresh key), never through this.
        """
        with self._lock:
            entries = self._load()
            for e in entries:
                if e["instance_id"] == instance_id:
                    if e["status"] != "active":
                        raise ValidationError("deployment is retired", code="INSTANCE_RETIRED")
                    if e["platform"] != deployment["platform"]:
                        raise ValidationError("a redeployment keeps the platform")
                    e["previous"] = (e["previous"] + [e["deployment_id"]])[-64:]
                    for name in ("deployment_id", "profile", "issued", "package_sha256"):
                        e[name] = deployment[name]
                    S.validate(ENTRY_SPEC, e)
                    self._save(entries)
                    return e
        raise NotFound("no deployment with this instance id")

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
