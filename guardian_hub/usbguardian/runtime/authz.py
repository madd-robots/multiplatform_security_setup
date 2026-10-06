# SPDX-License-Identifier: GPL-3.0-or-later
"""Authorization: explicit capabilities, default deny.

A principal is identified by the kernel (SO_PEERCRED uid), never by anything
the client says about itself.  The policy grants each known uid a set of
capabilities.  Some capabilities additionally require an authentication
factor; ``owner_key`` (a YubiKey, Stage 5) does not exist yet, so every
capability that needs it is unreachable until that stage lands.  That is
intentional: destructive and key-handling operations fail closed.

uid 0 receives nothing implicitly.  Root must be listed like any other uid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, Optional, Tuple

from ..common.canonical import canonical_digest, canonical_loads
from ..common.errors import ConfigError, GuardianError, PermissionDenied
from ..common.fsutil import check_trusted_file, read_file_bounded
from . import schema as S

FACTOR_PEER_UID = "peer_uid"
FACTOR_OWNER_KEY = "owner_key"
KNOWN_FACTORS = frozenset({FACTOR_PEER_UID, FACTOR_OWNER_KEY})


@dataclass(frozen=True)
class Capability:
    name: str
    description: str
    required_factors: FrozenSet[str] = frozenset()


CAPABILITIES: Dict[str, Capability] = {c.name: c for c in (
    Capability("runtime.status", "read broker status"),
    Capability("runtime.diagnostics", "run sandbox self-tests"),
    Capability("device.inspect", "read-only device analysis"),
    Capability("audit.read", "read the audit ledger"),
    Capability("auth.assert", "request owner challenges and present YubiKey assertions"),
    Capability("trust.read", "read enrolled owner keys and the trust anchor"),
    Capability("vault.prepare", "prepare a transfer manifest for signing"),
    Capability("vault.verify", "verify a transfer package without releasing it"),
    Capability("device.modify", "erase, partition or format a device", frozenset({FACTOR_OWNER_KEY})),
    Capability("vault.read", "decrypt vault contents", frozenset({FACTOR_OWNER_KEY})),
    Capability("vault.write", "encrypt into or change a vault", frozenset({FACTOR_OWNER_KEY})),
    Capability("keys.manage", "enroll, rotate or revoke keys", frozenset({FACTOR_OWNER_KEY})),
    Capability("forge.build", "build and sign spinoff deployments", frozenset({FACTOR_OWNER_KEY})),
)}

MAX_POLICY_BYTES = 64 * 1024
UID_MAX = 2 ** 32 - 2

POLICY_SPEC = S.Obj({
    "version": S.Const(1),
    "principals": S.List(S.Obj({
        "name": S.Str(pattern=r"[a-z][a-z0-9_-]{0,31}", max_len=32),
        "uid": S.Int(min_value=0, max_value=UID_MAX),
        "capabilities": S.List(S.Enum(CAPABILITIES), max_items=len(CAPABILITIES), unique=True),
    }), max_items=64),
})


@dataclass(frozen=True)
class Principal:
    name: str
    uid: int
    granted: FrozenSet[str]
    factors: FrozenSet[str] = field(default_factory=frozenset)

    def with_factor(self, factor: str) -> "Principal":
        if factor not in KNOWN_FACTORS:
            raise ValueError("unknown factor")
        return Principal(self.name, self.uid, self.granted, self.factors | {factor})


class Policy:
    def __init__(self, entries: Iterable[Tuple[str, int, Iterable[str]]]):
        self._by_uid: Dict[int, Principal] = {}
        names = set()
        for name, uid, caps in entries:
            caps = frozenset(caps)
            unknown = caps - set(CAPABILITIES)
            if unknown:
                raise ConfigError("policy grants unknown capability %s" % sorted(unknown)[0])
            if uid in self._by_uid or name in names:
                raise ConfigError("policy lists principal %s or uid %d twice" % (name, uid))
            names.add(name)
            self._by_uid[uid] = Principal(name, uid, caps)

    @classmethod
    def from_document(cls, doc: object) -> "Policy":
        try:
            checked = S.validate(POLICY_SPEC, doc)
        except GuardianError as exc:
            raise ConfigError("invalid policy: %s" % exc.message) from None
        return cls((p["name"], p["uid"], p["capabilities"]) for p in checked["principals"])

    @classmethod
    def load(cls, path: Path, *, allowed_owners: Tuple[int, ...] = (0,)) -> "Policy":
        """Load a policy file that only an allowed owner can have written."""
        check_trusted_file(path, allowed_owners=allowed_owners)
        try:
            doc = canonical_loads(read_file_bounded(path, MAX_POLICY_BYTES), max_bytes=MAX_POLICY_BYTES)
        except GuardianError as exc:
            raise ConfigError("cannot load policy: %s" % exc.message) from None
        return cls.from_document(doc)

    def principal_for_uid(self, uid: int) -> Optional[Principal]:
        principal = self._by_uid.get(uid)
        if principal is None:
            return None
        return principal.with_factor(FACTOR_PEER_UID)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    capability: str
    reason: str


REQUEST_DOMAIN = "guardian/owner-request/v1"


def request_digest(op: str, params: Dict[str, Any]) -> str:
    """Digest of one exact request; an owner assertion is bound to it."""
    return canonical_digest(REQUEST_DOMAIN, {"op": op, "params": params}).hex()


def decide(principal: Principal, capability: str) -> Decision:
    cap = CAPABILITIES.get(capability)
    if cap is None:
        return Decision(False, capability, "UNKNOWN_CAPABILITY")
    if capability not in principal.granted:
        return Decision(False, capability, "CAPABILITY_NOT_GRANTED")
    if not cap.required_factors <= principal.factors:
        return Decision(False, capability, "FACTOR_REQUIRED")
    return Decision(True, capability, "GRANTED")


def require(principal: Principal, capability: str) -> Decision:
    decision = decide(principal, capability)
    if not decision.allowed:
        raise PermissionDenied("operation requires %s (%s)" % (capability, decision.reason))
    return decision
