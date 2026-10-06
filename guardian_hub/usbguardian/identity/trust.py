# SPDX-License-Identifier: GPL-3.0-or-later
"""Trust log: which owner keys are enrolled, as a signed hash chain (D3).

Each event is a canonical document linked to the previous one by its
digest. The first event (genesis) fixes the trust anchor, and every Guardian
instance pins that anchor. Replaying the chain from genesis gives the
current state. No step depends on a password, PIN, recovery phrase or
serial number.

    genesis  one or two keys; each key proves possession by signing the event
    enroll   one new key; signed by an active key, plus proof of possession
             by the new key (D3: replacement through the remaining key)
    revoke   one active key; signed by any active key, including the subject
             itself when retiring it. The last active key cannot be revoked:
             losing every key means re-rooting from known-good media.

At most two keys are active at once (the owner has two YubiKeys). A key
that was ever revoked can never be enrolled again. Two different events
with the same sequence number are a fork, and are refused (fail closed).

A revoked key's signatures are rejected everywhere, including signatures it
made before revocation, because Guardian cannot know when a lost key was
first misused.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import ConfigError, GuardianError, IntegrityError, NotFound, ValidationError
from ..common.fsutil import atomic_write, read_file_bounded
from ..runtime import schema as S
from .sshkeys import HARDWARE_KEY_TYPES, KEY_ID_PATTERN, SshPublicKey, check_key_type, parse_public_key
from .sshsig import MAX_SIGNATURE, NS_ENROLL, NS_TRUST, SCHEME, SigCheck, check_armor

EVENT_DOMAIN = "guardian/trust-event/v1"
ZERO_HASH = "0" * 64
MAX_ACTIVE = 2
MAX_EVENTS = 1024
MAX_LOG_BYTES = 8 * 1024 * 1024
TIMESTAMP_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"

SIG_ENTRY = S.Obj({"key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                   "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)})
EVENT_SPEC = S.Obj({
    "format": S.Const("guardian-trust-event"),
    "version": S.Const(1),
    "seq": S.Int(min_value=0, max_value=MAX_EVENTS - 1),
    "prev": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "type": S.Enum(("genesis", "enroll", "revoke")),
    "time": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    "keys": S.List(S.Obj({
        "key": S.Str(min_len=10, max_len=2048),
        "label": S.Str(pattern=r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}", max_len=32),
        "serial": S.Nullable(S.Str(pattern=r"[A-Za-z0-9-]{1,32}", max_len=32)),
    }), max_items=MAX_ACTIVE),
    "subject": S.Nullable(S.Str(pattern=KEY_ID_PATTERN, max_len=71)),
    "reason": S.Str(max_len=200),
})
ENVELOPE_SPEC = S.Obj({
    "event": S.Obj({}, allow_extra=True),
    "signatures": S.List(SIG_ENTRY, max_items=MAX_ACTIVE),
    "proofs": S.List(SIG_ENTRY, max_items=MAX_ACTIVE),
})


@dataclass(frozen=True)
class EnrolledKey:
    key: SshPublicKey
    label: str
    serial: Optional[str]
    enrolled_seq: int


@dataclass(frozen=True)
class TrustState:
    anchor: str
    head: str
    seq: int
    active: Dict[str, EnrolledKey]
    revoked: Dict[str, int] = field(default_factory=dict)
    known: FrozenSet[str] = frozenset()

    def to_document(self) -> Dict[str, Any]:
        return {
            "anchor": self.anchor, "head": self.head, "seq": self.seq,
            "active": [{"key_id": kid, "label": k.label, "serial": k.serial, "key_type": k.key.key_type,
                        "openssh_fingerprint": k.key.openssh_fingerprint, "enrolled_seq": k.enrolled_seq}
                       for kid, k in sorted(self.active.items())],
            "revoked": [{"key_id": kid, "revoked_seq": seq} for kid, seq in sorted(self.revoked.items())],
        }


def event_digest(event: Dict[str, Any]) -> bytes:
    return canonical_digest(EVENT_DOMAIN, event)


def _fail(message: str, code: str = "TRUST_INVALID") -> IntegrityError:
    return IntegrityError(message, code=code)


def _check_sigs(entries: List[Dict[str, str]], allowed_keys: Dict[str, SshPublicKey], namespace: str,
                digest: bytes, sig_check: SigCheck) -> List[str]:
    signers = []
    for entry in entries:
        kid = entry["key_id"]
        if kid in signers:
            raise _fail("duplicate signer")
        key = allowed_keys.get(kid)
        if key is None:
            raise _fail("signature by a key that may not sign this event")
        try:
            signature = check_armor(entry["signature"].encode("ascii"))
        except (GuardianError, UnicodeEncodeError):
            raise _fail("malformed signature") from None
        if not sig_check(key, namespace, digest, signature):
            raise _fail("signature does not verify")
        signers.append(kid)
    return signers


def apply_event(state: Optional[TrustState], envelope: Any, sig_check: SigCheck, *,
                allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES) -> TrustState:
    """Verify one envelope against the current state and return the new state."""
    try:
        env = S.validate(ENVELOPE_SPEC, envelope, "$.envelope")
        event = S.validate(EVENT_SPEC, env["event"], "$.event")
    except ValidationError as exc:
        raise _fail("malformed trust event: %s" % exc.message) from None
    digest = event_digest(event)
    new_keys: List[Tuple[SshPublicKey, Dict[str, Any]]] = []
    for entry in event["keys"]:
        try:
            key = parse_public_key(entry["key"])
            check_key_type(key, allowed_types)
        except ValidationError as exc:
            raise _fail("trust event key rejected: %s" % exc.message) from None
        new_keys.append((key, entry))
    if len({k.key_id for k, _ in new_keys}) != len(new_keys):
        raise _fail("duplicate key in event")
    proof_keys = {k.key_id: k for k, _ in new_keys}

    if state is None:
        if event["type"] != "genesis" or event["seq"] != 0 or event["prev"] != ZERO_HASH:
            raise _fail("trust log must start with genesis")
        if not new_keys or event["subject"] is not None or env["signatures"]:
            raise _fail("malformed genesis")
        proved = _check_sigs(env["proofs"], proof_keys, NS_ENROLL, digest, sig_check)
        if set(proved) != set(proof_keys):
            raise _fail("every genesis key must prove possession")
        head = digest.hex()
        active = {k.key_id: EnrolledKey(k, e["label"], e["serial"], 0) for k, e in new_keys}
        return TrustState(anchor=head, head=head, seq=0, active=active, known=frozenset(active))

    if event["type"] == "genesis":
        raise _fail("second genesis", code="TRUST_FORK")
    if event["seq"] != state.seq + 1:
        raise _fail("trust event out of sequence", code="TRUST_FORK")
    if event["prev"] != state.head:
        raise _fail("trust event does not extend this chain", code="TRUST_FORK")
    authorities = {kid: ek.key for kid, ek in state.active.items()}
    active = dict(state.active)
    revoked = dict(state.revoked)
    known = set(state.known)

    if event["type"] == "enroll":
        if len(new_keys) != 1 or event["subject"] is not None:
            raise _fail("enroll adds exactly one key")
        key, entry = new_keys[0]
        if key.key_id in known:
            raise _fail("key was enrolled before; revoked keys can never return")
        if len(active) >= MAX_ACTIVE:
            raise _fail("two keys are already active; revoke one first")
        if not _check_sigs(env["signatures"], authorities, NS_TRUST, digest, sig_check):
            raise _fail("enroll must be signed by an active key")
        if _check_sigs(env["proofs"], proof_keys, NS_ENROLL, digest, sig_check) != [key.key_id]:
            raise _fail("new key must prove possession")
        active[key.key_id] = EnrolledKey(key, entry["label"], entry["serial"], event["seq"])
        known.add(key.key_id)
    else:  # revoke
        subject = event["subject"]
        if new_keys or env["proofs"] or subject is None:
            raise _fail("malformed revoke")
        if subject not in active:
            raise _fail("only an active key can be revoked")
        if len(active) == 1:
            raise _fail("the last active key cannot be revoked; re-root trust instead")
        if not _check_sigs(env["signatures"], authorities, NS_TRUST, digest, sig_check):
            raise _fail("revoke must be signed by an active key")
        del active[subject]
        revoked[subject] = event["seq"]
    return TrustState(anchor=state.anchor, head=digest.hex(), seq=event["seq"], active=active,
                      revoked=revoked, known=frozenset(known))


def replay(envelopes: List[Any], sig_check: SigCheck, *, anchor: Optional[str] = None,
           allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES) -> TrustState:
    if not envelopes:
        raise NotFound("trust log is empty")
    if len(envelopes) > MAX_EVENTS:
        raise _fail("trust log too long")
    state: Optional[TrustState] = None
    for env in envelopes:
        state = apply_event(state, env, sig_check, allowed_types=allowed_types)
        if anchor is not None and state.anchor != anchor:
            raise _fail("trust log does not start at the pinned anchor", code="TRUST_ANCHOR_MISMATCH")
    assert state is not None
    return state


def check_extension(current: List[Any], incoming: List[Any]) -> List[Any]:
    """Accept ``incoming`` only if ``current`` is a prefix of it (sync); else it is a fork."""
    if len(incoming) < len(current) or [canonical_dumps(e) for e in incoming[:len(current)]] != \
            [canonical_dumps(e) for e in current]:
        raise _fail("incoming trust log is not an extension of this one", code="TRUST_FORK")
    return incoming[len(current):]


class TrustVerifier:
    """Vault ``Verifier`` backed by the trust state: active keys only, one namespace."""

    def __init__(self, state: TrustState, sig_check: SigCheck, namespace: str):
        self.state = state
        self.sig_check = sig_check
        self.namespace = namespace

    def verify(self, scheme: str, key_id: str, digest: bytes, signature: bytes) -> None:
        if scheme != SCHEME:
            raise IntegrityError("unsupported signature scheme")
        enrolled = self.state.active.get(key_id)
        if enrolled is None:
            reason = "revoked" if key_id in self.state.revoked else "not enrolled"
            raise IntegrityError("signing key is %s" % reason)
        try:
            check_armor(signature)
        except ValidationError:
            raise IntegrityError("malformed signature") from None
        if not self.sig_check(enrolled.key, self.namespace, digest, signature):
            raise IntegrityError("signature does not verify")


def signature_entry(key_id: str, signature: bytes) -> Dict[str, str]:
    return {"key_id": key_id, "signature": signature.decode("ascii")}


class TrustStore:
    """Persistent trust log plus pinned anchor in a private state directory.

    Writes are serialized; the cached state is replaced only after a new
    event verified and was durably written.
    """

    def __init__(self, directory: Path, sig_check: SigCheck, *,
                 allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES):
        self.directory = Path(directory)
        self.log_path = self.directory / "trust.log"
        self.anchor_path = self.directory / "trust.anchor"
        self.sig_check = sig_check
        self.allowed_types = allowed_types
        self._lock = threading.Lock()
        self._envelopes: List[Any] = []
        self._state: Optional[TrustState] = None
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        if self.anchor_path.exists() != self.log_path.exists():
            raise ConfigError("trust anchor and trust log must both exist or both be absent")
        if self.log_path.exists():
            anchor = canonical_loads(read_file_bounded(self.anchor_path, 1024, require_private=True),
                                     require_canonical=True)
            if not isinstance(anchor, dict) or set(anchor) != {"anchor"}:
                raise ConfigError("malformed trust anchor file")
            raw = read_file_bounded(self.log_path, MAX_LOG_BYTES, require_private=True)
            envelopes = [canonical_loads(line, require_canonical=True, max_bytes=256 * 1024)
                         for line in raw.split(b"\n") if line]
            self._state = replay(envelopes, self.sig_check, anchor=anchor["anchor"],
                                 allowed_types=self.allowed_types)
            self._envelopes = envelopes
        self._loaded = True

    def state(self) -> Optional[TrustState]:
        with self._lock:
            self._load()
            return self._state

    def require_state(self) -> TrustState:
        state = self.state()
        if state is None:
            raise NotFound("trust is not initialized; enroll the owner keys first", code="TRUST_UNINITIALIZED")
        return state

    def envelopes(self) -> List[Any]:
        with self._lock:
            self._load()
            return list(self._envelopes)

    def preview(self, envelope: Any) -> TrustState:
        """Verify ``envelope`` as the next event without storing it."""
        with self._lock:
            self._load()
            return apply_event(self._state, envelope, self.sig_check, allowed_types=self.allowed_types)

    def append(self, envelope: Any) -> TrustState:
        with self._lock:
            self._load()
            new_state = apply_event(self._state, envelope, self.sig_check, allowed_types=self.allowed_types)
            envelopes = self._envelopes + [envelope]
            data = b"".join(canonical_dumps(e) + b"\n" for e in envelopes)
            if self._state is None:
                atomic_write(self.anchor_path, canonical_dumps({"anchor": new_state.anchor}))
            atomic_write(self.log_path, data)
            self._envelopes = envelopes
            self._state = new_state
            return new_state


__all__ = ["TrustState", "TrustStore", "TrustVerifier", "apply_event", "replay", "check_extension",
           "event_digest", "signature_entry"]
