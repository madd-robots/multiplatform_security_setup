# SPDX-License-Identifier: GPL-3.0-or-later
"""Lease documents: the spinoff's request and Guardian Main's signed records.

    request     made and signed on the spinoff by its own key (guardian-spinoff@v1).
                It proves possession of that key and states the machine binding.
                It carries no authority.
    lease       signed by an owner key through Guardian Main (guardian-lease@v1):
                instance, machine, generation, spinoff key, sequence, validity.
                A renewal is simply a lease with a higher sequence.
    revocation  signed the same way: instance, machine, revoked generation,
                sequence, reason. It removes authority only.

Times are integer seconds since the epoch (UTC). Sequences only increase
per instance, across leases and revocations alike.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict

from ..common.canonical import canonical_digest
from ..common.errors import IntegrityError, ValidationError
from ..identity.sshkeys import ED25519, KEY_ID_PATTERN, SshPublicKey, parse_public_key
from ..identity.sshsig import MAX_SIGNATURE, NS_SPINOFF, SigCheck, check_armor
from ..runtime import schema as S

REQUEST_DOMAIN = "guardian/lease-request/v1"
RECORD_DOMAIN = "guardian/lease-record/v1"
INSTANCE_ID_PATTERN = r"[a-z0-9][a-z0-9-]{0,63}"
HEX32 = r"[0-9a-f]{32}"
HEX64 = r"[0-9a-f]{64}"
MAX_TIME = 2 ** 40
MAX_GENERATION = 1_000_000
MAX_SEQ = 2 ** 40
DAY = 86400
DEFAULT_LEASE_DAYS = 90          # Guardian policy (owner handoff D5), not a standard
DEFAULT_WARN_DAYS = 14
MAX_LEASE_DAYS = 3650
STATES = ("ACTIVE", "EXPIRING", "EXPIRED", "REVOKED", "SUPERSEDED", "UNKNOWN", "UNLEASED")
AUTHORIZED_STATES = frozenset({"ACTIVE", "EXPIRING"})

_INSTANCE = S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64)
_MACHINE = S.Str(pattern=HEX64, max_len=64)
_TIME = S.Int(min_value=0, max_value=MAX_TIME)
_KEY_LINE = S.Str(min_len=10, max_len=256)
_SIGNATURE = S.Str(min_len=1, max_len=MAX_SIGNATURE)

REQUEST_SPEC = S.Obj({
    "format": S.Const("guardian-lease-request"),
    "version": S.Const(1),
    "instance_id": _INSTANCE,
    "deployment_id": S.Str(pattern=HEX32, max_len=32),
    "machine_id": _MACHINE,
    "machine_sources": S.List(S.Str(pattern=r"[a-z_]{1,32}", max_len=32), min_items=1, max_items=8, unique=True),
    "spinoff_key": _KEY_LINE,
    "generation": S.Int(min_value=0, max_value=MAX_GENERATION),   # generation the spinoff holds (0: none)
    "seq": S.Int(min_value=0, max_value=MAX_SEQ),                  # highest sequence it accepted
    "state": S.Enum(STATES),
    "time": _TIME,                                                 # spinoff clock, informational only
    "nonce": S.Str(pattern=HEX32, max_len=32),
})
REQUEST_ENVELOPE_SPEC = S.Obj({
    "request": S.Obj({}, allow_extra=True),
    "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
    "signature": _SIGNATURE,
})

RECORD_SPEC = S.Obj({
    "format": S.Const("guardian-lease"),
    "version": S.Const(1),
    "kind": S.Enum(("lease", "revocation")),
    "record_id": S.Str(pattern=HEX32, max_len=32),
    "instance_id": _INSTANCE,
    "machine_id": _MACHINE,
    "generation": S.Int(min_value=1, max_value=MAX_GENERATION),
    "seq": S.Int(min_value=1, max_value=MAX_SEQ),
    "spinoff_key": S.Nullable(_KEY_LINE),       # lease only
    "not_before": S.Nullable(_TIME),            # lease only
    "not_after": S.Nullable(_TIME),             # lease only
    "warn_seconds": S.Nullable(S.Int(min_value=0, max_value=MAX_LEASE_DAYS * DAY)),
    "issued": _TIME,
    "reason": S.Str(max_len=200),
    "trust_anchor": S.Str(pattern=HEX64, max_len=64),
    "issuer": S.Obj({"instance_id": _INSTANCE, "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71)}),
})
RECORD_ENVELOPE_SPEC = S.Obj({
    "record": S.Obj({}, allow_extra=True),
    "signature": _SIGNATURE,
})


def iso(t: int) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def request_digest(request: Dict[str, Any]) -> bytes:
    return canonical_digest(REQUEST_DOMAIN, request)


def record_digest(record: Dict[str, Any]) -> bytes:
    return canonical_digest(RECORD_DOMAIN, record)


def parse_spinoff_key(line: str) -> SshPublicKey:
    key = parse_public_key(line)
    if key.key_type != ED25519:
        raise ValidationError("a spinoff key must be ssh-ed25519")
    return key


def check_record(record: Any) -> Dict[str, Any]:
    rec = S.validate(RECORD_SPEC, record, "$.record")
    lease_fields = (rec["spinoff_key"], rec["not_before"], rec["not_after"], rec["warn_seconds"])
    if rec["kind"] == "lease":
        if any(v is None for v in lease_fields):
            raise ValidationError("a lease needs a key and a validity period")
        parse_spinoff_key(rec["spinoff_key"])
        if not rec["not_before"] < rec["not_after"] or rec["not_after"] - rec["not_before"] > MAX_LEASE_DAYS * DAY:
            raise ValidationError("lease validity period is invalid")
        if rec["warn_seconds"] >= rec["not_after"] - rec["not_before"]:
            raise ValidationError("warning window must be shorter than the lease")
    elif any(v is not None for v in lease_fields):
        raise ValidationError("a revocation carries no key or validity period")
    return rec


def check_envelope(envelope: Any) -> Dict[str, Any]:
    env = S.validate(RECORD_ENVELOPE_SPEC, envelope, "$.envelope")
    return {"record": check_record(env["record"]), "signature": env["signature"]}


def verify_request(envelope: Any, sig_check: SigCheck) -> Dict[str, Any]:
    """Check a spinoff's request and its proof of possession.  Returns the request."""
    env = S.validate(REQUEST_ENVELOPE_SPEC, envelope, "$.request_envelope")
    request = S.validate(REQUEST_SPEC, env["request"], "$.request")
    key = parse_spinoff_key(request["spinoff_key"])
    if key.key_id != env["key_id"]:
        raise ValidationError("request key id does not match its key")
    try:
        signature = check_armor(env["signature"].encode("ascii"))
    except (ValidationError, UnicodeEncodeError):
        raise IntegrityError("lease request signature is malformed", code="LEASE_REQUEST_INVALID") from None
    if not sig_check(key, NS_SPINOFF, request_digest(request), signature):
        raise IntegrityError("lease request is not signed by its spinoff key", code="LEASE_REQUEST_INVALID")
    return request
