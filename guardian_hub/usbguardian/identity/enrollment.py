# SPDX-License-Identifier: GPL-3.0-or-later
"""Client-side builders for trust events.  Each signature is one touch.

Creating the keys themselves (done once per YubiKey, from the Rescue USB):

    ssh-keygen -t ed25519-sk -O application=ssh:guardian -N '' -f guardian-key-a

That writes a key handle (useless without the YubiKey) and the public key.
Do not add ``-O no-touch-required`` or ``-O verify-required`` (D2: touch,
no PIN). Keep a copy of both handles on the Rescue USB: a handle cannot be
recovered from the YubiKey, because it is not a resident credential.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..common.errors import ValidationError
from .sshsig import NS_ENROLL, NS_TRUST, SshKeygenSigner
from .trust import ZERO_HASH, event_digest, signature_entry


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _key_entry(signer: SshKeygenSigner, label: str, serial: Optional[str]) -> Dict[str, Any]:
    return {"key": signer.key.to_line(), "label": label, "serial": serial}


def genesis(keys: Sequence[Tuple[SshKeygenSigner, str, Optional[str]]], *, time: Optional[str] = None) -> Dict[str, Any]:
    """First event: one or two keys, each proving possession (one touch per key)."""
    if not 1 <= len(keys) <= 2:
        raise ValidationError("genesis enrolls one or two keys")
    event = {"format": "guardian-trust-event", "version": 1, "seq": 0, "prev": ZERO_HASH, "type": "genesis",
             "time": time or _now(), "keys": [_key_entry(s, label, serial) for s, label, serial in keys],
             "subject": None, "reason": ""}
    digest = event_digest(event)
    proofs = [signature_entry(s.key_id, s.sign_ns(NS_ENROLL, digest)) for s, _, _ in keys]
    return {"event": event, "signatures": [], "proofs": proofs}


def enroll(head: str, seq: int, new_key: SshKeygenSigner, label: str, serial: Optional[str],
           authorizer: SshKeygenSigner, *, time: Optional[str] = None) -> Dict[str, Any]:
    """Enroll a replacement key after event ``seq``/``head``: touch the remaining key, then the new key."""
    event = {"format": "guardian-trust-event", "version": 1, "seq": seq + 1, "prev": head,
             "type": "enroll", "time": time or _now(), "keys": [_key_entry(new_key, label, serial)],
             "subject": None, "reason": ""}
    digest = event_digest(event)
    return {"event": event,
            "signatures": [signature_entry(authorizer.key_id, authorizer.sign_ns(NS_TRUST, digest))],
            "proofs": [signature_entry(new_key.key_id, new_key.sign_ns(NS_ENROLL, digest))]}


def revoke(head: str, seq: int, subject_key_id: str, authorizer: SshKeygenSigner, reason: str, *,
           time: Optional[str] = None) -> Dict[str, Any]:
    """Revoke a lost or retired key after event ``seq``/``head`` with one touch on any active key."""
    event = {"format": "guardian-trust-event", "version": 1, "seq": seq + 1, "prev": head,
             "type": "revoke", "time": time or _now(), "keys": [], "subject": subject_key_id,
             "reason": reason[:200]}
    digest = event_digest(event)
    signatures: List[Dict[str, str]] = [signature_entry(authorizer.key_id, authorizer.sign_ns(NS_TRUST, digest))]
    return {"event": event, "signatures": signatures, "proofs": []}
