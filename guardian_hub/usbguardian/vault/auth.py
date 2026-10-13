# SPDX-License-Identifier: GPL-3.0-or-later
"""Manifest authentication interface.

A transfer manifest is only trustworthy if it is authenticated by an
enrolled owner key. Without that, anyone who can alter the medium can also
recompute every digest. Stage 5 provides the YubiKey signer (touch-gated)
and the verifier (enrolled public keys plus revocation state).

There is deliberately no "unauthenticated" verifier. Until Stage 5, nothing
in production can verify a package, so nothing can be released.
"""

from __future__ import annotations

import re
from typing import Protocol

SCHEME_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,47}$")
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_SIGNATURE = 16 * 1024


class Signer(Protocol):
    scheme: str
    key_id: str

    def sign(self, digest: bytes) -> bytes:
        """Sign a 32-byte manifest digest.  Requires owner presence in Stage 5."""


class Verifier(Protocol):
    def verify(self, scheme: str, key_id: str, digest: bytes, signature: bytes) -> None:
        """Raise IntegrityError unless the signature is valid for an enrolled, unrevoked key."""
