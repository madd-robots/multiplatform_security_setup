# SPDX-License-Identifier: GPL-3.0-or-later
"""OpenSSH public keys: strict parsing, key ids and the key-type policy.

A key is identified by the SHA-256 of its wire-format blob. The YubiKey
serial number is never an identifier for authentication (D3). It may be
recorded as a label only.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import FrozenSet, Tuple

from ..common.canonical import b64decode
from ..common.errors import GuardianError, ValidationError

SK_ED25519 = "sk-ssh-ed25519@openssh.com"
SK_ECDSA = "sk-ecdsa-sha2-nistp256@openssh.com"
ED25519 = "ssh-ed25519"
# Production accepts only hardware security keys (touch-gated, D2).
HARDWARE_KEY_TYPES: FrozenSet[str] = frozenset({SK_ED25519, SK_ECDSA})
KNOWN_KEY_TYPES: FrozenSet[str] = HARDWARE_KEY_TYPES | {ED25519}
KEY_ID_PATTERN = r"sha256-[0-9a-f]{64}"
MAX_BLOB = 1024


@dataclass(frozen=True)
class SshPublicKey:
    key_type: str
    blob: bytes

    @property
    def key_id(self) -> str:
        return "sha256-" + hashlib.sha256(self.blob).hexdigest()

    @property
    def openssh_fingerprint(self) -> str:
        """The fingerprint ``ssh-keygen -l`` prints, for comparison by eye."""
        return "SHA256:" + base64.b64encode(hashlib.sha256(self.blob).digest()).decode("ascii").rstrip("=")

    def to_line(self) -> str:
        return "%s %s" % (self.key_type, base64.b64encode(self.blob).decode("ascii"))


def _string(buf: bytes, off: int) -> Tuple[bytes, int]:
    if off + 4 > len(buf):
        raise ValidationError("truncated public key")
    n = int.from_bytes(buf[off:off + 4], "big")
    if off + 4 + n > len(buf):
        raise ValidationError("truncated public key")
    return buf[off + 4:off + 4 + n], off + 4 + n


def _application(buf: bytes, off: int) -> int:
    app, off = _string(buf, off)
    if not re.fullmatch(rb"ssh:[\x21-\x7e]{0,60}", app):
        raise ValidationError("security key application must be ssh:...")
    return off


def parse_public_key(line: str) -> SshPublicKey:
    """Parse ``type base64 [comment]``.  Options and unknown types are refused."""
    if not isinstance(line, str) or len(line) > 4096 or "\n" in line.strip():
        raise ValidationError("invalid public key line")
    parts = line.strip().split(None, 2)
    if len(parts) < 2 or parts[0] not in KNOWN_KEY_TYPES:
        raise ValidationError("unsupported or malformed public key")
    key_type = parts[0]
    try:
        blob = b64decode(parts[1], max_bytes=MAX_BLOB)
    except GuardianError:
        raise ValidationError("public key is not valid base64") from None
    name, off = _string(blob, 0)
    if name != key_type.encode("ascii"):
        raise ValidationError("public key type does not match its contents")
    if key_type in (ED25519, SK_ED25519):
        pk, off = _string(blob, off)
        if len(pk) != 32:
            raise ValidationError("bad ed25519 public key length")
    else:
        curve, off = _string(blob, off)
        point, off = _string(blob, off)
        if curve != b"nistp256" or len(point) != 65 or point[0] != 4:
            raise ValidationError("bad nistp256 public key")
    if key_type in HARDWARE_KEY_TYPES:
        off = _application(blob, off)
    if off != len(blob):
        raise ValidationError("trailing data in public key")
    return SshPublicKey(key_type, blob)


def check_key_type(key: SshPublicKey, allowed: FrozenSet[str]) -> None:
    if key.key_type not in allowed:
        raise ValidationError("key type %s is not allowed (hardware security keys only)" % key.key_type,
                              code="KEY_TYPE_NOT_ALLOWED")
