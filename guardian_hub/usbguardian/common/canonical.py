# SPDX-License-Identifier: GPL-3.0-or-later
"""Canonical serialization.

Everything Guardian hashes, signs, stores or sends over IPC is encoded as
canonical JSON so that one value has exactly one byte representation on every
platform (Linux, Windows, Termux).

The format is the RFC 8785 (JCS) encoding restricted to a subset that has no
ambiguity:

* values: null, true, false, integers in [-(2**53-1), 2**53-1], strings,
  arrays, objects with string keys
* no floating point numbers (NaN, -0.0 and rounding make them non-canonical)
* strings must be valid Unicode (no lone surrogates)
* object keys sorted by UTF-16 code units (as RFC 8785 requires), no
  duplicate keys, no insignificant whitespace, UTF-8 output

Binary data is carried as strict base64 strings (``b64encode``/``b64decode``).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any, Dict, List, Tuple

from .errors import ResourceLimitExceeded, ValidationError

MAX_SAFE_INT = 2 ** 53 - 1
DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_DEPTH = 32
DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,63}$")

_ENCODER = json.JSONEncoder(ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _key_order(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare in UTF-16 code unit order.
    return key.encode("utf-16-be", "surrogatepass")


def _check_str(value: str, where: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValidationError("%s: string is not valid Unicode (lone surrogate)" % where) from None


def _normalize(value: Any, depth: int, max_depth: int, where: str) -> Any:
    """Validate a value and return it with objects in canonical key order."""
    if depth > max_depth:
        raise ValidationError("%s: nesting deeper than %d" % (where, max_depth))
    if value is None or value is True or value is False:
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
            raise ValidationError("%s: integer outside the interoperable range" % where)
        return int(value)
    if isinstance(value, str):
        _check_str(value, where)
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_normalize(v, depth + 1, max_depth, "%s[%d]" % (where, i)) for i, v in enumerate(value)]
    if isinstance(value, dict):
        items: List[Tuple[str, Any]] = []
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValidationError("%s: object key is not a string" % where)
            _check_str(k, where)
            items.append((k, v))
        items.sort(key=lambda kv: _key_order(kv[0]))
        out: Dict[str, Any] = {}
        for k, v in items:
            out[k] = _normalize(v, depth + 1, max_depth, "%s.%s" % (where, k[:40]))
        return out
    if isinstance(value, float):
        raise ValidationError("%s: floating point numbers are not allowed" % where)
    raise ValidationError("%s: type %s cannot be serialized" % (where, type(value).__name__))


def canonical_dumps(value: Any, *, max_depth: int = DEFAULT_MAX_DEPTH) -> bytes:
    """Encode ``value`` as canonical JSON bytes."""
    normalized = _normalize(value, 0, max_depth, "$")
    return _ENCODER.encode(normalized).encode("utf-8")


def _max_nesting(text: str) -> int:
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
        elif ch in "]}":
            depth -= 1
    return deepest


def _reject_float(text: str) -> Any:
    raise ValidationError("floating point numbers are not allowed")


def _reject_constant(text: str) -> Any:
    raise ValidationError("non-finite number %s is not allowed" % text[:10])


def _parse_int(text: str) -> int:
    if len(text) > 17:
        raise ValidationError("integer outside the interoperable range")
    value = int(text)
    if not -MAX_SAFE_INT <= value <= MAX_SAFE_INT:
        raise ValidationError("integer outside the interoperable range")
    return value


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValidationError("duplicate object key")
        out[k] = v
    return out


_DECODER = json.JSONDecoder(object_pairs_hook=_no_duplicates, parse_float=_reject_float,
                            parse_int=_parse_int, parse_constant=_reject_constant, strict=True)


def canonical_loads(data: bytes, *, max_bytes: int = DEFAULT_MAX_BYTES,
                    max_depth: int = DEFAULT_MAX_DEPTH, require_canonical: bool = False) -> Any:
    """Strictly parse JSON bytes received from any source.

    Rejects oversized input, invalid UTF-8, a BOM, duplicate keys, floats,
    out-of-range integers, lone surrogates and excessive nesting.  With
    ``require_canonical`` the input must also be byte-identical to its
    canonical encoding (use this for anything signed or hashed).
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ValidationError("input must be bytes")
    data = bytes(data)
    if len(data) > max_bytes:
        raise ResourceLimitExceeded("JSON document larger than %d bytes" % max_bytes)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError("JSON document is not valid UTF-8") from None
    if text.startswith("\ufeff"):
        raise ValidationError("JSON document starts with a byte order mark")
    if _max_nesting(text) > max_depth:
        raise ValidationError("JSON nesting deeper than %d" % max_depth)
    try:
        value = _DECODER.decode(text)
    except json.JSONDecodeError as exc:
        raise ValidationError("malformed JSON at offset %d" % exc.pos) from None
    except RecursionError:
        raise ValidationError("JSON nesting too deep") from None
    # Re-validates strings (escaped lone surrogates) and depth.
    normalized = _normalize(value, 0, max_depth, "$")
    if require_canonical and _ENCODER.encode(normalized).encode("utf-8") != data:
        raise ValidationError("JSON document is not in canonical form")
    return value


def canonical_digest(domain: str, value: Any) -> bytes:
    """SHA-256 over a domain tag and the canonical encoding of ``value``.

    The domain tag (for example ``guardian/deployment/v1``) keeps a hash or
    signature made for one purpose from being accepted for another.
    """
    if not isinstance(domain, str) or not DOMAIN_RE.match(domain):
        raise ValueError("invalid digest domain")
    h = hashlib.sha256()
    h.update(b"usbguardian-canonical-v1\x00")
    h.update(domain.encode("ascii"))
    h.update(b"\x00")
    h.update(canonical_dumps(value))
    return h.digest()


def b64encode(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def b64decode(text: Any, *, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Strict base64: standard alphabet, correct padding, canonical form."""
    if not isinstance(text, str):
        raise ValidationError("base64 value must be a string")
    if len(text) > (max_bytes + 2) // 3 * 4:
        raise ResourceLimitExceeded("base64 value too large")
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValidationError("invalid base64") from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValidationError("base64 value is not in canonical form")
    return raw
