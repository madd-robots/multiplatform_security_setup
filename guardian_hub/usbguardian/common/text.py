# SPDX-License-Identifier: GPL-3.0-or-later
"""Rendering of untrusted text for terminals, logs and error messages."""

from __future__ import annotations

from typing import Any


def display_text(value: Any, max_len: int = 200) -> str:
    """Render untrusted text as printable ASCII.

    Device models, labels, serials and filenames come from hostile media and
    may contain terminal escape sequences, bidi overrides or lookalike
    characters.  Everything that is not printable ASCII is shown escaped, so
    the result is safe to print and cannot forge extra log lines.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).decode("utf-8", "surrogateescape")
    out = []
    for ch in str(value):
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif 0xDC80 <= o <= 0xDCFF:
            # undecodable byte carried by surrogateescape
            out.append("\\x%02x" % (o - 0xDC00))
        elif o <= 0xFF:
            out.append("\\x%02x" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    text = "".join(out)
    if max_len >= 0 and len(text) > max_len:
        text = text[:max_len] + "...(truncated)"
    return text
