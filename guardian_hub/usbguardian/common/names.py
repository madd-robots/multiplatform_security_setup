# SPDX-License-Identifier: GPL-3.0-or-later
"""Safe filenames and relative paths.

``check_component`` decides whether a name may be used as-is on Linux,
Windows and Android storage (FAT/exFAT/NTFS/ext4).  ``sanitize_component``
derives a safe ASCII name from untrusted text such as a USB model string.

These checks are lexical.  They do not stop symlink races; code that opens
paths under an untrusted directory must also use the descriptor-based helpers
in ``fsutil``.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, List

from .errors import ValidationError
from .text import display_text

WINDOWS_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
    + ["COM%d" % i for i in range(10)]
    + ["LPT%d" % i for i in range(10)]
    + ["COM\u00b9", "COM\u00b2", "COM\u00b3", "LPT\u00b9", "LPT\u00b2", "LPT\u00b3"]
)
WINDOWS_INVALID_CHARS = frozenset('<>:"|?*')
BIDI_CONTROLS = frozenset({0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
                           0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD})
MAX_COMPONENT_BYTES = 255
MAX_PATH_BYTES = 1024

_SAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]+")


def check_component(name: Any, *, max_len: int = 128, allow_non_ascii: bool = False,
                    allow_leading_dash: bool = False) -> List[str]:
    """Return reason codes for an unsafe single path component (empty if safe)."""
    if not isinstance(name, str):
        return ["NOT_A_STRING"]
    reasons: List[str] = []

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    if name in ("", ".", ".."):
        add("PATH_TRAVERSAL" if name == ".." else "EMPTY_OR_DOT_NAME")
        return reasons
    if "/" in name:
        add("EMBEDDED_SLASH")
    if "\\" in name:
        add("EMBEDDED_BACKSLASH")
    if "\x00" in name:
        add("NUL_IN_NAME")
    try:
        encoded_len = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        add("INVALID_NAME_ENCODING")
        encoded_len = len(name.encode("utf-8", "replace"))
    for ch in name:
        o = ord(ch)
        if ch == "\n":
            add("NEWLINE_IN_NAME")
        elif ch == "\r":
            add("CARRIAGE_RETURN_IN_NAME")
        elif o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:
            add("CONTROL_CHARACTER_IN_NAME")
        elif o in BIDI_CONTROLS:
            add("BIDI_CONTROL_IN_NAME")
        elif o in ZERO_WIDTH:
            add("ZERO_WIDTH_CHARACTER_IN_NAME")
        elif 0xD800 <= o <= 0xDFFF:
            add("INVALID_NAME_ENCODING")
        else:
            cat = unicodedata.category(ch)
            if cat == "Cf":
                add("FORMAT_CHARACTER_IN_NAME")
            elif cat in ("Co", "Cn"):
                add("UNASSIGNED_OR_PRIVATE_CHARACTER_IN_NAME")
            elif cat in ("Zl", "Zp") or (cat == "Zs" and ch != " "):
                add("UNUSUAL_WHITESPACE_IN_NAME")
        if ch in WINDOWS_INVALID_CHARS:
            add("WINDOWS_INVALID_CHARACTER")
    if not name.isascii() and not allow_non_ascii:
        # Rejecting non-ASCII names is the feasible defence against lookalike
        # (homoglyph) names.
        add("NON_ASCII_NAME")
    if "INVALID_NAME_ENCODING" not in reasons and unicodedata.normalize("NFC", name) != name:
        add("NOT_NFC_NORMALIZED")
    if name[-1] in " .":
        add("TRAILING_SPACE_OR_DOT")
    if name[0] == " ":
        add("LEADING_SPACE")
    if name[0] == "-" and not allow_leading_dash:
        # A leading dash turns a filename into an option for external tools.
        add("LEADING_DASH")
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if stem in WINDOWS_RESERVED_NAMES:
        add("WINDOWS_RESERVED_NAME")
    if len(name) > max_len or encoded_len > MAX_COMPONENT_BYTES:
        add("NAME_TOO_LONG")
    return reasons


def validate_component(name: Any, **kwargs: Any) -> str:
    reasons = check_component(name, **kwargs)
    if reasons:
        code = "PATH_TRAVERSAL" if "PATH_TRAVERSAL" in reasons else "UNSAFE_NAME"
        raise ValidationError("unsafe name %s (%s)" % (display_text(name, 80), ", ".join(reasons)), code=code)
    return name


def validate_relative_path(rel: Any, **kwargs: Any) -> List[str]:
    """Split a '/'-separated relative path and validate every component."""
    if not isinstance(rel, str) or not rel:
        raise ValidationError("empty or invalid relative path", code="PATH_TRAVERSAL")
    if rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel):
        raise ValidationError("absolute path rejected: %s" % display_text(rel, 80), code="ABSOLUTE_PATH")
    if len(rel.encode("utf-8", "replace")) > MAX_PATH_BYTES:
        raise ValidationError("relative path too long", code="UNSAFE_NAME")
    parts = rel.split("/")
    for part in parts:
        validate_component(part, **kwargs)
    return parts


def safe_join(base: Path, rel: str, **kwargs: Any) -> Path:
    """Join a validated relative path below ``base`` (lexically)."""
    return Path(base).joinpath(*validate_relative_path(rel, **kwargs))


def sanitize_component(text: Any, *, fallback: str = "unnamed", max_len: int = 64) -> str:
    """Derive a safe ASCII filename component from untrusted text.

    The result contains only ``[A-Za-z0-9._-]``, does not start with ``.`` or
    ``-``, is not a Windows reserved name and always passes
    ``check_component``.
    """
    if not 1 <= max_len <= 128:
        raise ValueError("max_len out of range")
    if check_component(fallback) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", fallback):
        raise ValueError("fallback must itself be a safe name")
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", "replace")
    raw = unicodedata.normalize("NFKD", str(text if text is not None else ""))
    ascii_text = raw.encode("ascii", "ignore").decode("ascii")
    name = _SAFE_CHAR_RE.sub("_", ascii_text)
    name = re.sub(r"_+", "_", name).strip("._-")
    name = name[:max_len].rstrip("._-")
    if not name:
        name = fallback[:max_len]
    if name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        name = ("_" + name)[:max_len].rstrip("._-")
        if name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES or not name:
            name = fallback[:max_len]
    return name
