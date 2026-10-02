#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""MX USB Transfer Airlock.

Moves a small set of text-based recovery files (for example PowerShell
hardening scripts) from an untrusted USB flash drive, through a local
quarantine, onto a clean USB flash drive.  The two drives are never present
during the same stage.

    DIRTY USB -> READ-ONLY INGEST -> QUARANTINE -> PHYSICAL REMOVAL
    -> VALIDATION -> CLEAN USB -> VERIFIED RELEASE

Nothing from either drive is ever executed.  Run with: python3 -I -B airlock.py
See README.md and SECURITY_MODEL.md for the trust model and its limits.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import errno
import hashlib
import json
import math
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

APP_NAME = "mx_usb_airlock"
APP_VERSION = "1.0.0"
SESSION_SCHEMA = 1

PHASE_INGEST_IN_PROGRESS = "INGEST_IN_PROGRESS"
PHASE_INGESTED = "INGESTED_AWAITING_SOURCE_REMOVAL"
PHASE_SOURCE_REMOVED = "SOURCE_REMOVED"
PHASE_RELEASED = "RELEASED_AND_VERIFIED"
PHASE_BLOCKED = "BLOCKED"
PHASE_CANCELLED = "CANCELLED"
TERMINAL_PHASES = frozenset({PHASE_RELEASED, PHASE_BLOCKED, PHASE_CANCELLED})

HASH_MATCH = "INTEGRITY_VERIFIED_AGAINST_TRUSTED_HASH"
HASH_MISMATCH = "TRUSTED_HASH_MISMATCH"
HASH_NOT_PREAUTHORIZED = "HASH_NOT_PREAUTHORIZED"

SEV_INFO = "INFO"
SEV_REVIEW = "REVIEW"
SEV_BLOCKING = "BLOCKING"

DEFAULT_ALLOWED_EXTENSIONS = ("ps1", "txt", "md", "json", "sha256", "sha256sum", "csv")

# Never allowed, even if a configuration file lists them.  This tool moves
# text; executables, scripts for other interpreters, archives, images and
# macro-capable documents stay behind.
HARD_DENIED_EXTENSIONS = frozenset({
    "exe", "dll", "msi", "msp", "mst", "com", "scr", "bat", "cmd", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "lnk", "url", "iso", "img", "vhd", "vhdx",
    "vmdk", "qcow2", "sys", "psm1", "psd1", "ps1xml", "psc1", "pssc", "cdxml",
    "jar", "class", "py", "pyc", "pyo", "pyw", "pyz", "sh", "bash", "zsh", "csh",
    "ksh", "so", "elf", "bin", "run", "out", "o", "ko", "cpl", "ocx", "drv", "efi",
    "msc", "reg", "inf", "ini", "scf", "pif", "application", "appref-ms",
    "gadget", "doc", "docm", "docx", "dot", "dotm", "dotx", "xls", "xlsm", "xlsx",
    "xlsb", "xlt", "xltm", "xla", "xlam", "xll", "ppt", "pptm", "pptx", "pot",
    "potm", "ppam", "ppsm", "sldm", "rtf", "odt", "ods", "odp", "pdf", "zip",
    "7z", "rar", "gz", "tgz", "bz2", "tbz2", "xz", "txz", "zst", "lz", "lzma",
    "lz4", "tar", "cab", "arj", "lzh", "ace", "z", "dmg", "wim", "esd", "swm",
    "apk", "deb", "rpm", "appx", "msix", "appxbundle", "msixbundle", "chm",
    "hlp", "library-ms", "search-ms", "settingcontent-ms", "iqy", "slk",
    "website", "diagcab", "desktop", "html", "htm", "xhtml", "mht", "mhtml",
    "svg", "xml", "xsl", "xslt", "wasm", "dylib", "app", "pkg", "command",
    "action", "workflow", "scpt", "applescript", "lua", "pl", "pm", "rb", "php",
    "asp", "aspx", "jsp", "cer", "crt", "der", "p12", "pfx", "key", "pem",
})

SOURCE_FILESYSTEMS = ("vfat", "exfat", "ntfs", "ext2", "ext3", "ext4")
DEST_FILESYSTEMS = ("vfat", "exfat")

SKIP_DIR_NAMES = frozenset({
    "system volume information", "$recycle.bin", "recycler", "recycled",
    "lost+found", "found.000", "$extend", "msocache",
})
SYSTEM_METADATA_FILES = frozenset({
    "autorun.inf", "desktop.ini", "thumbs.db", "ehthumbs.db", "iconcache.db",
    ".ds_store", "$mft", "$bitmap", "$logfile", "$volume", "indexervolumeguid",
    "wpsettings.dat",
})

WINDOWS_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"]
    + ["COM%d" % i for i in range(10)]
    + ["LPT%d" % i for i in range(10)]
    + ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"]
)
WINDOWS_INVALID_CHARS = frozenset('<>:"|?*')
BIDI_CONTROLS = frozenset({0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C,
                           0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD})

# External tools are only ever taken from these root-owned directories, never
# from PATH, so a hostile PATH entry cannot shadow them.
TOOL_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}

SYSTEM_MOUNTPOINTS = frozenset({
    "/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/usr/local", "/var",
    "/var/log", "/var/lib", "/opt", "/srv", "/tmp", "/root",
})
LIVE_MOUNT_PREFIXES = (
    "/live", "/run/live", "/lib/live/mount", "/cdrom", "/run/initramfs/live",
    "/run/initramfs/isoscan", "/run/archiso", "/isodevice", "/run/rootfsbase",
)

KNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
MAJMIN_RE = re.compile(r"^\d{1,5}:\d{1,7}$")
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

INSTALLED_OS_WARNING = (
    "A known-good live environment was NOT detected. Running inside an "
    "installed operating system that may already be compromised cannot "
    "provide the same trust level as verified live media. Continuing as "
    "requested."
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class AirlockError(Exception):
    """Base class for expected, reportable failures."""


class BlockingError(AirlockError):
    """A security-critical condition: processing stops (fail closed)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CommandError(BlockingError):
    def __init__(self, tool: str, returncode: int, stderr: str):
        super().__init__(
            "COMMAND_FAILED",
            "%s failed with exit status %d: %s" % (tool, returncode, display_text(stderr.strip(), 300)),
        )
        self.tool = tool
        self.returncode = returncode


class ToolMissing(AirlockError):
    def __init__(self, tool: str):
        super().__init__("required tool not found in trusted system directories: %s" % tool)
        self.tool = tool


class OperatorCancelled(AirlockError):
    pass


class ConfigError(AirlockError):
    pass


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "%s-%s" % (stamp, secrets.token_hex(4))


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return ("%d %s" % (value, unit)) if unit == "B" else ("%.1f %s" % (value, unit))
        value /= 1024.0
    return "%d B" % n


def display_text(value: Any, max_len: int = 200) -> str:
    """Render untrusted text as printable ASCII.

    Device models, labels, serials and filenames come from hostile media and
    may contain terminal escape sequences, bidi overrides or lookalike
    characters.  Everything that is not printable ASCII is shown escaped.
    """
    if value is None:
        return ""
    out = []
    for ch in str(value):
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif 0x20 <= o < 0x7F:
            out.append(ch)
        elif 0xDC80 <= o <= 0xDCFF:
            out.append("\\x%02x" % (o - 0xDC00))
        elif o <= 0xFF:
            out.append("\\x%02x" % o)
        elif o <= 0xFFFF:
            out.append("\\u%04x" % o)
        else:
            out.append("\\U%08x" % o)
    text = "".join(out)
    if len(text) > max_len:
        text = text[:max_len] + "...(truncated)"
    return text


def read_bounded(fd: int, limit: int) -> bytes:
    chunks = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def open_dir_nofollow(name: Any, dir_fd: Optional[int] = None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    return os.open(name, flags, dir_fd=dir_fd)


def fsync_quiet(fd: int) -> None:
    # Directory fsync is unsupported on some filesystems (EINVAL); data files
    # are fsynced separately and a global sync follows.
    try:
        os.fsync(fd)
    except OSError:
        pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def ensure_private_dir(path: Path, create: bool = True) -> None:
    """Create or validate a 0700 directory owned by the effective user."""
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BlockingError("STATE_DIR_INVALID", "cannot access %s: %s" % (path, exc.strerror))
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise BlockingError("STATE_DIR_INVALID", "%s is not a real directory (symlink or other type)" % path)
    if st.st_uid != os.geteuid():
        raise BlockingError("STATE_DIR_INVALID", "%s is not owned by the current user" % path)
    if st.st_mode & 0o077:
        raise BlockingError("STATE_DIR_INVALID",
                            "%s is accessible by other users (mode %o); expected 0700" % (path, st.st_mode & 0o777))


def make_flag(code: str, severity: str, detail: str, lines: Optional[List[int]] = None) -> Dict[str, Any]:
    flag: Dict[str, Any] = {"code": code, "severity": severity, "detail": detail}
    if lines:
        flag["lines"] = lines[:10]
        flag["line_count"] = len(lines)
    return flag


# ---------------------------------------------------------------------------
# Console / operator interaction
# ---------------------------------------------------------------------------

class Console:
    def __init__(self, input_fn: Optional[Callable[[str], str]] = None, out: Any = None,
                 interactive: Optional[bool] = None, color: Optional[bool] = None):
        self._input = input_fn or input
        self.out = out or sys.stdout
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        if color is None:
            color = out is None and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.color = color

    def line(self, text: str = "") -> None:
        print(text, file=self.out)
        try:
            self.out.flush()
        except (AttributeError, ValueError):
            pass

    def _tag(self, tag: str, text: str, code: str) -> None:
        label = "[%s]" % tag
        if self.color:
            label = "\033[%sm%s\033[0m" % (code, label)
        self.line("%s %s" % (label, text))

    def passed(self, text: str) -> None:
        self._tag("PASS", text, "1;32")

    def warn(self, text: str) -> None:
        self._tag("WARNING", text, "1;33")

    def blocking(self, text: str) -> None:
        self._tag("BLOCKING", text, "1;31")

    def info(self, text: str) -> None:
        self._tag("INFO", text, "36")

    def heading(self, text: str) -> None:
        bar = "=" * max(20, min(78, len(text) + 4))
        self.line("")
        self.line(bar)
        self.line("  " + text)
        self.line(bar)

    def ask(self, prompt: str) -> str:
        if not self.interactive:
            raise OperatorCancelled("operator confirmation is required but no interactive terminal is attached")
        try:
            answer = self._input(prompt)
        except (EOFError, KeyboardInterrupt):
            raise OperatorCancelled("operator cancelled")
        return (answer or "").strip()

    def confirm_phrase(self, phrase: str, question: str) -> None:
        self.line(question)
        answer = self.ask("Type %s to continue (anything else cancels): " % phrase)
        if answer != phrase:
            raise OperatorCancelled("confirmation phrase not entered")


# ---------------------------------------------------------------------------
# External command execution (argument arrays only, never through a shell)
# ---------------------------------------------------------------------------

@dataclass
class CmdResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str


def _trusted_dir(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


def find_tool(name: str) -> Optional[str]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("invalid tool name")
    for directory in TOOL_DIRS:
        if not _trusted_dir(directory):
            continue
        candidate = os.path.join(directory, name)
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if st.st_uid != 0 or st.st_mode & 0o022:
            continue
        return candidate
    return None


class CommandRunner:
    def __init__(self, log: Optional["RunLog"] = None):
        self.euid = os.geteuid()
        self.log = log
        self._privilege_ready = self.euid == 0

    def ensure_privilege(self, console: Console) -> None:
        if self._privilege_ready:
            return
        sudo = find_tool("sudo")
        if sudo is None:
            raise BlockingError("PRIVILEGE_UNAVAILABLE",
                                "root is required for block-device and mount steps, but sudo was not found; "
                                "run the command from a root shell on the live system")
        console.info("Root privileges are needed only for: setting block devices read-only, mounting and "
                     "unmounting, and optional network lockdown. sudo may ask for your password.")
        try:
            rc = subprocess.run([sudo, "-v"], env=dict(SAFE_ENV), timeout=300, shell=False, check=False).returncode
        except (subprocess.TimeoutExpired, OSError):
            rc = 1
        if rc != 0:
            raise BlockingError("PRIVILEGE_UNAVAILABLE", "sudo authentication failed")
        self._privilege_ready = True

    def run(self, tool: str, args: Sequence[Any], timeout: int = 30, privileged: bool = False,
            input_text: Optional[str] = None, check: bool = True) -> CmdResult:
        exe = find_tool(tool)
        if exe is None:
            raise ToolMissing(tool)
        argv = [exe] + [str(a) for a in args]
        if privileged and self.euid != 0:
            sudo = find_tool("sudo")
            if sudo is None:
                raise BlockingError("PRIVILEGE_UNAVAILABLE", "root is required for %s but sudo was not found" % tool)
            argv = [sudo, "--"] + argv
        kwargs: Dict[str, Any] = {
            "capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace",
            "timeout": timeout, "env": dict(SAFE_ENV), "shell": False, "check": False,
        }
        if input_text is None:
            kwargs["stdin"] = subprocess.DEVNULL
        else:
            kwargs["input"] = input_text
        try:
            proc = subprocess.run(argv, **kwargs)
        except subprocess.TimeoutExpired:
            raise BlockingError("COMMAND_TIMEOUT", "%s did not finish within %d seconds" % (tool, timeout))
        except OSError as exc:
            raise BlockingError("COMMAND_FAILED", "%s could not be started: %s" % (tool, exc.strerror))
        if self.log:
            self.log.event("command", tool=tool, args=[display_text(a, 120) for a in args],
                           privileged=privileged, returncode=proc.returncode,
                           stderr=display_text(proc.stderr.strip(), 300))
        if check and proc.returncode != 0:
            raise CommandError(tool, proc.returncode, proc.stderr)
        return CmdResult(argv, proc.returncode, proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# Logging (append-only per run; filenames and hashes only, never contents)
# ---------------------------------------------------------------------------

class RunLog:
    def __init__(self, path: Path, invocation: str):
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(path, flags, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            os.close(fd)
            raise BlockingError("LOG_INVALID", "log file %s is not a regular file owned by this user" % path)
        self._file = os.fdopen(fd, "a", encoding="utf-8")
        self.path = path
        self.invocation = invocation

    def event(self, name: str, **details: Any) -> None:
        record = {"ts": utc_now(), "invocation": self.invocation, "event": name}
        record.update(details)
        self._file.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        self._file.flush()

    def close(self) -> None:
        try:
            self._file.close()
        except OSError:
            pass


class NullLog:
    path = None

    def event(self, name: str, **details: Any) -> None:
        pass

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Configuration (inert JSON only)
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: Dict[str, Any] = {
    "allowed_extensions": list(DEFAULT_ALLOWED_EXTENSIONS),
    "max_file_bytes": 2 * 1024 * 1024,
    "max_total_bytes": 32 * 1024 * 1024,
    "max_files": 200,
    "max_scan_entries": 5000,
    "max_depth": 6,
    "max_name_length": 128,
    "allow_non_ascii_names": False,
    "require_trusted_hashes": False,
    "compute_sha512": True,
    "clamav_enabled": True,
    "destination_dir_name": "RECOVERY_TRANSFER",
}

_CONFIG_LIMITS = {
    "max_file_bytes": (1, 64 * 1024 * 1024),
    "max_total_bytes": (1, 512 * 1024 * 1024),
    "max_files": (1, 10000),
    "max_scan_entries": (1, 1000000),
    "max_depth": (0, 32),
    "max_name_length": (8, 255),
}


def load_config(path: Optional[str]) -> Dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)
    if not path:
        return config
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise ConfigError("cannot open config %s: %s" % (display_text(path), exc.strerror))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 65536:
            raise ConfigError("config must be a regular file smaller than 64 KiB")
        raw = read_bounded(fd, 65537)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ConfigError("config is not valid UTF-8 JSON: %s" % exc)
    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")
    for key, value in data.items():
        if key.startswith("_comment"):
            continue
        if key not in DEFAULT_CONFIG:
            raise ConfigError("unknown config key: %s" % display_text(key))
        expected = DEFAULT_CONFIG[key]
        if isinstance(expected, bool):
            if not isinstance(value, bool):
                raise ConfigError("%s must be true or false" % key)
        elif isinstance(expected, int):
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError("%s must be an integer" % key)
            low, high = _CONFIG_LIMITS[key]
            if not low <= value <= high:
                raise ConfigError("%s must be between %d and %d" % (key, low, high))
        elif isinstance(expected, list):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise ConfigError("%s must be a list of strings" % key)
        elif isinstance(expected, str):
            if not isinstance(value, str):
                raise ConfigError("%s must be a string" % key)
        config[key] = value
    extensions = []
    for ext in config["allowed_extensions"]:
        norm = ext.strip().lower().lstrip(".")
        if not re.fullmatch(r"[a-z0-9]{1,12}", norm):
            raise ConfigError("invalid extension in allowed_extensions: %s" % display_text(ext))
        if norm in HARD_DENIED_EXTENSIONS:
            raise ConfigError("extension .%s is on the built-in deny list and cannot be allowlisted" % norm)
        extensions.append(norm)
    if not extensions:
        raise ConfigError("allowed_extensions must not be empty")
    config["allowed_extensions"] = sorted(set(extensions))
    dest = config["destination_dir_name"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", dest) or check_name_component(dest):
        raise ConfigError("destination_dir_name must be 1-64 characters of A-Z, a-z, 0-9, _ or -")
    return config


# ---------------------------------------------------------------------------
# Filename and path validation
# ---------------------------------------------------------------------------

def check_name_component(name: str, max_len: int = 128, allow_non_ascii: bool = False) -> List[str]:
    """Return reason codes for an unsafe single path component (empty if acceptable)."""
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
    encoded_len = len(name.encode("utf-8", "replace"))
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        add("INVALID_NAME_ENCODING")
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
        # Rejecting all non-ASCII names is the feasible defence against
        # lookalike (homoglyph) filenames.
        add("NON_ASCII_NAME")
    if "INVALID_NAME_ENCODING" not in reasons and unicodedata.normalize("NFC", name) != name:
        add("NOT_NFC_NORMALIZED")
    if name[-1] in " .":
        add("TRAILING_SPACE_OR_DOT")
    if name[0] == " ":
        add("LEADING_SPACE")
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if stem in WINDOWS_RESERVED_NAMES:
        add("WINDOWS_RESERVED_NAME")
    if len(name) > max_len or encoded_len > 255:
        add("NAME_TOO_LONG")
    return reasons


def file_extension(name: str) -> str:
    stripped = name.lstrip(".")
    if "." not in stripped:
        return ""
    return stripped.rsplit(".", 1)[1].lower()


def check_extension(name: str, allowed: Iterable[str]) -> List[str]:
    reasons = []
    ext = file_extension(name)
    if not ext:
        reasons.append("NO_EXTENSION")
    elif ext in HARD_DENIED_EXTENSIONS:
        reasons.append("DENIED_FILE_TYPE")
    elif ext not in allowed:
        reasons.append("TYPE_NOT_ALLOWLISTED")
    inner = name.lstrip(".").split(".")[1:-1]
    if any(part.strip().lower() in HARD_DENIED_EXTENSIONS for part in inner):
        reasons.append("DECEPTIVE_DOUBLE_EXTENSION")
    return reasons


def validate_relative_path(rel: Any, max_len: int = 255, allow_non_ascii: bool = False) -> List[str]:
    """Split and validate a relative path; raise BlockingError on traversal or unsafe parts."""
    if not isinstance(rel, str) or not rel:
        raise BlockingError("PATH_TRAVERSAL", "empty or invalid relative path")
    if rel.startswith("/") or rel.startswith("\\") or re.match(r"^[A-Za-z]:", rel):
        raise BlockingError("ABSOLUTE_PATH", "absolute path rejected: %s" % display_text(rel))
    parts = rel.split("/")
    for part in parts:
        reasons = check_name_component(part, max_len, allow_non_ascii)
        if reasons:
            code = "PATH_TRAVERSAL" if "PATH_TRAVERSAL" in reasons else "UNSAFE_PATH_COMPONENT"
            raise BlockingError(code, "unsafe path component %s (%s)" % (display_text(part), ", ".join(reasons)))
    return parts


# ---------------------------------------------------------------------------
# Content inspection
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: Tuple[Tuple[int, bytes, str], ...] = (
    (0, b"\x7fELF", "ELF_EXECUTABLE"),
    (0, b"PK\x03\x04", "ZIP_ARCHIVE_OR_OFFICE_DOCUMENT"),
    (0, b"PK\x05\x06", "ZIP_ARCHIVE_OR_OFFICE_DOCUMENT"),
    (0, b"PK\x07\x08", "ZIP_ARCHIVE_OR_OFFICE_DOCUMENT"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE_COMPOUND_DOCUMENT_OR_MSI"),
    (0, b"Rar!\x1a\x07", "RAR_ARCHIVE"),
    (0, b"7z\xbc\xaf\x27\x1c", "7Z_ARCHIVE"),
    (0, b"\x1f\x8b", "GZIP_ARCHIVE"),
    (0, b"\xfd7zXZ\x00", "XZ_ARCHIVE"),
    (0, b"\x28\xb5\x2f\xfd", "ZSTD_ARCHIVE"),
    (0, b"\x04\x22\x4d\x18", "LZ4_ARCHIVE"),
    (0, b"MSCF", "CAB_ARCHIVE"),
    (0, b"ITSF", "CHM_HELP_FILE"),
    (0, b"%PDF-", "PDF_DOCUMENT"),
    (0, b"{\\rtf", "RTF_DOCUMENT"),
    (0, b"\xca\xfe\xba\xbe", "JAVA_CLASS_OR_MACHO"),
    (0, b"\xfe\xed\xfa\xce", "MACHO_EXECUTABLE"),
    (0, b"\xfe\xed\xfa\xcf", "MACHO_EXECUTABLE"),
    (0, b"\xce\xfa\xed\xfe", "MACHO_EXECUTABLE"),
    (0, b"\xcf\xfa\xed\xfe", "MACHO_EXECUTABLE"),
    (0, b"L\x00\x00\x00\x01\x14\x02\x00", "WINDOWS_SHORTCUT"),
    (0, b"conectix", "VHD_DISK_IMAGE"),
    (0, b"vhdxfile", "VHDX_DISK_IMAGE"),
    (0, b"KDMV", "VMDK_DISK_IMAGE"),
    (0, b"QFI\xfb", "QCOW_DISK_IMAGE"),
    (0, b"\x00asm", "WASM_MODULE"),
    (0, b"SQLite format 3\x00", "SQLITE_DATABASE"),
    (0, b"MSWIM\x00", "WIM_IMAGE"),
    (0, b"!<arch>\n", "AR_ARCHIVE_OR_DEB"),
    (0, b"\xed\xab\xee\xdb", "RPM_PACKAGE"),
    (0, b"hsqs", "SQUASHFS_IMAGE"),
    (0x8001, b"CD001", "ISO9660_IMAGE"),
    (257, b"ustar", "TAR_ARCHIVE"),
)


def detect_binary_signatures(data: bytes) -> List[str]:
    found = []
    for offset, sig, label in MAGIC_SIGNATURES:
        if data[offset:offset + len(sig)] == sig and label not in found:
            found.append(label)
    if data[:3] == b"BZh" and data[4:10] == b"1AY&SY":
        found.append("BZIP2_ARCHIVE")
    if data[:2] == b"MZ":
        label = "MZ_EXECUTABLE_HEADER"
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if 0 < pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                label = "PE_EXECUTABLE"
        found.append(label)
    if len(data) >= 512 and data[-512:-504] == b"conectix" and "VHD_DISK_IMAGE" not in found:
        found.append("VHD_DISK_IMAGE")
    return found


def decode_text(data: bytes) -> Tuple[Optional[str], str, List[Dict[str, Any]], List[str]]:
    """Decode file bytes for inspection only. Returns (text, encoding, flags, reject_reasons)."""
    flags: List[Dict[str, Any]] = []
    if data.startswith(b"\x00\x00\xfe\xff") or data.startswith(b"\xff\xfe\x00\x00"):
        return None, "utf-32", flags, ["UNSUPPORTED_UTF32_ENCODING"]
    if data.startswith(b"\xef\xbb\xbf"):
        encoding, body = "utf-8", data[3:]
    elif data.startswith(b"\xff\xfe"):
        encoding, body = "utf-16-le", data[2:]
    elif data.startswith(b"\xfe\xff"):
        encoding, body = "utf-16-be", data[2:]
    else:
        encoding, body = "utf-8", data
    if encoding == "utf-8" and b"\x00" in body:
        return None, encoding, flags, ["NUL_BYTES_PRESENT"]
    try:
        text = body.decode(encoding)
    except UnicodeDecodeError:
        if encoding != "utf-8":
            return None, encoding, flags, ["NOT_VALID_TEXT"]
        try:
            text = body.decode("cp1252")
        except UnicodeDecodeError:
            return None, encoding, flags, ["NOT_VALID_TEXT"]
        encoding = "cp1252"
        flags.append(make_flag("LEGACY_8BIT_ENCODING", SEV_REVIEW,
                               "not valid UTF-8; decoded as Windows-1252 for inspection only (bytes are copied unchanged)"))
    if "\x00" in text:
        return None, encoding, flags, ["NUL_CHARACTERS_PRESENT"]
    controls = sum(1 for ch in text
                   if (ord(ch) < 0x20 and ch not in "\t\n\r\x0c") or 0x7F <= ord(ch) <= 0x9F)
    if controls:
        if controls > max(8, len(text) // 100):
            return None, encoding, flags, ["BINARY_CONTENT"]
        flags.append(make_flag("CONTROL_CHARACTERS", SEV_REVIEW,
                               "%d non-printing control characters present" % controls))
    return text, encoding, flags, []


BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{64,}")


def shannon_entropy(token: str) -> float:
    counts: Dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(token))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def text_heuristics(text: str) -> List[Dict[str, Any]]:
    flags = []
    bidi_lines, zw_lines, long_lines, b64_lines, entropy_lines = [], [], [], [], []
    non_ascii = 0
    for number, line in enumerate(text.splitlines(), 1):
        if not line.isascii():
            for ch in line:
                o = ord(ch)
                if o > 0x7F:
                    non_ascii += 1
                if o in BIDI_CONTROLS and (not bidi_lines or bidi_lines[-1] != number):
                    bidi_lines.append(number)
                elif o in ZERO_WIDTH and not (o == 0xFEFF and number == 1 and line.startswith(ch)):
                    if not zw_lines or zw_lines[-1] != number:
                        zw_lines.append(number)
        if len(line) > 1000:
            long_lines.append(number)
        if BASE64_BLOB_RE.search(line):
            b64_lines.append(number)
        for match in TOKEN_RE.finditer(line):
            if shannon_entropy(match.group(0)) > 4.8:
                entropy_lines.append(number)
                break
    if bidi_lines:
        flags.append(make_flag("SUSPICIOUS_UNICODE_BIDI_CONTROL", SEV_REVIEW,
                               "bidirectional override/control characters can make code display differently from how it runs",
                               bidi_lines))
    if zw_lines:
        flags.append(make_flag("INVISIBLE_UNICODE_CHARACTER", SEV_REVIEW, "zero-width or invisible characters", zw_lines))
    if long_lines:
        flags.append(make_flag("EXTREMELY_LONG_LINE", SEV_REVIEW, "lines longer than 1000 characters", long_lines))
    if b64_lines:
        flags.append(make_flag("BASE64_BLOB", SEV_REVIEW, "long base64-like data", b64_lines))
    if entropy_lines:
        flags.append(make_flag("HIGH_ENTROPY_DATA", SEV_REVIEW, "high-entropy embedded token (possible packed or encrypted data)",
                               entropy_lines))
    if non_ascii:
        flags.append(make_flag("NON_ASCII_CHARACTERS", SEV_INFO, "%d non-ASCII characters (check for lookalikes)" % non_ascii))
    return flags


_PS_PATTERN_SPECS: Tuple[Tuple[str, str, str], ...] = (
    ("ENCODED_COMMAND",
     r"(?<![\w-])-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+['\"]?[A-Za-z0-9+/]{16,}={0,2}",
     "encoded PowerShell command argument"),
    ("FROMBASE64STRING", r"FromBase64String", "base64 decoding"),
    ("INVOKE_EXPRESSION", r"\bInvoke-Expression\b", "Invoke-Expression (dynamic code execution)"),
    ("IEX_ALIAS", r"(?<![\w-])iex(?![\w-])", "IEX alias (dynamic code execution)"),
    ("DOWNLOADSTRING", r"\.DownloadString(?:Async)?\s*\(", "WebClient.DownloadString"),
    ("DOWNLOADFILE", r"\.DownloadFile(?:Async|TaskAsync)?\s*\(", "WebClient.DownloadFile"),
    ("DOWNLOADDATA", r"\.DownloadData(?:Async)?\s*\(", "WebClient.DownloadData"),
    ("INVOKE_WEBREQUEST", r"\b(?:Invoke-WebRequest|Invoke-RestMethod)\b|(?<![\w-])(?:iwr|irm)(?![\w-])",
     "web request cmdlet"),
    ("CURL_WGET", r"(?<![\w.-])(?:curl|wget)(?:\.exe)?(?![\w-])", "curl/wget"),
    ("WEBCLIENT", r"Net\.WebClient|\bWebClient\b|Net\.Http\.HttpClient", "WebClient/HttpClient"),
    ("BITS_TRANSFER", r"\bStart-BitsTransfer\b|\bbitsadmin\b", "BITS transfer"),
    ("REFLECTION_LOADING",
     r"Reflection\.Assembly|\[System\.Reflection|Assembly\]::(?:Load|LoadFile|LoadFrom|LoadWithPartialName)"
     r"|GetDelegateForFunctionPointer|VirtualAlloc|\.GetMethod\(\s*['\"]Invoke",
     "reflection-based loading"),
    ("ADD_TYPE", r"\bAdd-Type\b", "Add-Type (inline compiled code)"),
    ("RUNDLL32", r"\brundll32\b", "rundll32"),
    ("REGSVR32", r"\bregsvr32\b", "regsvr32"),
    ("MSHTA", r"\bmshta\b", "mshta"),
    ("CERTUTIL_DOWNLOAD_OR_DECODE", r"\bcertutil(?:\.exe)?\b[^\r\n]*(?:-urlcache|-decode|-decodehex|-split|https?://)",
     "certutil download/decode behaviour"),
    ("SCHEDULED_TASK", r"\b(?:Register-ScheduledTask|New-ScheduledTask\w*|Set-ScheduledTask|schtasks(?:\.exe)?)\b",
     "scheduled task creation/change"),
    ("SERVICE_CREATION", r"\bNew-Service\b|\bsc(?:\.exe)?\s+(?:create|config)\b|Win32_Service[^\r\n]*Create",
     "service creation/change"),
    ("RUN_KEY_PERSISTENCE", r"CurrentVersion\\+Run(?:Once|Services)?\b|\\Winlogon\\+(?:Userinit|Shell)\b",
     "Run/RunOnce/Winlogon persistence keys"),
    ("WMI_PERSISTENCE",
     r"__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding"
     r"|\bSet-WmiInstance\b|\bRegister-WmiEvent\b|\bRegister-CimIndicationEvent\b",
     "WMI event subscription persistence"),
    ("POWERSHELL_REMOTING",
     r"\b(?:Enter-PSSession|New-PSSession|Enable-PSRemoting)\b|\bInvoke-Command\b[^\r\n]*-ComputerName\b",
     "PowerShell remoting"),
    ("WINRM_CHANGE", r"\bwinrm(?:\.cmd)?\b|WSMan:|\bSet-WSManQuickConfig\b|\bSet-WSManInstance\b", "WinRM configuration"),
    ("DEFENDER_EXCLUSION", r"\b(?:Add|Set)-MpPreference\b[^\r\n]*-Exclusion\w*", "Microsoft Defender exclusion"),
    ("DEFENDER_DISABLE",
     r"\bSet-MpPreference\b[^\r\n]*-Disable\w+\s+(?:\$true|1|true)\b|DisableRealtimeMonitoring|DisableAntiSpyware"
     r"|DisableBehaviorMonitoring|DisableIOAVProtection",
     "Microsoft Defender disable setting (check the value)"),
    ("FIREWALL_DISABLE",
     r"\bSet-NetFirewallProfile\b[^\r\n]*-Enabled\s+(?:\$?false|0)\b"
     r"|\bnetsh\s+(?:adv)?firewall\b[^\r\n]*\b(?:state\s+off|disable)\b",
     "firewall disabling"),
    ("EXECUTION_POLICY_WEAKENING",
     r"\bSet-ExecutionPolicy\b[^\r\n]*\b(?:Bypass|Unrestricted)\b|(?<![\w-])-(?:ExecutionPolicy|ep|exec)\s+(?:Bypass|Unrestricted)\b",
     "execution policy weakening"),
    ("HIDDEN_POWERSHELL_LAUNCH",
     r"(?<![\w-])-(?:WindowStyle|w|win|window)\s+(?:Hidden|h)\b|CreateNoWindow\s*=\s*\$?true",
     "hidden window launch"),
)
PS_PATTERNS = tuple((code, re.compile(rx, re.IGNORECASE), desc) for code, rx, desc in _PS_PATTERN_SPECS)
# PowerShell's escape character (ASCII 0x60) can split keywords to evade
# matching.  It is built from its code point so this source file contains none.
PS_ESCAPE_CHAR = chr(0x60)
PS_ESCAPE_IN_WORD_RE = re.compile("[A-Za-z]" + re.escape(PS_ESCAPE_CHAR) + "[A-Za-z]")


def scan_powershell(text: str) -> List[Dict[str, Any]]:
    """Static review flags for PowerShell. Informational only; nothing is executed or rewritten."""
    hits: Dict[str, List[int]] = {}
    descriptions = {code: desc for code, _rx, desc in PS_PATTERNS}
    for number, line in enumerate(text.splitlines(), 1):
        variants = [line]
        if PS_ESCAPE_CHAR in line:
            variants.append(line.replace(PS_ESCAPE_CHAR, ""))
            if PS_ESCAPE_IN_WORD_RE.search(line):
                hits.setdefault("ESCAPE_CHARACTER_OBFUSCATION", []).append(number)
        for code, rx, _desc in PS_PATTERNS:
            if any(rx.search(v) for v in variants):
                hits.setdefault(code, []).append(number)
    descriptions["ESCAPE_CHARACTER_OBFUSCATION"] = "PowerShell escape character inside a word (keyword splitting)"
    return [make_flag(code, SEV_REVIEW, descriptions[code], lines) for code, lines in hits.items()]


def inspect_content(name: str, data: bytes) -> Tuple[List[str], List[Dict[str, Any]], str]:
    """Return (reject_reasons, review_flags, encoding) for file bytes."""
    ext = file_extension(name)
    if not data:
        return [], [make_flag("ZERO_BYTE_FILE", SEV_REVIEW, "file is empty")], "empty"
    signatures = detect_binary_signatures(data)
    if signatures:
        return ["BINARY_SIGNATURE:" + s for s in signatures], [], "binary"
    text, encoding, flags, rejects = decode_text(data)
    if rejects or text is None:
        return rejects or ["NOT_VALID_TEXT"], flags, encoding
    if text.startswith("#!") and ext != "ps1":
        flags.append(make_flag("SHEBANG_SCRIPT_HEADER", SEV_REVIEW, "file starts with a script interpreter line"))
    flags.extend(text_heuristics(text))
    if ext == "ps1":
        flags.extend(scan_powershell(text))
    elif ext == "json":
        try:
            json.loads(text)
        except (ValueError, RecursionError):
            flags.append(make_flag("INVALID_JSON", SEV_REVIEW, "content does not parse as JSON"))
    elif ext == "csv":
        formula_lines = []
        for number, line in enumerate(text.splitlines(), 1):
            for cell in line.split(","):
                c = cell.strip().lstrip("\"'")
                if c[:1] in ("=", "+", "@") or (c[:1] == "-" and len(c) > 1 and not (c[1].isdigit() or c[1] == ".")):
                    formula_lines.append(number)
                    break
        if formula_lines:
            flags.append(make_flag("CSV_FORMULA_PREFIX", SEV_REVIEW,
                                   "cells starting with = + - @ can execute as spreadsheet formulas", formula_lines))
    return [], flags, encoding


# ---------------------------------------------------------------------------
# Device model
# ---------------------------------------------------------------------------

@dataclass
class Partition:
    kname: str
    maj_min: str
    size: int = 0
    fstype: str = ""
    uuid: str = ""
    label: str = ""
    partuuid: str = ""
    ro: bool = False


@dataclass
class Disk:
    kname: str
    maj_min: str
    size: int = 0
    tran: str = ""
    removable: bool = False
    hotplug: bool = False
    ro: bool = False
    model: str = ""
    vendor: str = ""
    serial: str = ""
    by_id: List[str] = field(default_factory=list)
    partitions: List[Partition] = field(default_factory=list)
    whole_disk_fs: bool = False

    def preferred_by_id(self) -> str:
        usb = sorted(n for n in self.by_id if n.startswith("usb-"))
        if usb:
            return usb[0]
        return sorted(self.by_id)[0] if self.by_id else ""

    def identity(self) -> Dict[str, Any]:
        return {
            "kname": self.kname, "maj_min": self.maj_min, "size": self.size, "tran": self.tran,
            "model": self.model, "vendor": self.vendor, "serial": self.serial,
            "by_id": sorted(self.by_id), "fs_uuids": sorted(p.uuid for p in self.partitions if p.uuid),
        }

    def partition(self, kname: str) -> Optional[Partition]:
        for p in self.partitions:
            if p.kname == kname:
                return p
        return None


@dataclass
class MountEntry:
    target: str
    maj_min: str
    fstype: str
    source: str
    options: frozenset
    super_options: frozenset


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip() in ("1", "true", "True")
    return False


def _to_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _to_str(value: Any) -> str:
    return "" if value is None else str(value).strip()


LSBLK_COLUMNS = "NAME,KNAME,MAJ:MIN,TYPE,TRAN,RM,HOTPLUG,RO,SIZE,MODEL,VENDOR,SERIAL,FSTYPE,UUID,LABEL,PARTUUID"


def parse_lsblk_json(text: str) -> List[Disk]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise BlockingError("DEVICE_ENUMERATION_FAILED", "lsblk returned invalid JSON: %s" % exc)
    disks: List[Disk] = []
    for dev in data.get("blockdevices", []) or []:
        if not isinstance(dev, dict) or _to_str(dev.get("type")) != "disk":
            continue
        kname = _to_str(dev.get("kname")) or _to_str(dev.get("name"))
        maj_min = _to_str(dev.get("maj:min"))
        if not KNAME_RE.match(kname) or not MAJMIN_RE.match(maj_min):
            continue
        size = _to_int(dev.get("size"))
        if size <= 0:
            continue
        disk = Disk(kname=kname, maj_min=maj_min, size=size, tran=_to_str(dev.get("tran")).lower(),
                    removable=_to_bool(dev.get("rm")), hotplug=_to_bool(dev.get("hotplug")),
                    ro=_to_bool(dev.get("ro")), model=_to_str(dev.get("model")),
                    vendor=_to_str(dev.get("vendor")), serial=_to_str(dev.get("serial")))
        for child in dev.get("children", []) or []:
            if not isinstance(child, dict) or _to_str(child.get("type")) != "part":
                continue
            ck = _to_str(child.get("kname")) or _to_str(child.get("name"))
            cmm = _to_str(child.get("maj:min"))
            if not KNAME_RE.match(ck) or not MAJMIN_RE.match(cmm):
                continue
            disk.partitions.append(Partition(kname=ck, maj_min=cmm, size=_to_int(child.get("size")),
                                             fstype=_to_str(child.get("fstype")).lower(),
                                             uuid=_to_str(child.get("uuid")), label=_to_str(child.get("label")),
                                             partuuid=_to_str(child.get("partuuid")), ro=_to_bool(child.get("ro"))))
        fstype = _to_str(dev.get("fstype")).lower()
        if not disk.partitions and fstype:
            # Filesystem directly on the whole device ("superfloppy" layout).
            disk.partitions.append(Partition(kname=kname, maj_min=maj_min, size=size, fstype=fstype,
                                             uuid=_to_str(dev.get("uuid")), label=_to_str(dev.get("label")),
                                             ro=disk.ro))
            disk.whole_disk_fs = True
        disks.append(disk)
    return disks


def _unescape_mount_field(raw: bytes) -> str:
    out = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), raw)
    return out.decode("utf-8", "surrogateescape")


def parse_mountinfo(data: bytes) -> List[MountEntry]:
    entries = []
    for line in data.splitlines():
        fields = line.split(b" ")
        try:
            sep = fields.index(b"-", 6)
        except ValueError:
            continue
        if len(fields) < sep + 4:
            continue
        entries.append(MountEntry(
            target=_unescape_mount_field(fields[4]),
            maj_min=fields[2].decode("ascii", "replace"),
            fstype=fields[sep + 1].decode("ascii", "replace"),
            source=_unescape_mount_field(fields[sep + 2]),
            options=frozenset(fields[5].decode("ascii", "replace").split(",")),
            super_options=frozenset(fields[sep + 3].decode("ascii", "replace").split(",")),
        ))
    return entries


def read_mountinfo() -> List[MountEntry]:
    with open("/proc/self/mountinfo", "rb") as handle:
        return parse_mountinfo(handle.read(8 * 1024 * 1024))


def mount_options(fstype: str, mode: str, uid: int, gid: int) -> Tuple[str, str]:
    """Return (kernel filesystem type, option string) for a supported filesystem."""
    if mode not in ("ro", "rw"):
        raise ValueError("mode must be ro or rw")
    ro = mode == "ro"
    opts = [mode, "nodev", "nosuid", "noexec"]
    owner = ["uid=%d" % int(uid), "gid=%d" % int(gid),
             "fmask=0377" if ro else "fmask=0177", "dmask=0277" if ro else "dmask=0077"]
    if fstype == "vfat":
        opts += owner + ["shortname=mixed", "utf8"] + ([] if ro else ["flush"])
        return "vfat", ",".join(opts)
    if fstype == "exfat":
        return "exfat", ",".join(opts + owner)
    if not ro:
        raise BlockingError("UNSUPPORTED_FILESYSTEM",
                            "destination filesystem %s is not supported for writing; use FAT32 or exFAT "
                            "(prepare-clean-usb can create FAT32)" % display_text(fstype))
    if fstype == "ntfs":
        return "ntfs3", ",".join(opts + owner)
    if fstype == "ext2":
        return "ext2", ",".join(opts)
    if fstype in ("ext3", "ext4"):
        # noload: never replay a journal from untrusted media.
        return "ext4", ",".join(opts + ["noload"])
    raise BlockingError("UNSUPPORTED_FILESYSTEM", "filesystem type %s is not supported" % display_text(fstype))


# ---------------------------------------------------------------------------
# Real Linux backend
# ---------------------------------------------------------------------------

def _read_sys(path: str, limit: int = 4096) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit).strip()
    except OSError:
        return ""


def _majmin_of_dev(st_dev: int) -> str:
    return "%d:%d" % (os.major(st_dev), os.minor(st_dev))


class LinuxBackend:
    simulated = False

    def __init__(self, runner: CommandRunner):
        self.runner = runner

    # -- hooks used by the simulator; no-ops on real hardware
    def notify(self, event: str, **details: Any) -> None:
        pass

    def ensure_privilege(self, console: Console) -> None:
        self.runner.ensure_privilege(console)

    # -- enumeration
    def list_disks(self) -> List[Disk]:
        result = self.runner.run("lsblk", ["-J", "-b", "-o", LSBLK_COLUMNS], timeout=20)
        disks = parse_lsblk_json(result.stdout)
        by_id = self._by_id_map()
        for disk in disks:
            disk.by_id = sorted(by_id.get(disk.kname, []))
            if not disk.serial or not disk.tran:
                props = self._udev_props(disk.kname)
                if not disk.serial:
                    disk.serial = props.get("ID_SERIAL_SHORT", "")
                if not disk.tran and props.get("ID_BUS") == "usb":
                    disk.tran = "usb"
        return disks

    @staticmethod
    def _by_id_map() -> Dict[str, List[str]]:
        mapping: Dict[str, List[str]] = {}
        base = "/dev/disk/by-id"
        try:
            names = os.listdir(base)
        except OSError:
            return mapping
        for name in names:
            target = os.path.realpath(os.path.join(base, name))
            if os.path.dirname(target) != "/dev":
                continue
            kname = os.path.basename(target)
            if KNAME_RE.match(kname):
                mapping.setdefault(kname, []).append(name)
        return mapping

    def _udev_props(self, kname: str) -> Dict[str, str]:
        if find_tool("udevadm") is None:
            return {}
        try:
            res = self.runner.run("udevadm", ["info", "--query=property", "--name=/dev/" + kname],
                                  timeout=15, check=False)
        except (BlockingError, ToolMissing):
            return {}
        props = {}
        for line in res.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and re.fullmatch(r"[A-Z0-9_]+", key):
                props[key] = value.strip()
        return props

    def _whole_disks_for_kname(self, kname: str, depth: int = 0) -> Set[str]:
        if depth > 8 or not KNAME_RE.match(kname):
            return set()
        sysdir = "/sys/class/block/" + kname
        if not os.path.exists(sysdir):
            return set()
        if os.path.exists(sysdir + "/partition"):
            parent = os.path.basename(os.path.dirname(os.path.realpath(sysdir)))
            return {parent} if KNAME_RE.match(parent) else set()
        result: Set[str] = set()
        try:
            slaves = os.listdir(sysdir + "/slaves")
        except OSError:
            slaves = []
        for slave in slaves:
            result |= self._whole_disks_for_kname(slave, depth + 1)
        if kname.startswith("loop"):
            backing = _read_sys(sysdir + "/loop/backing_file")
            if backing:
                try:
                    result |= self._whole_disks_for_majmin(_majmin_of_dev(os.stat(backing).st_dev), depth + 1)
                except OSError:
                    pass
        if not result:
            result.add(kname)
        return result

    def _whole_disks_for_majmin(self, maj_min: str, depth: int = 0) -> Set[str]:
        if not MAJMIN_RE.match(maj_min) or maj_min.startswith("0:"):
            return set()
        try:
            kname = os.path.basename(os.readlink("/sys/dev/block/" + maj_min))
        except OSError:
            return set()
        return self._whole_disks_for_kname(kname, depth)

    def _whole_disks_for_mount(self, entry: MountEntry) -> Set[str]:
        disks = self._whole_disks_for_majmin(entry.maj_min)
        if entry.source.startswith("/dev/"):
            try:
                st = os.stat(entry.source)
                if stat.S_ISBLK(st.st_mode):
                    disks |= self._whole_disks_for_majmin(_majmin_of_dev(st.st_rdev))
            except OSError:
                pass
        return disks

    def protected_disks(self) -> Dict[str, str]:
        """Disks that must never be selected: system, swap, and live boot media."""
        reasons: Dict[str, str] = {}
        for entry in read_mountinfo():
            reason = None
            if entry.target in SYSTEM_MOUNTPOINTS:
                reason = "SYSTEM DISK (mounted at %s)" % entry.target
            elif any(entry.target == p or entry.target.startswith(p + "/") for p in LIVE_MOUNT_PREFIXES):
                reason = "LIVE BOOT DEVICE (mounted at %s)" % display_text(entry.target)
            if reason:
                for disk in self._whole_disks_for_mount(entry):
                    reasons.setdefault(disk, reason)
        swaps = _read_sys("/proc/swaps", 65536).splitlines()[1:]
        for line in swaps:
            path = line.split()[0] if line.split() else ""
            try:
                st = os.stat(path)
            except OSError:
                continue
            if stat.S_ISBLK(st.st_mode):
                for disk in self._whole_disks_for_majmin(_majmin_of_dev(st.st_rdev)):
                    reasons.setdefault(disk, "SYSTEM DISK (active swap)")
        try:
            loops = [n for n in os.listdir("/sys/block") if n.startswith("loop")]
        except OSError:
            loops = []
        for loop in loops:
            backing = _read_sys("/sys/block/%s/loop/backing_file" % loop)
            if not backing:
                continue
            try:
                dev = _majmin_of_dev(os.stat(backing).st_dev)
            except OSError:
                continue
            for disk in self._whole_disks_for_majmin(dev):
                reasons.setdefault(disk, "LIVE BOOT DEVICE (holds a loop-mounted image)")
        return reasons

    def live_media_uuid_hints(self) -> List[str]:
        hints = []
        for token in _read_sys("/proc/cmdline", 8192).split():
            key, sep, value = token.partition("=")
            if not sep or key not in ("bdev", "from", "live-media", "fromiso", "root", "rootdev", "img_dev"):
                continue
            if value.upper().startswith("UUID="):
                value = value[5:]
            if re.fullmatch(r"[0-9A-Fa-f-]{4,64}", value):
                hints.append(value)
        return hints

    # -- device node / mount operations
    def check_node(self, kname: str, maj_min: str) -> None:
        if not KNAME_RE.match(kname) or not MAJMIN_RE.match(maj_min):
            raise BlockingError("IDENTITY_UNCERTAIN", "invalid kernel device name")
        path = "/dev/" + kname
        try:
            st = os.lstat(path)
        except OSError:
            raise BlockingError("DEVICE_DISAPPEARED", "%s no longer exists" % path)
        if not stat.S_ISBLK(st.st_mode) or _majmin_of_dev(st.st_rdev) != maj_min:
            raise BlockingError("IDENTITY_CHANGED", "%s no longer refers to device %s" % (path, maj_min))

    def mounts_of(self, part: Partition) -> List[MountEntry]:
        return [m for m in read_mountinfo() if m.maj_min == part.maj_min]

    def is_mounted_at(self, target: Path) -> bool:
        real = os.path.realpath(str(target))
        return any(m.target == real for m in read_mountinfo())

    def unmount_partition(self, part: Partition, target: Optional[Path] = None) -> None:
        for _ in range(6):
            mounted_target = target is not None and self.is_mounted_at(target)
            if not self.mounts_of(part) and not mounted_target:
                return
            if mounted_target:
                arg = os.path.realpath(str(target))
            else:
                self.check_node(part.kname, part.maj_min)
                arg = "/dev/" + part.kname
            self.runner.run("umount", ["--", arg], privileged=True, timeout=90, check=False)
        if self.mounts_of(part) or (target is not None and self.is_mounted_at(target)):
            raise BlockingError("UNMOUNT_FAILED", "could not unmount /dev/%s" % part.kname)

    def set_readonly(self, disk: Disk) -> Tuple[bool, Dict[str, Any]]:
        details: Dict[str, Any] = {}
        ok = True
        nodes = [(disk.kname, disk.maj_min)] + [(p.kname, p.maj_min) for p in disk.partitions if p.kname != disk.kname]
        for kname, maj_min in nodes:
            self.check_node(kname, maj_min)
            set_res = self.runner.run("blockdev", ["--setro", "/dev/" + kname], privileged=True, timeout=30, check=False)
            get_res = self.runner.run("blockdev", ["--getro", "/dev/" + kname], privileged=True, timeout=30, check=False)
            sysfs = _read_sys("/sys/class/block/%s/ro" % kname)
            verified = set_res.returncode == 0 and get_res.stdout.strip() == "1" and sysfs == "1"
            details[kname] = {"setro_exit": set_res.returncode, "getro": get_res.stdout.strip(),
                              "sysfs_ro": sysfs, "verified": verified}
            ok = ok and verified
        return ok, details

    @staticmethod
    def _check_mountpoint(target: Path) -> None:
        st = os.lstat(target)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise BlockingError("MOUNTPOINT_INVALID", "mount point %s is not a private directory" % target)
        if os.listdir(target):
            raise BlockingError("MOUNTPOINT_INVALID", "mount point %s is not empty" % target)
        if st.st_dev != os.stat(os.path.dirname(os.path.realpath(str(target)))).st_dev:
            raise BlockingError("MOUNTPOINT_INVALID", "mount point %s is already a mount" % target)

    def mount(self, part: Partition, fstype: str, target: Path, options: str) -> Path:
        self.check_node(part.kname, part.maj_min)
        self._check_mountpoint(target)
        res = self.runner.run("mount", ["-i", "-t", fstype, "-o", options, "--", "/dev/" + part.kname,
                                        os.path.realpath(str(target))],
                              privileged=True, timeout=90, check=False)
        if res.returncode != 0:
            raise BlockingError("MOUNT_FAILED", "mount of /dev/%s failed: %s" % (part.kname, display_text(res.stderr.strip(), 300)))
        return Path(target)

    def verify_mount(self, part: Partition, root: Path, expect_ro: bool) -> Dict[str, Any]:
        real = os.path.realpath(str(root))
        matches = [m for m in read_mountinfo() if m.target == real]
        if not matches:
            raise BlockingError("FILESYSTEM_DISAPPEARED", "filesystem is no longer mounted at %s" % real)
        entry = matches[-1]
        if entry.maj_min != part.maj_min:
            raise BlockingError("MOUNT_SOURCE_MISMATCH", "mount at %s is not backed by the selected device" % real)
        need = {"nodev", "nosuid", "noexec", "ro" if expect_ro else "rw"}
        missing = need - set(entry.options)
        if missing:
            raise BlockingError("MOUNT_OPTIONS_NOT_ENFORCED", "mount is missing options: %s" % ",".join(sorted(missing)))
        if _majmin_of_dev(os.stat(real).st_dev) != part.maj_min:
            raise BlockingError("MOUNT_SOURCE_MISMATCH", "mounted filesystem device number does not match")
        return {"target": real, "fstype": entry.fstype, "options": sorted(entry.options),
                "super_options": sorted(entry.super_options)}

    def expected_root_dev(self, part: Partition) -> Optional[int]:
        major, minor = part.maj_min.split(":")
        return os.makedev(int(major), int(minor))

    def flush_buffers(self, part: Partition) -> None:
        try:
            self.check_node(part.kname, part.maj_min)
            self.runner.run("blockdev", ["--flushbufs", "/dev/" + part.kname], privileged=True, timeout=60, check=False)
        except (BlockingError, ToolMissing):
            pass

    def path_on_devices(self, path: str, knames: Iterable[str]) -> bool:
        try:
            dev = _majmin_of_dev(os.stat(path).st_dev)
        except OSError:
            return False
        return bool(self._whole_disks_for_majmin(dev) & set(knames))

    def filesystem_type_of(self, path: Path) -> str:
        real = os.path.realpath(str(path))
        best = ("", "")
        for entry in read_mountinfo():
            t = entry.target
            if (real == t or real.startswith(t.rstrip("/") + "/")) and len(t) >= len(best[0]):
                best = (t, entry.fstype)
        return best[1]

    def settle(self) -> None:
        if find_tool("udevadm"):
            try:
                self.runner.run("udevadm", ["settle", "--timeout=15"], timeout=30, check=False)
            except BlockingError:
                pass

    # -- environment / network / scanning
    def environment(self) -> Dict[str, Any]:
        os_release: Dict[str, str] = {}
        for line in _read_sys("/etc/os-release", 16384).splitlines():
            key, sep, value = line.partition("=")
            if sep and key in ("PRETTY_NAME", "ID", "VERSION_ID", "VERSION_CODENAME"):
                os_release[key] = display_text(value.strip().strip('"'), 120)
        cmdline = _read_sys("/proc/cmdline", 8192).split()
        markers = []
        for token in cmdline:
            if token in ("boot=live", "boot=casper", "boot=antiX", "toram"):
                markers.append("kernel command line: %s" % display_text(token, 40))
            elif token.startswith(("bdev=", "live-media=", "fromiso=", "archisobasedir=")):
                markers.append("kernel command line: %s=..." % display_text(token.split("=", 1)[0], 40))
        root_fstype = ""
        for entry in read_mountinfo():
            if entry.target == "/":
                root_fstype = entry.fstype
            if any(entry.target == p or entry.target.startswith(p + "/") for p in LIVE_MOUNT_PREFIXES):
                markers.append("live media mount: %s" % display_text(entry.target, 80))
        if root_fstype in ("overlay", "aufs", "squashfs", "tmpfs"):
            markers.append("root filesystem type: %s" % root_fstype)
        uname = os.uname()
        tools = {t: find_tool(t) is not None for t in (
            "lsblk", "udevadm", "mount", "umount", "blockdev", "rfkill", "ip", "nft", "clamscan", "sudo",
            "wipefs", "sfdisk", "mkfs.vfat")}
        return {
            "simulated": False,
            "os_release": os_release,
            "kernel": display_text(uname.release, 80),
            "machine": display_text(uname.machine, 40),
            "pid1": display_text(_read_sys("/proc/1/comm", 64), 40),
            "root_fstype": root_fstype,
            "live_detected": bool(markers),
            "live_markers": sorted(set(markers))[:12],
            "euid": os.geteuid(),
            "python": sys.version.split()[0],
            "python_isolated_mode": bool(sys.flags.isolated),
            "tools": tools,
        }

    def network_state(self) -> Dict[str, Any]:
        state: Dict[str, Any] = {"interfaces_up": [], "default_route": None, "rfkill": [], "known": False}
        if find_tool("ip"):
            try:
                links = json.loads(self.runner.run("ip", ["-j", "link", "show"], timeout=15).stdout or "[]")
                state["interfaces_up"] = sorted(
                    l["ifname"] for l in links
                    if isinstance(l, dict) and isinstance(l.get("ifname"), str) and l["ifname"] != "lo"
                    and "UP" in (l.get("flags") or []))
                routes = json.loads(self.runner.run("ip", ["-j", "route", "show", "default"], timeout=15).stdout or "[]")
                routes6 = json.loads(self.runner.run("ip", ["-j", "-6", "route", "show", "default"], timeout=15,
                                                     check=False).stdout or "[]")
                state["default_route"] = bool(routes) or bool(routes6)
                state["known"] = True
            except (BlockingError, ValueError, TypeError):
                pass
        if find_tool("rfkill"):
            try:
                data = json.loads(self.runner.run("rfkill", ["-J"], timeout=15).stdout or "{}")
                devices = next((v for v in data.values() if isinstance(v, list)), []) if isinstance(data, dict) else []
                state["rfkill"] = [{"id": d.get("id"), "type": display_text(d.get("type"), 20),
                                    "soft": d.get("soft"), "hard": d.get("hard")}
                                   for d in devices if isinstance(d, dict)]
            except (BlockingError, ValueError):
                pass
        return state

    def network_lockdown(self, save_path: Path, use_firewall: bool) -> Dict[str, Any]:
        before = self.network_state()
        record: Dict[str, Any] = {"created_at": utc_now(), "before": before, "actions": []}
        _write_private_json(save_path, record, exclusive=True)
        for dev in before["rfkill"]:
            if dev.get("soft") == "unblocked" and isinstance(dev.get("id"), int):
                res = self.runner.run("rfkill", ["block", str(dev["id"])], privileged=True, timeout=15, check=False)
                if res.returncode == 0:
                    record["actions"].append({"type": "rfkill_block", "id": dev["id"]})
                    _write_private_json(save_path, record)
        for ifname in before["interfaces_up"]:
            if not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", ifname):
                continue
            res = self.runner.run("ip", ["link", "set", "dev", ifname, "down"], privileged=True, timeout=15, check=False)
            if res.returncode == 0:
                record["actions"].append({"type": "link_down", "ifname": ifname})
                _write_private_json(save_path, record)
        if use_firewall:
            ruleset = (
                "table inet airlock_lockdown {\n"
                "  chain input { type filter hook input priority -300; policy drop; iif \"lo\" accept; }\n"
                "  chain output { type filter hook output priority -300; policy drop; oif \"lo\" accept; }\n"
                "  chain forward { type filter hook forward priority -300; policy drop; }\n"
                "}\n")
            res = self.runner.run("nft", ["-f", "-"], privileged=True, timeout=15, input_text=ruleset, check=False)
            if res.returncode == 0:
                record["actions"].append({"type": "nft_table", "name": "airlock_lockdown"})
                _write_private_json(save_path, record)
            else:
                record["firewall_error"] = display_text(res.stderr.strip(), 200)
                _write_private_json(save_path, record)
        record["after"] = self.network_state()
        _write_private_json(save_path, record)
        return record

    def network_restore(self, save_path: Path) -> Dict[str, Any]:
        record = _read_private_json(save_path)
        failures = []
        for action in reversed(record.get("actions", [])):
            kind = action.get("type")
            if kind == "nft_table":
                args = ["delete", "table", "inet", "airlock_lockdown"]
                res = self.runner.run("nft", args, privileged=True, timeout=15, check=False)
            elif kind == "link_down" and re.fullmatch(r"[A-Za-z0-9_.:@-]{1,15}", str(action.get("ifname"))):
                res = self.runner.run("ip", ["link", "set", "dev", action["ifname"], "up"], privileged=True, timeout=15, check=False)
            elif kind == "rfkill_block" and isinstance(action.get("id"), int):
                res = self.runner.run("rfkill", ["unblock", str(action["id"])], privileged=True, timeout=15, check=False)
            else:
                continue
            if res.returncode != 0:
                failures.append(action)
        return {"restored_actions": len(record.get("actions", [])) - len(failures), "failures": failures,
                "after": self.network_state()}

    def clamav_scan(self, paths: List[str]) -> Dict[str, Any]:
        if find_tool("clamscan") is None:
            return {"available": False}
        info: Dict[str, Any] = {"available": True}
        ver = self.runner.run("clamscan", ["--version"], timeout=120, check=False)
        first = ver.stdout.strip().splitlines()[0] if ver.stdout.strip() else ""
        m = re.match(r"ClamAV\s+([^/\s]+)(?:/(\d+)/(.+))?", first)
        info["version"] = display_text(m.group(1) if m else first, 60)
        info["database_version"] = display_text(m.group(2), 20) if m and m.group(2) else "unknown"
        info["database_date"] = display_text(m.group(3).strip(), 60) if m and m.group(3) else "unknown"
        res = self.runner.run("clamscan", ["--no-summary", "--stdout"] + list(paths), timeout=1800, check=False)
        info["exit_code"] = res.returncode
        results: Dict[str, str] = {}
        for line in res.stdout.splitlines():
            path, sep, verdict = line.rpartition(": ")
            if sep and path in paths:
                results[path] = "OK" if verdict.strip() == "OK" else display_text(verdict.strip(), 120)
        info["results"] = results
        if res.returncode not in (0, 1):
            info["error"] = display_text(res.stderr.strip(), 300)
        return info

    def prepare_fat32(self, disk: Disk, label: str) -> Partition:
        mkfs = "mkfs.vfat" if find_tool("mkfs.vfat") else "mkfs.fat"
        for tool in ("wipefs", "sfdisk", mkfs):
            if find_tool(tool) is None:
                raise ToolMissing(tool)
        for part in disk.partitions:
            if part.kname != disk.kname:
                self.check_node(part.kname, part.maj_min)
                self.runner.run("wipefs", ["-a", "--", "/dev/" + part.kname], privileged=True, timeout=120)
        self.check_node(disk.kname, disk.maj_min)
        self.runner.run("wipefs", ["-a", "--", "/dev/" + disk.kname], privileged=True, timeout=120)
        self.check_node(disk.kname, disk.maj_min)
        self.runner.run("sfdisk", ["--wipe", "always", "--wipe-partitions", "always", "--", "/dev/" + disk.kname],
                        privileged=True, timeout=120, input_text="label: dos\n,,c\n")
        self.settle()
        new_part = None
        for _ in range(30):
            for d in self.list_disks():
                if d.maj_min == disk.maj_min and d.serial == disk.serial and len(d.partitions) == 1 \
                        and d.partitions[0].kname != d.kname:
                    new_part = d.partitions[0]
            if new_part:
                break
            time.sleep(0.5)
        if new_part is None:
            raise BlockingError("PARTITION_NOT_FOUND", "new partition did not appear after partitioning")
        self.check_node(new_part.kname, new_part.maj_min)
        self.runner.run(mkfs, ["-F", "32", "-n", label, "--", "/dev/" + new_part.kname], privileged=True, timeout=600)
        self.settle()
        return new_part


def _write_private_json(path: Path, data: Any, exclusive: bool = False) -> None:
    payload = (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        return
    directory = os.path.dirname(str(path))
    tmp = os.path.join(directory, ".%s.%s.tmp" % (os.path.basename(str(path)), secrets.token_hex(6)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        write_all(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _read_private_json(path: Path, limit: int = 32 * 1024 * 1024) -> Any:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_size > limit:
            raise BlockingError("STATE_INVALID", "%s is not a valid private state file" % path)
        raw = read_bounded(fd, limit + 1)
    finally:
        os.close(fd)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise BlockingError("STATE_INVALID", "%s is corrupt: %s" % (path, exc))


# ---------------------------------------------------------------------------
# Simulated backend (tests and operator practice; touches no real device)
# ---------------------------------------------------------------------------

class SimulatedBackend:
    simulated = True

    def __init__(self) -> None:
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.mounted: Dict[str, Dict[str, Any]] = {}
        self.readonly: Set[str] = set()
        self.readonly_supported = True
        self.live_detected = True
        self.net: Dict[str, Any] = {"interfaces_up": [], "default_route": False, "rfkill": [], "known": True}
        self.clamav_result: Any = None
        self.calls: List[Tuple[str, Any]] = []
        self.auto: Optional[Callable[["SimulatedBackend", str], None]] = None

    def add_device(self, disk: Disk, roots: Dict[str, Path], protected: Optional[str] = None,
                   automount: Optional[str] = None) -> None:
        self.devices[disk.kname] = {"disk": disk, "roots": {k: Path(v) for k, v in roots.items()},
                                    "protected": protected}
        if automount:
            for part in disk.partitions:
                opts = [automount, "nosuid", "nodev", "relatime"]
                self.mounted[part.kname] = {"target": "/media/sim/%s" % part.kname, "ro": automount == "ro",
                                            "options": opts, "automount": True}

    def remove_device(self, kname: str) -> None:
        dev = self.devices.pop(kname, None)
        if dev:
            for part in dev["disk"].partitions:
                self.mounted.pop(part.kname, None)

    def notify(self, event: str, **details: Any) -> None:
        self.calls.append(("notify", event))
        if self.auto:
            self.auto(self, event)

    def ensure_privilege(self, console: Console) -> None:
        self.calls.append(("ensure_privilege", None))

    def list_disks(self) -> List[Disk]:
        return [copy.deepcopy(d["disk"]) for d in self.devices.values()]

    def protected_disks(self) -> Dict[str, str]:
        return {k: d["protected"] for k, d in self.devices.items() if d["protected"]}

    def live_media_uuid_hints(self) -> List[str]:
        return []

    def _locate(self, kname: str) -> Tuple[Optional[Dict[str, Any]], Optional[Any]]:
        for dev in self.devices.values():
            if dev["disk"].kname == kname:
                return dev, dev["disk"]
            for part in dev["disk"].partitions:
                if part.kname == kname:
                    return dev, part
        return None, None

    def check_node(self, kname: str, maj_min: str) -> None:
        _dev, obj = self._locate(kname)
        if obj is None:
            raise BlockingError("DEVICE_DISAPPEARED", "/dev/%s no longer exists" % kname)
        if obj.maj_min != maj_min:
            raise BlockingError("IDENTITY_CHANGED", "/dev/%s no longer refers to device %s" % (kname, maj_min))

    def mounts_of(self, part: Partition) -> List[MountEntry]:
        m = self.mounted.get(part.kname)
        if not m:
            return []
        return [MountEntry(m["target"], part.maj_min, part.fstype, "/dev/" + part.kname,
                           frozenset(m["options"]), frozenset())]

    def unmount_partition(self, part: Partition, target: Optional[Path] = None) -> None:
        self.calls.append(("unmount", part.kname))
        self.mounted.pop(part.kname, None)

    def set_readonly(self, disk: Disk) -> Tuple[bool, Dict[str, Any]]:
        self.calls.append(("set_readonly", disk.kname))
        if not self.readonly_supported:
            return False, {disk.kname: {"verified": False}}
        self.readonly.add(disk.kname)
        return True, {disk.kname: {"verified": True}}

    def mount(self, part: Partition, fstype: str, target: Path, options: str) -> Path:
        self.check_node(part.kname, part.maj_min)
        dev, _obj = self._locate(part.kname)
        if part.kname in self.mounted:
            raise BlockingError("MOUNT_FAILED", "partition already mounted")
        opts = options.split(",")
        self.mounted[part.kname] = {"target": str(target), "ro": "ro" in opts,
                                    "options": opts, "automount": False}
        self.calls.append(("mount", (part.kname, fstype, options)))
        return dev["roots"][part.kname]

    def verify_mount(self, part: Partition, root: Path, expect_ro: bool) -> Dict[str, Any]:
        m = self.mounted.get(part.kname)
        if not m or not os.path.isdir(str(root)):
            raise BlockingError("FILESYSTEM_DISAPPEARED", "filesystem is no longer mounted")
        if m["ro"] != expect_ro:
            raise BlockingError("MOUNT_OPTIONS_NOT_ENFORCED", "mount read-only state is not as expected")
        missing = {"nodev", "nosuid", "noexec"} - set(m["options"])
        if missing:
            raise BlockingError("MOUNT_OPTIONS_NOT_ENFORCED", "missing options: %s" % ",".join(sorted(missing)))
        return {"target": str(root), "fstype": part.fstype, "options": sorted(m["options"]), "simulated": True}

    def expected_root_dev(self, part: Partition) -> Optional[int]:
        return None

    def flush_buffers(self, part: Partition) -> None:
        pass

    def is_mounted_at(self, target: Path) -> bool:
        return False

    def path_on_devices(self, path: str, knames: Iterable[str]) -> bool:
        real = os.path.realpath(path)
        for kname in knames:
            dev = self.devices.get(kname)
            if not dev:
                continue
            for root in dev["roots"].values():
                r = os.path.realpath(str(root))
                if real == r or real.startswith(r + os.sep):
                    return True
        return False

    def filesystem_type_of(self, path: Path) -> str:
        return "simulated"

    def settle(self) -> None:
        pass

    def environment(self) -> Dict[str, Any]:
        return {"simulated": True, "os_release": {"PRETTY_NAME": "simulation"}, "kernel": os.uname().release,
                "machine": os.uname().machine, "pid1": "simulation", "root_fstype": "simulated",
                "live_detected": self.live_detected,
                "live_markers": ["simulation scenario"] if self.live_detected else [],
                "euid": os.geteuid(), "python": sys.version.split()[0],
                "python_isolated_mode": bool(sys.flags.isolated), "tools": {}}

    def network_state(self) -> Dict[str, Any]:
        return copy.deepcopy(self.net)

    def network_lockdown(self, save_path: Path, use_firewall: bool) -> Dict[str, Any]:
        record = {"created_at": utc_now(), "before": self.network_state(),
                  "actions": [{"type": "link_down", "ifname": i} for i in self.net["interfaces_up"]]}
        _write_private_json(save_path, record, exclusive=True)
        self.net["interfaces_up"] = []
        self.net["default_route"] = False
        record["after"] = self.network_state()
        _write_private_json(save_path, record)
        return record

    def network_restore(self, save_path: Path) -> Dict[str, Any]:
        record = _read_private_json(save_path)
        self.net = copy.deepcopy(record["before"])
        return {"restored_actions": len(record.get("actions", [])), "failures": [], "after": self.network_state()}

    def clamav_scan(self, paths: List[str]) -> Dict[str, Any]:
        if callable(self.clamav_result):
            return self.clamav_result(paths)
        return self.clamav_result or {"available": False}

    def prepare_fat32(self, disk: Disk, label: str) -> Partition:
        dev = self.devices[disk.kname]
        old_roots = list(dev["roots"].values())
        root = old_roots[0]
        for entry in os.listdir(root):
            path = os.path.join(str(root), entry)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
        major = disk.maj_min.split(":")[0]
        minor = int(disk.maj_min.split(":")[1]) + 1
        part = Partition(kname=disk.kname + "1", maj_min="%s:%d" % (major, minor), size=disk.size,
                         fstype="vfat", uuid=secrets.token_hex(2).upper() + "-" + secrets.token_hex(2).upper(),
                         label=label)
        dev["disk"].partitions = [part]
        dev["disk"].whole_disk_fs = False
        dev["roots"] = {part.kname: root}
        return part


def sim_disk(kname: str, maj: int, serial: str, model: str = "SimStick", vendor: str = "SimVendor",
             size: int = 8 * 1024 ** 3, fstype: str = "vfat", uuid: str = "", tran: str = "usb",
             removable: bool = True, label: str = "") -> Disk:
    if not uuid:
        digest = hashlib.sha256(("%s|%s|%s" % (kname, serial, model)).encode("utf-8")).hexdigest().upper()
        uuid = digest[:4] + "-" + digest[4:8]
    part = Partition(kname=kname + "1", maj_min="%d:1" % maj, size=size, fstype=fstype, uuid=uuid, label=label)
    by_id = ["usb-%s_%s_%s-0:0" % (vendor, model, serial)] if serial and tran == "usb" else []
    return Disk(kname=kname, maj_min="%d:0" % maj, size=size, tran=tran, removable=removable,
                hotplug=removable, model=model, vendor=vendor, serial=serial, by_id=by_id, partitions=[part])


def load_simulation_scenario(path: str, source_removed: bool) -> SimulatedBackend:
    """Build a simulated backend from an inert JSON scenario (see TESTING.md)."""
    data = _read_scenario(path)
    backend = SimulatedBackend()
    backend.live_detected = bool(data.get("live_detected", True))
    pending: Dict[str, Tuple[Disk, Dict[str, Path], Optional[str]]] = {}
    for index, spec in enumerate(data.get("devices", [])):
        if not isinstance(spec, dict):
            raise ConfigError("scenario device entries must be objects")
        role = spec.get("role")
        root = Path(str(spec.get("root", ""))).expanduser()
        if not root.is_absolute():
            root = (Path(path).resolve().parent / root)
        if not root.is_dir():
            raise ConfigError("scenario root directory does not exist: %s" % display_text(root))
        disk = sim_disk(kname=str(spec.get("kname", "sd%s" % "abcdefgh"[index % 8])), maj=8 + index,
                        serial=str(spec.get("serial", "")), model=str(spec.get("model", "SimStick")),
                        vendor=str(spec.get("vendor", "SimVendor")), size=int(spec.get("size", 8 * 1024 ** 3)),
                        fstype=str(spec.get("fstype", "vfat")), tran=str(spec.get("tran", "usb")),
                        removable=role not in ("system",))
        roots = {disk.partitions[0].kname: root}
        protected = {"system": "SYSTEM DISK (simulated)", "live": "LIVE BOOT DEVICE (simulated)"}.get(str(role))
        if role in ("system", "live"):
            backend.add_device(disk, roots, protected=protected)
        elif role == "source":
            if not source_removed:
                backend.add_device(disk, roots, automount=spec.get("automount"))
            pending["source"] = (disk, roots, None)
        elif role == "destination":
            pending["destination"] = (disk, roots, None)
        else:
            raise ConfigError("scenario role must be system, live, source or destination")

    def auto(be: SimulatedBackend, event: str) -> None:
        if event == "await_source_removal" and "source" in pending:
            be.remove_device(pending["source"][0].kname)
        elif event == "await_destination_insertion" and "destination" in pending:
            disk, roots, _ = pending["destination"]
            if disk.kname not in be.devices:
                be.add_device(copy.deepcopy(disk), roots)

    backend.auto = auto
    return backend


def _read_scenario(path: str) -> Dict[str, Any]:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(1024 * 1024)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ConfigError("cannot read simulation scenario: %s" % exc)
    if not isinstance(data, dict):
        raise ConfigError("scenario must be a JSON object")
    return data


# ---------------------------------------------------------------------------
# State store and sessions
# ---------------------------------------------------------------------------

class StateStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    @staticmethod
    def default_root(simulated: bool = False) -> Path:
        suffix = "-simulation" if simulated else ""
        xdg = os.environ.get("XDG_RUNTIME_DIR", "")
        if xdg and os.path.isabs(xdg):
            try:
                st = os.lstat(xdg)
                if stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077:
                    return Path(xdg) / (APP_NAME + suffix)
            except OSError:
                pass
        if os.path.isdir("/dev/shm"):
            return Path("/dev/shm") / ("%s-%d%s" % (APP_NAME, os.geteuid(), suffix))
        return Path(tempfile.gettempdir()) / ("%s-%d%s" % (APP_NAME, os.geteuid(), suffix))

    def ensure(self) -> None:
        ensure_private_dir(self.root)
        for sub in ("quarantine", "mnt", "logs", "reports", "archive"):
            ensure_private_dir(self.root / sub)
        for sub in ("source", "dest"):
            ensure_private_dir(self.root / "mnt" / sub)

    @property
    def session_path(self) -> Path:
        return self.root / "session.json"

    @property
    def lockdown_path(self) -> Path:
        return self.root / "network_lockdown.json"

    def mountpoint(self, role: str) -> Path:
        return self.root / "mnt" / role

    def load_session(self) -> Optional[Dict[str, Any]]:
        try:
            os.lstat(self.session_path)
        except FileNotFoundError:
            return None
        session = _read_private_json(self.session_path)
        if not isinstance(session, dict) or session.get("schema") != SESSION_SCHEMA \
                or not RUN_ID_RE.match(str(session.get("run_id", ""))):
            raise BlockingError("STATE_INVALID", "session file is not a valid airlock session")
        return session

    def save_session(self, session: Dict[str, Any]) -> None:
        session["updated_at"] = utc_now()
        _write_private_json(self.session_path, session)

    def quarantine_dir(self, run_id: str) -> Path:
        if not RUN_ID_RE.match(run_id):
            raise BlockingError("STATE_INVALID", "invalid run id")
        return self.root / "quarantine" / run_id

    def wipe_quarantine(self, run_id: str) -> None:
        qdir = self.quarantine_dir(run_id)
        try:
            qfd = open_dir_nofollow(qdir)
        except FileNotFoundError:
            return
        try:
            for name in os.listdir(qfd):
                st = os.stat(name, dir_fd=qfd, follow_symlinks=False)
                if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                    os.unlink(name, dir_fd=qfd)
        finally:
            os.close(qfd)
        os.rmdir(qdir)

    def archive_session(self, session: Dict[str, Any]) -> None:
        _write_private_json(self.root / "archive" / ("%s.json" % session["run_id"]), session)
        self.wipe_quarantine(session["run_id"])
        os.unlink(self.session_path)


def add_warning(session: Dict[str, Any], code: str, message: str) -> None:
    session.setdefault("warnings", []).append({"ts": utc_now(), "code": code, "message": message})


def add_blocking(session: Dict[str, Any], code: str, message: str) -> None:
    session.setdefault("blocking", []).append({"ts": utc_now(), "code": code, "message": message})


# ---------------------------------------------------------------------------
# Application context
# ---------------------------------------------------------------------------

class Context:
    def __init__(self, console: Console, backend: Any, config: Dict[str, Any], store: StateStore,
                 args: argparse.Namespace, operator_live_knames: Optional[Set[str]] = None):
        self.console = console
        self.backend = backend
        self.config = config
        self.store = store
        self.args = args
        self.operator_live_knames = operator_live_knames or set()
        self.log: Any = NullLog()
        self.invocation = secrets.token_hex(4)
        self.uid = os.getuid()
        self.gid = os.getgid()

    def attach_log(self, run_id: Optional[str]) -> None:
        self.log.close()
        name = ("%s.log" % run_id) if run_id else "no-session.log"
        self.log = RunLog(self.store.root / "logs" / name, self.invocation)
        if isinstance(self.backend, LinuxBackend):
            self.backend.runner.log = self.log

    def arg(self, name: str, default: Any = None) -> Any:
        return getattr(self.args, name, default)


# ---------------------------------------------------------------------------
# Device policy
# ---------------------------------------------------------------------------

def enumerate_devices(ctx: Context) -> Tuple[List[Disk], Dict[str, str]]:
    disks = ctx.backend.list_disks()
    protected = dict(ctx.backend.protected_disks())
    for uuid in ctx.backend.live_media_uuid_hints():
        for disk in disks:
            if any(p.uuid and p.uuid.lower() == uuid.lower() for p in disk.partitions):
                protected.setdefault(disk.kname, "BOOT/LIVE DEVICE (named on kernel command line)")
    for kname in ctx.operator_live_knames:
        protected.setdefault(kname, "LIVE BOOT DEVICE (declared with --live-device)")
    # A disk mounted anywhere other than a desktop automount location or this
    # tool's own mount points is in use by the system (for example undetected
    # live media) and is never offered.
    own = os.path.realpath(str(ctx.store.root))
    for disk in disks:
        if disk.kname in protected:
            continue
        for part in disk.partitions:
            for m in ctx.backend.mounts_of(part):
                t = m.target
                if t.startswith(("/media/", "/run/media/")) or t == own or t.startswith(own + "/"):
                    continue
                protected.setdefault(disk.kname, "IN USE (mounted at %s)" % display_text(t, 80))
    return disks, protected


def removable_disks(disks: List[Disk], protected: Dict[str, str]) -> List[Disk]:
    return [d for d in disks if d.kname not in protected and d.size > 0
            and (d.removable or d.hotplug or d.tran == "usb")]


def matches_fingerprint(fp: Dict[str, Any], disk: Disk) -> bool:
    """True when disk could be the device described by fp (conservative: ambiguity counts as a match)."""
    if fp.get("serial") and disk.serial and fp["serial"] == disk.serial:
        return True
    if set(fp.get("by_id") or []) & set(disk.by_id):
        return True
    uuids = set(fp.get("fs_uuids") or [])
    if uuids and any(p.uuid and p.uuid in uuids for p in disk.partitions):
        return True
    if (not fp.get("serial") or not disk.serial) and fp.get("model") == disk.model \
            and fp.get("vendor") == disk.vendor and fp.get("size") == disk.size:
        return True
    return False


def revalidate(ctx: Context, expected: Dict[str, Any], part_kname: Optional[str] = None,
               part_expected: Optional[Dict[str, Any]] = None) -> Tuple[Disk, Optional[Partition]]:
    """Re-read device state and fail closed unless it is exactly the confirmed device."""
    disks, protected = enumerate_devices(ctx)
    found = [d for d in disks if d.kname == expected["kname"]]
    if not found:
        raise BlockingError("DEVICE_DISAPPEARED", "the confirmed device is no longer present")
    disk = found[0]
    for key in ("maj_min", "size", "model", "vendor", "serial"):
        if getattr(disk, key) != expected.get(key):
            raise BlockingError("IDENTITY_CHANGED", "device %s changed (%s) since it was confirmed" % (disk.kname, key))
    if sorted(disk.by_id) != sorted(expected.get("by_id") or []):
        raise BlockingError("IDENTITY_CHANGED", "device %s by-id links changed since it was confirmed" % disk.kname)
    if disk.kname in protected:
        raise BlockingError("PROTECTED_DEVICE", "device %s is now classified as %s" % (disk.kname, protected[disk.kname]))
    ctx.backend.check_node(disk.kname, disk.maj_min)
    part = None
    if part_kname:
        part = disk.partition(part_kname)
        if part is None:
            raise BlockingError("IDENTITY_CHANGED", "partition %s disappeared" % part_kname)
        if part_expected:
            for key in ("maj_min", "fstype", "uuid", "size"):
                if getattr(part, key) != part_expected.get(key):
                    raise BlockingError("IDENTITY_CHANGED", "partition %s changed (%s)" % (part_kname, key))
        ctx.backend.check_node(part.kname, part.maj_min)
    return disk, part


def show_identity(console: Console, role: str, disk: Disk, part: Optional[Partition] = None,
                  mountpoint: str = "(not mounted)") -> None:
    by_id = disk.preferred_by_id()
    rows = [
        ("DEVICE ROLE", role),
        ("MODEL", display_text(disk.model) or "(none reported)"),
        ("VENDOR", display_text(disk.vendor) or "(none reported)"),
        ("SERIAL", display_text(disk.serial) or "(NONE REPORTED)"),
        ("SIZE", "%s (%d bytes)" % (human_size(disk.size), disk.size)),
        ("BY-ID PATH", ("/dev/disk/by-id/" + display_text(by_id)) if by_id else "(none)"),
        ("TRANSPORT", display_text(disk.tran) or "(unknown)"),
        ("REMOVABLE", "rm=%d hotplug=%d" % (int(disk.removable), int(disk.hotplug))),
        ("KERNEL NAME", "/dev/%s (informational only; can change)" % disk.kname),
    ]
    if part is not None:
        rows += [
            ("PARTITION", "/dev/%s" % part.kname),
            ("FILESYSTEM", display_text(part.fstype) or "(none detected)"),
            ("FS UUID", display_text(part.uuid) or "(none)"),
            ("LABEL", (display_text(part.label) or "(none)") + "  [untrusted, informational]"),
            ("MOUNTPOINT", mountpoint),
        ]
    else:
        fs = ", ".join("%s:%s" % (p.kname, display_text(p.fstype) or "-") for p in disk.partitions) or "(none)"
        rows += [("FILESYSTEM", fs), ("MOUNTPOINT", mountpoint)]
    console.line("-" * 70)
    for key, value in rows:
        console.line("  %-12s : %s" % (key, value))
    console.line("-" * 70)


def serial_tail(disk: Disk) -> str:
    alnum = re.sub(r"[^A-Za-z0-9]", "", disk.serial if disk.serial.isascii() else "")
    if len(alnum) < 4:
        raise BlockingError("IDENTITY_UNCERTAIN",
                            "the destination does not report a usable serial number, so it cannot be identified "
                            "confidently; use a USB drive that reports a serial number")
    return alnum[-4:].upper()


def choose_partition(ctx: Context, disk: Disk, supported: Sequence[str], purpose: str) -> Partition:
    candidates = [p for p in disk.partitions if p.fstype in supported]
    if not candidates:
        found = ", ".join(display_text(p.fstype) or "none" for p in disk.partitions) or "no filesystems"
        raise BlockingError("UNSUPPORTED_FILESYSTEM",
                            "no supported filesystem for %s on this device (found: %s; supported: %s)"
                            % (purpose, found, ", ".join(supported)))
    if len(candidates) == 1:
        return candidates[0]
    ctx.console.line("Multiple usable partitions found:")
    for index, part in enumerate(candidates, 1):
        ctx.console.line("  %d) /dev/%s  %s  %s  UUID %s  label %s" % (
            index, part.kname, display_text(part.fstype), human_size(part.size),
            display_text(part.uuid), display_text(part.label)))
    answer = ctx.console.ask("Select partition number for %s (q to cancel): " % purpose)
    if answer.lower() in ("q", "quit"):
        raise OperatorCancelled("operator cancelled partition selection")
    if not answer.isdigit() or not 1 <= int(answer) <= len(candidates):
        raise BlockingError("AMBIGUOUS_SELECTION", "invalid partition selection")
    return candidates[int(answer) - 1]


def handle_existing_mounts(ctx: Context, session: Optional[Dict[str, Any]], disk: Disk, role: str) -> List[Dict[str, Any]]:
    """Detect (auto)mounts of the selected device, record them, and unmount."""
    c = ctx.console
    events = []
    mounted_parts = []
    for part in disk.partitions:
        mounts = ctx.backend.mounts_of(part)
        if mounts:
            mounted_parts.append(part)
        for m in mounts:
            events.append({"partition": part.kname, "target": display_text(m.target), "fstype": m.fstype,
                           "options": sorted(m.options), "read_write": "rw" in m.options,
                           "desktop_location": m.target.startswith(("/media/", "/run/media/"))})
    if not events:
        return events
    any_rw = any(e["read_write"] for e in events)
    for e in events:
        c.warn("Device was already mounted: /dev/%s at %s (%s)" % (e["partition"], e["target"], "read-write" if e["read_write"] else "read-only"))
    if role == "source" and any_rw:
        c.blocking("DIRTY SOURCE WAS MOUNTED READ-WRITE (probably desktop automount). Normal processing stopped.")
    ctx.backend.ensure_privilege(c)
    for part in mounted_parts:
        ctx.backend.unmount_partition(part)
    for part in mounted_parts:
        if ctx.backend.mounts_of(part):
            raise BlockingError("UNMOUNT_FAILED", "could not unmount /dev/%s" % part.kname)
    c.passed("Existing mounts removed.")
    c.warn("Desktop automount should ideally be disabled before future transfers (see RECOVERY.md). "
           "No desktop settings were changed.")
    ctx.log.event("automount_detected", role=role, events=events)
    if session is not None:
        add_warning(session, "AUTOMOUNT_DETECTED", "%s device was mounted before processing (%s)"
                    % (role, "read-write" if any_rw else "read-only"))
    if role == "source" and any_rw:
        if session is not None:
            add_warning(session, "SOURCE_WAS_MOUNTED_RW",
                        "dirty source was mounted read-write before ingest; contents may have changed and remain untrusted")
            ctx.store.save_session(session)
        c.confirm_phrase("CONTINUE",
                         "The dirty filesystem was writable while mounted and may have been modified. It is now "
                         "unmounted and its contents remain fully untrusted.")
    return events


# ---------------------------------------------------------------------------
# Source scanning
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    accepted: List[Dict[str, Any]] = field(default_factory=list)
    rejected: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    entries_examined: int = 0
    total_bytes: int = 0
    limit_reached: bool = False


class _Scanner:
    def __init__(self, config: Dict[str, Any], root_dev: int, on_entry: Optional[Callable[[], None]]):
        self.config = config
        self.root_dev = root_dev
        self.on_entry = on_entry
        self.result = ScanResult()
        self.allowed = set(config["allowed_extensions"])

    def reject(self, rel_parts: List[str], reasons: List[str], size: Optional[int] = None, kind: str = "file") -> None:
        self.result.rejected.append({
            "kind": kind,
            "relative_path_display": "/".join(display_text(p, 120) for p in rel_parts),
            "original_name": rel_parts[-1],
            "reasons": reasons,
            "size": size,
        })

    def scan_dir(self, dfd: int, rel_parts: List[str], depth: int) -> None:
        try:
            with os.scandir(dfd) as iterator:
                names = sorted(entry.name for entry in iterator)
        except OSError as exc:
            raise BlockingError("SOURCE_READ_ERROR", "cannot list source directory: %s" % exc.strerror)
        for name in names:
            if self.result.limit_reached:
                return
            self.result.entries_examined += 1
            if self.result.entries_examined > self.config["max_scan_entries"]:
                self.result.limit_reached = True
                self.result.warnings.append("scan limit of %d entries reached; remaining entries were not examined "
                                            "and stay behind" % self.config["max_scan_entries"])
                return
            if self.on_entry:
                self.on_entry()
            if name in (".", "..") or "/" in name or "\x00" in name:
                raise BlockingError("PATH_TRAVERSAL", "filesystem returned an impossible entry name (%s)" % display_text(name))
            parts = rel_parts + [name]
            try:
                st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError as exc:
                raise BlockingError("SOURCE_READ_ERROR", "cannot stat %s: %s"
                                    % ("/".join(display_text(p) for p in parts), exc.strerror))
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                self.reject(parts, ["SYMLINK_NOT_FOLLOWED"], kind="symlink")
                continue
            if stat.S_ISDIR(mode):
                self.handle_dir(dfd, name, parts, st, depth)
                continue
            if not stat.S_ISREG(mode):
                kind = ("device node" if stat.S_ISBLK(mode) or stat.S_ISCHR(mode) else
                        "fifo" if stat.S_ISFIFO(mode) else "socket" if stat.S_ISSOCK(mode) else "special file")
                raise BlockingError("UNSUPPORTED_SPECIAL_FILE", "source contains a %s: %s"
                                    % (kind, "/".join(display_text(p) for p in parts)))
            self.handle_file(dfd, name, parts, st)

    def handle_dir(self, dfd: int, name: str, parts: List[str], st: os.stat_result, depth: int) -> None:
        lower = name.lower()
        if name.startswith(".") or lower in SKIP_DIR_NAMES or lower.startswith(".trash"):
            self.reject(parts, ["HIDDEN_OR_SYSTEM_DIRECTORY_SKIPPED"], kind="directory")
            return
        reasons = check_name_component(name, self.config["max_name_length"], self.config["allow_non_ascii_names"])
        if reasons:
            self.reject(parts, ["UNSAFE_DIRECTORY_NAME"] + reasons, kind="directory")
            return
        if st.st_dev != self.root_dev:
            raise BlockingError("MOUNT_BOUNDARY", "source tree crosses a filesystem boundary at %s"
                                % "/".join(display_text(p) for p in parts))
        if depth + 1 > self.config["max_depth"]:
            self.reject(parts, ["MAX_DEPTH_EXCEEDED"], kind="directory")
            return
        try:
            sub = open_dir_nofollow(name, dir_fd=dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                self.reject(parts, ["SYMLINK_NOT_FOLLOWED"], kind="symlink")
                return
            if exc.errno == errno.EACCES:
                self.reject(parts, ["PERMISSION_DENIED"], kind="directory")
                return
            raise BlockingError("SOURCE_READ_ERROR", "cannot open directory: %s" % exc.strerror)
        try:
            fst = os.fstat(sub)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                raise BlockingError("SOURCE_CHANGED_DURING_SCAN", "directory changed while being opened")
            self.scan_dir(sub, parts, depth + 1)
        finally:
            os.close(sub)

    def handle_file(self, dfd: int, name: str, parts: List[str], st: os.stat_result) -> None:
        cfg = self.config
        reasons: List[str] = []
        lower = name.lower()
        if name.startswith("."):
            reasons.append("HIDDEN_FILE")
        if lower in SYSTEM_METADATA_FILES:
            reasons.append("SYSTEM_METADATA_FILE")
        reasons += check_name_component(name, cfg["max_name_length"], cfg["allow_non_ascii_names"])
        reasons += check_extension(name, self.allowed)
        if reasons:
            self.reject(parts, reasons, st.st_size)
            return
        if len(self.result.accepted) >= cfg["max_files"]:
            self.reject(parts, ["MAX_FILES_EXCEEDED"], st.st_size)
            return
        if st.st_size > cfg["max_file_bytes"]:
            self.reject(parts, ["TOO_LARGE"], st.st_size)
            return
        if self.result.total_bytes + st.st_size > cfg["max_total_bytes"]:
            self.reject(parts, ["TOTAL_SIZE_LIMIT_EXCEEDED"], st.st_size)
            return
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
        try:
            fd = os.open(name, flags, dir_fd=dfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                self.reject(parts, ["SYMLINK_NOT_FOLLOWED"], kind="symlink")
                return
            if exc.errno == errno.EACCES:
                self.reject(parts, ["PERMISSION_DENIED"], st.st_size)
                return
            raise BlockingError("SOURCE_READ_ERROR", "cannot open %s: %s"
                                % ("/".join(display_text(p) for p in parts), exc.strerror))
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                raise BlockingError("SOURCE_CHANGED_DURING_SCAN", "file changed while being opened: %s"
                                    % "/".join(display_text(p) for p in parts))
            if fst.st_dev != self.root_dev:
                raise BlockingError("MOUNT_BOUNDARY", "file is on a different filesystem")
            data = read_bounded(fd, cfg["max_file_bytes"] + 1)
        except OSError as exc:
            raise BlockingError("SOURCE_READ_ERROR", "read error on %s: %s"
                                % ("/".join(display_text(p) for p in parts), exc.strerror))
        finally:
            os.close(fd)
        if len(data) > cfg["max_file_bytes"]:
            self.reject(parts, ["TOO_LARGE"], len(data))
            return
        if len(data) != fst.st_size:
            self.reject(parts, ["SIZE_CHANGED_DURING_READ"], len(data))
            self.result.warnings.append("file size changed while reading: %s" % "/".join(display_text(p) for p in parts))
            return
        rejects, review_flags, encoding = inspect_content(name, data)
        if rejects:
            self.reject(parts, rejects, len(data))
            return
        if fst.st_nlink > 1:
            review_flags.append(make_flag("MULTIPLE_HARD_LINKS", SEV_INFO, "source file has %d hard links (not preserved)" % fst.st_nlink))
        if fst.st_mode & (stat.S_ISUID | stat.S_ISGID):
            review_flags.append(make_flag("SETUID_SETGID_ON_SOURCE", SEV_INFO, "setuid/setgid bit on source (not preserved)"))
        record = {
            "original_name": name,
            "sanitized_display_name": display_text(name, 160),
            "relative_path": "/".join(parts),
            "relative_path_display": "/".join(display_text(p, 120) for p in parts),
            "size": len(data),
            "sha256": sha256_hex(data),
            "sha512": sha512_hex(data) if cfg["compute_sha512"] else None,
            "encoding": encoding,
            "review_flags": review_flags,
            "_data": data,
        }
        self.result.accepted.append(record)
        self.result.total_bytes += len(data)


def scan_source_tree(root: Path, config: Dict[str, Any], expected_dev: Optional[int] = None,
                     on_entry: Optional[Callable[[], None]] = None) -> ScanResult:
    try:
        root_fd = open_dir_nofollow(str(root))
    except OSError as exc:
        raise BlockingError("FILESYSTEM_DISAPPEARED", "cannot open source root: %s" % exc.strerror)
    try:
        st = os.fstat(root_fd)
        if expected_dev is not None and st.st_dev != expected_dev:
            raise BlockingError("MOUNT_SOURCE_MISMATCH", "source root is not on the selected device")
        scanner = _Scanner(config, st.st_dev, on_entry)
        scanner.scan_dir(root_fd, [], 0)
    finally:
        os.close(root_fd)
    result = scanner.result
    _reject_collisions(result)
    return result


def _reject_collisions(result: ScanResult) -> None:
    """Reject names that collide on case-insensitive targets (FAT, NTFS, Windows)."""
    keys: Dict[str, List[int]] = {}
    for index, rec in enumerate(result.accepted):
        keys.setdefault(unicodedata.normalize("NFC", rec["relative_path"]).casefold(), []).append(index)
    prefixes: Set[str] = set()
    for key in keys:
        parts = key.split("/")
        for i in range(1, len(parts)):
            prefixes.add("/".join(parts[:i]))
    bad: Set[int] = set()
    for key, indexes in keys.items():
        if len(indexes) > 1 or key in prefixes:
            bad.update(indexes)
    if not bad:
        return
    keep = []
    for index, rec in enumerate(result.accepted):
        if index in bad:
            result.rejected.append({"kind": "file", "relative_path_display": rec["relative_path_display"],
                                    "original_name": rec["original_name"], "reasons": ["NAME_COLLISION"],
                                    "size": rec["size"]})
            result.total_bytes -= rec["size"]
        else:
            keep.append(rec)
    result.accepted = keep


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def write_quarantine(qdir: Path, records: List[Dict[str, Any]]) -> None:
    """Store accepted files as new 0600 regular files under opaque names."""
    qfd = open_dir_nofollow(str(qdir))
    try:
        st = os.fstat(qfd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise BlockingError("QUARANTINE_INVALID", "quarantine directory is not private")
        real_root = os.path.realpath(str(qdir))
        for index, rec in enumerate(records, 1):
            qname = "f%06d.dat" % index
            fd = os.open(qname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=qfd)
            try:
                write_all(fd, rec["_data"])
                os.fsync(fd)
            finally:
                os.close(fd)
            if os.path.dirname(os.path.realpath(os.path.join(real_root, qname))) != real_root:
                raise BlockingError("PATH_TRAVERSAL", "quarantine path escaped its root")
            rec["quarantine_name"] = qname
        fsync_quiet(qfd)
    finally:
        os.close(qfd)


def read_quarantine_file(qdir: Path, rec: Dict[str, Any], expected_sha256: str) -> bytes:
    qname = rec.get("quarantine_name", "")
    if not re.fullmatch(r"f\d{6}\.dat", qname):
        raise BlockingError("QUARANTINE_TAMPERED", "invalid quarantine name in session")
    try:
        qfd = open_dir_nofollow(str(qdir))
    except OSError as exc:
        raise BlockingError("QUARANTINE_TAMPERED", "quarantine directory unavailable: %s" % exc.strerror)
    try:
        try:
            fd = os.open(qname, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=qfd)
        except OSError as exc:
            raise BlockingError("QUARANTINE_TAMPERED", "cannot open quarantined %s: %s"
                                % (rec.get("relative_path_display"), exc.strerror))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != rec["size"]:
                raise BlockingError("QUARANTINE_TAMPERED", "quarantined %s is no longer the stored regular file"
                                    % rec.get("relative_path_display"))
            data = read_bounded(fd, rec["size"] + 1)
        finally:
            os.close(fd)
    finally:
        os.close(qfd)
    if len(data) != rec["size"] or sha256_hex(data) != expected_sha256:
        raise BlockingError("QUARANTINE_TAMPERED", "quarantined %s no longer matches its recorded SHA-256"
                            % rec.get("relative_path_display"))
    return data


# ---------------------------------------------------------------------------
# Trusted hashes (operator-supplied, never from the dirty USB)
# ---------------------------------------------------------------------------

HASH_LINE_RE = re.compile(r"^([0-9A-Fa-f]{64})(?:\s+\*?(.+?))?\s*$")
BSD_HASH_LINE_RE = re.compile(r"^SHA256\s*\((.+)\)\s*=\s*([0-9A-Fa-f]{64})\s*$")


@dataclass
class HashList:
    named: Dict[str, str] = field(default_factory=dict)
    by_basename: Dict[str, Set[str]] = field(default_factory=dict)
    bare: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)

    def add(self, name: Optional[str], digest: str) -> None:
        digest = digest.lower()
        if not name:
            self.bare.add(digest)
            return
        name = name.replace("\\", "/")
        while name.startswith("./"):
            name = name[2:]
        try:
            validate_relative_path(name, 255, True)
        except BlockingError as exc:
            self.errors.append("unsafe name %s: %s" % (display_text(name), exc))
            return
        if name in self.named and self.named[name] != digest:
            self.errors.append("conflicting hashes for %s" % display_text(name))
            return
        self.named[name] = digest
        self.by_basename.setdefault(name.rsplit("/", 1)[-1], set()).add(digest)

    def count(self) -> int:
        return len(self.named) + len(self.bare)


def parse_hash_text(text: str) -> HashList:
    hashes = HashList()
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        m = HASH_LINE_RE.match(line)
        if m:
            hashes.add(m.group(2), m.group(1))
            continue
        m = BSD_HASH_LINE_RE.match(line)
        if m:
            hashes.add(m.group(1), m.group(2))
            continue
        hashes.errors.append("line %d is not a SHA-256 entry" % number)
    return hashes


def parse_hash_json(text: str) -> HashList:
    hashes = HashList()
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        hashes.errors.append("invalid JSON: %s" % exc)
        return hashes
    if not isinstance(data, dict):
        hashes.errors.append("JSON trusted hash file must be an object")
        return hashes
    named = data.get("sha256", {})
    bare = data.get("hashes", [])
    if not isinstance(named, dict) or not isinstance(bare, list):
        hashes.errors.append("expected {\"sha256\": {name: hash}, \"hashes\": [hash, ...]}")
        return hashes
    for name, digest in named.items():
        if isinstance(digest, str) and SHA256_RE.match(digest.lower()):
            hashes.add(str(name), digest)
        else:
            hashes.errors.append("invalid hash for %s" % display_text(name))
    for digest in bare:
        if isinstance(digest, str) and SHA256_RE.match(digest.lower()):
            hashes.add(None, digest)
        else:
            hashes.errors.append("invalid bare hash entry")
    return hashes


def load_trusted_hashes(ctx: Context, path: str) -> Tuple[HashList, Dict[str, Any]]:
    real = os.path.realpath(path)
    for forbidden in (ctx.store.root / "quarantine", ctx.store.root / "mnt"):
        f = os.path.realpath(str(forbidden))
        if real == f or real.startswith(f + os.sep):
            raise BlockingError("TRUSTED_HASH_FROM_DIRTY_MEDIA", "the trusted hash file is inside the quarantine or "
                                "a mount point; content from the dirty USB can never define trusted hashes")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise BlockingError("TRUSTED_HASH_FILE_INVALID", "cannot open trusted hash file: %s" % exc.strerror)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 1024 * 1024:
            raise BlockingError("TRUSTED_HASH_FILE_INVALID", "trusted hash file must be a regular file under 1 MiB")
        if st.st_uid not in (os.geteuid(), 0):
            raise BlockingError("TRUSTED_HASH_FILE_INVALID", "trusted hash file is not owned by you or root")
        raw = read_bounded(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    disks, protected = enumerate_devices(ctx)
    removable = [d.kname for d in removable_disks(disks, protected)]
    if removable and ctx.backend.path_on_devices(path, removable):
        raise BlockingError("TRUSTED_HASH_ON_REMOVABLE",
                            "the trusted hash file is stored on removable USB media; it must be kept separately "
                            "from the dirty USB (for example typed in on the live system)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BlockingError("TRUSTED_HASH_FILE_INVALID", "trusted hash file is not UTF-8 text")
    hashes = parse_hash_json(text) if path.lower().endswith(".json") else parse_hash_text(text)
    if hashes.errors:
        raise BlockingError("TRUSTED_HASH_FILE_INVALID", "trusted hash file rejected: %s" % "; ".join(hashes.errors[:5]))
    if not hashes.count():
        raise BlockingError("TRUSTED_HASH_FILE_INVALID", "trusted hash file contains no SHA-256 entries")
    meta = {"source": "file", "path": display_text(os.path.abspath(path), 300), "file_sha256": sha256_hex(raw),
            "entries": hashes.count(), "loaded_at": utc_now()}
    return hashes, meta


def compare_hash(rec: Dict[str, Any], hashes: HashList) -> Optional[Dict[str, Any]]:
    """Compare one file against a hash list. None when the list says nothing about it."""
    rel = rec["relative_path"]
    base = rel.rsplit("/", 1)[-1]
    actual = rec["sha256"]
    if rel in hashes.named:
        expected = hashes.named[rel]
        return {"result": "match" if expected == actual else "mismatch", "matched_by": "relative_path", "expected": expected}
    named_paths = [n for n in hashes.named if n.rsplit("/", 1)[-1] == base]
    if named_paths:
        candidates = hashes.by_basename.get(base, set())
        return {"result": "match" if actual in candidates else "mismatch", "matched_by": "file_name",
                "expected": sorted(candidates)[0] if len(candidates) == 1 else sorted(candidates)}
    if actual in hashes.bare:
        return {"result": "match", "matched_by": "hash_only", "expected": actual}
    if actual in hashes.named.values():
        other = sorted(n for n, h in hashes.named.items() if h == actual)[0]
        return {"result": "match", "matched_by": "hash_listed_under_other_name:" + display_text(other), "expected": actual}
    return None


def apply_trusted_hashes(session: Dict[str, Any], hashes: HashList, meta: Dict[str, Any]) -> Dict[str, int]:
    counts = {"match": 0, "mismatch": 0, "unlisted": 0}
    for rec in session["files"]:
        outcome = compare_hash(rec, hashes)
        if outcome is None:
            counts["unlisted"] += 1
            continue
        set_hash_result(session, rec, outcome, meta)
        counts[outcome["result"]] += 1
    session.setdefault("trusted_hash_sources", []).append(dict(meta, results=counts))
    return counts


def set_hash_result(session: Dict[str, Any], rec: Dict[str, Any], outcome: Dict[str, Any], meta: Dict[str, Any]) -> None:
    # A mismatch is sticky: no later list can clear it.
    if rec["hash_status"] == HASH_MISMATCH:
        return
    entry = {"source": meta.get("source"), "path": meta.get("path"), "matched_by": outcome["matched_by"],
             "expected": outcome["expected"], "at": utc_now()}
    if outcome["result"] == "match":
        rec["hash_status"] = HASH_MATCH
        rec["trusted_hash"] = entry
    else:
        rec["hash_status"] = HASH_MISMATCH
        rec["trusted_hash"] = entry
        rec["approved"] = False
        add_blocking(session, "TRUSTED_HASH_MISMATCH",
                     "%s does not match its independently trusted SHA-256; release is blocked"
                     % rec["relative_path_display"])


def compare_source_supplied_hashes(session: Dict[str, Any], records: List[Dict[str, Any]]) -> None:
    """Hash lists found on the dirty USB are untrusted metadata: informational comparison only."""
    for listing in records:
        name = listing["original_name"].lower()
        if not (file_extension(name) in ("sha256", "sha256sum") or name.startswith("sha256sums")):
            continue
        text, _enc, _flags, rejects = decode_text(listing["_data"])
        if rejects or text is None:
            continue
        hashes = parse_hash_text(text)
        summary = {"listing": listing["relative_path_display"], "entries": hashes.count(), "matches": [], "mismatches": []}
        for rec in records:
            if rec is listing:
                continue
            outcome = compare_hash(rec, hashes)
            if outcome is None:
                continue
            if outcome["result"] == "match":
                summary["matches"].append(rec["relative_path_display"])
                rec["review_flags"].append(make_flag(
                    "SOURCE_SUPPLIED_HASH_MATCH", SEV_INFO,
                    "matches a hash list found on the dirty USB (%s); that list is untrusted and does not establish "
                    "authenticity" % listing["relative_path_display"]))
            else:
                summary["mismatches"].append(rec["relative_path_display"])
                rec["review_flags"].append(make_flag(
                    "SOURCE_SUPPLIED_HASH_MISMATCH", SEV_REVIEW,
                    "does NOT match the hash list found on the dirty USB (%s); possible tampering"
                    % listing["relative_path_display"]))
        session.setdefault("source_supplied_hash_lists", []).append(summary)


# ---------------------------------------------------------------------------
# Network isolation
# ---------------------------------------------------------------------------

def describe_network(console: Console, net: Dict[str, Any]) -> None:
    if not net.get("known"):
        console.warn("Network state could not be determined (ip tool unavailable).")
        return
    if not net["interfaces_up"] and not net.get("default_route"):
        console.passed("OFFLINE: no non-loopback interface is up and no default route exists.")
    else:
        console.warn("Network appears ACTIVE (interfaces up: %s; default route: %s). The transfer needs no "
                     "network; consider --offline-lockdown." % (
                         ", ".join(display_text(i) for i in net["interfaces_up"]) or "none",
                         "yes" if net.get("default_route") else "no"))
    unblocked = [d for d in net.get("rfkill", []) if d.get("soft") == "unblocked" and d.get("hard") == "unblocked"]
    if unblocked:
        console.warn("Radios not blocked by rfkill: %s" % ", ".join(str(d.get("type")) for d in unblocked))


def do_network_lockdown(ctx: Context, use_firewall: bool) -> Dict[str, Any]:
    c = ctx.console
    if os.path.lexists(str(ctx.store.lockdown_path)):
        c.info("A network lockdown is already active (state saved at %s)." % ctx.store.lockdown_path)
        return _read_private_json(ctx.store.lockdown_path)
    ctx.backend.ensure_privilege(c)
    record = ctx.backend.network_lockdown(ctx.store.lockdown_path, use_firewall)
    ctx.log.event("network_lockdown", actions=record.get("actions", []))
    c.passed("Offline lockdown applied (%d actions). Prior state saved to %s."
             % (len(record.get("actions", [])), ctx.store.lockdown_path))
    if record.get("firewall_error"):
        c.warn("Firewall drop policy could not be applied: %s" % record["firewall_error"])
    c.info("Restore later with: python3 airlock.py network-restore")
    return record


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def new_session(ctx: Context, env: Dict[str, Any], net: Dict[str, Any]) -> Dict[str, Any]:
    now = utc_now()
    return {
        "schema": SESSION_SCHEMA, "app_version": APP_VERSION, "run_id": new_run_id(),
        "simulated": bool(ctx.backend.simulated), "phase": PHASE_INGEST_IN_PROGRESS,
        "created_at": now, "updated_at": now, "environment": env, "network": net,
        "warnings": [], "blocking": [], "source": None, "files": [], "rejected": [], "scan": {},
        "quarantine": {}, "trusted_hash_sources": [], "source_supplied_hash_lists": [], "clamav": None,
        "release_attempts": [], "release": None, "verification": None, "clean_verifications": [],
        "source_removed_at": None,
    }


def load_session_checked(ctx: Context) -> Dict[str, Any]:
    session = ctx.store.load_session()
    if session is None:
        raise BlockingError("NO_SESSION", "no active session; start with: python3 airlock.py ingest")
    if bool(session.get("simulated")) != bool(ctx.backend.simulated):
        raise BlockingError("SESSION_MODE_MISMATCH", "session was created in %s mode"
                            % ("simulation" if session.get("simulated") else "real-device"))
    ctx.attach_log(session["run_id"])
    return session


def print_environment_summary(ctx: Context, env: Dict[str, Any]) -> None:
    c = ctx.console
    if env.get("simulated"):
        c.warn("SIMULATION MODE: no real devices are accessed.")
    if env.get("live_detected"):
        c.passed("Live environment indicators: %s" % "; ".join(env.get("live_markers", [])))
    else:
        c.warn(INSTALLED_OS_WARNING)
    if env.get("euid") == 0:
        c.warn("Running as root. Only specific steps need root; prefer a normal user with sudo.")
    if not env.get("python_isolated_mode"):
        c.info("Tip: run as 'python3 -I -B airlock.py ...' so Python ignores environment variables and user site paths.")


def confirm_no_removable_present(ctx: Context, session: Dict[str, Any]) -> None:
    """Require physical removal of the dirty USB, verified by re-enumeration."""
    c = ctx.console
    fingerprint = session["source"]["identity"] if session.get("source") else {}
    for _attempt in range(10):
        c.heading("REMOVE DIRTY USB NOW")
        ctx.backend.notify("await_source_removal")
        answer = c.ask("Physically remove the DIRTY USB (and any other USB storage), then type REMOVED (q to stop): ")
        if answer.lower() in ("q", "quit"):
            raise OperatorCancelled("operator stopped before confirming source removal")
        if answer != "REMOVED":
            c.warn("Removal not confirmed.")
            continue
        disks, protected = enumerate_devices(ctx)
        present = removable_disks(disks, protected)
        still = [d for d in present if fingerprint and matches_fingerprint(fingerprint, d)]
        if still:
            c.blocking("DIRTY USB STILL DETECTED (%s). DO NOT ENTER RELEASE MODE. Remove it physically."
                       % ", ".join(display_text(d.preferred_by_id() or d.kname) for d in still))
            ctx.log.event("source_still_present", devices=[d.kname for d in still])
            continue
        if present:
            c.blocking("Removable storage is still attached: %s. Only the protected live boot media may remain."
                       % ", ".join(display_text(d.preferred_by_id() or d.kname) for d in present))
            continue
        c.passed("Dirty source confirmed absent: no removable USB storage detected.")
        session["phase"] = PHASE_SOURCE_REMOVED
        session["source_removed_at"] = utc_now()
        ctx.store.save_session(session)
        ctx.log.event("source_removed_confirmed")
        return
    raise BlockingError("SOURCE_STILL_PRESENT", "dirty source removal could not be confirmed")


def require_source_removed(ctx: Context, session: Dict[str, Any]) -> None:
    if session["phase"] == PHASE_INGESTED:
        confirm_no_removable_present(ctx, session)
    if session["phase"] != PHASE_SOURCE_REMOVED:
        raise BlockingError("WRONG_PHASE", "session phase is %s; this step needs %s" % (session["phase"], PHASE_SOURCE_REMOVED))


def wait_for_single_removable(ctx: Context, prompt: str, event: Optional[str] = None,
                              ask_first: bool = False) -> Disk:
    c = ctx.console
    if ask_first:
        if event:
            ctx.backend.notify(event)
        if c.ask(prompt).lower() in ("q", "quit"):
            raise OperatorCancelled("operator cancelled")
    for _attempt in range(20):
        disks, protected = enumerate_devices(ctx)
        present = removable_disks(disks, protected)
        if len(present) > 1:
            for d in present:
                c.line("  present: %s  %s  serial %s  %s" % (display_text(d.preferred_by_id() or d.kname),
                                                              display_text(d.model), display_text(d.serial), human_size(d.size)))
            raise BlockingError("MULTIPLE_REMOVABLE_DEVICES",
                                "more than one removable storage device is present. Source and destination must "
                                "never be attached at the same time. STOP: remove all but one device and start again. "
                                "If one of them is the live boot media and was not detected, declare it with "
                                "--live-device /dev/disk/by-id/...")
        if present:
            return present[0]
        if event:
            ctx.backend.notify(event)
        if c.ask(prompt).lower() in ("q", "quit"):
            raise OperatorCancelled("operator cancelled")
    raise BlockingError("NO_DEVICE", "no removable USB storage device was detected")


def ensure_not_mounted(ctx: Context, part: Partition) -> None:
    if ctx.backend.mounts_of(part):
        raise BlockingError("CONCURRENT_MOUNT", "/dev/%s was mounted again by another process (probably desktop "
                            "automount). Disable automount and start again." % part.kname)


def prepare_mountpoint(ctx: Context, role: str) -> Path:
    target = ctx.store.mountpoint(role)
    ensure_private_dir(target)
    if not ctx.backend.simulated:
        if ctx.backend.is_mounted_at(target):
            raise BlockingError("MOUNTPOINT_INVALID", "%s is still mounted from an earlier run; unmount it first" % target)
    return target


# ---------------------------------------------------------------------------
# Commands: status
# ---------------------------------------------------------------------------

def cmd_status(ctx: Context) -> int:
    c = ctx.console
    c.heading("MX USB TRANSFER AIRLOCK %s - STATUS" % APP_VERSION)
    env = ctx.backend.environment()
    osr = env.get("os_release", {})
    c.line("System      : %s, kernel %s, PID 1 %s" % (osr.get("PRETTY_NAME", "unknown"), env.get("kernel"), env.get("pid1")))
    c.line("State dir   : %s" % ctx.store.root)
    print_environment_summary(ctx, env)
    describe_network(c, ctx.backend.network_state())
    if os.path.lexists(str(ctx.store.lockdown_path)):
        c.info("Offline lockdown is ACTIVE (restore with: network-restore).")
    disks, protected = enumerate_devices(ctx)
    c.line("")
    c.line("Block devices:")
    for disk in disks:
        if disk.kname in protected:
            role = "PROTECTED - " + protected[disk.kname]
        elif disk in removable_disks([disk], protected):
            role = "REMOVABLE " + ("USB" if disk.tran == "usb" else "(non-USB: %s)" % (display_text(disk.tran) or "unknown"))
        else:
            role = "INTERNAL/OTHER (never selectable)"
        c.line("  /dev/%-8s %-10s %s" % (disk.kname, human_size(disk.size), role))
        c.line("      model %s  serial %s  by-id %s" % (display_text(disk.model) or "-", display_text(disk.serial) or "-",
                                                       display_text(disk.preferred_by_id()) or "-"))
    present = removable_disks(disks, protected)
    if len(present) > 1:
        c.blocking("More than one removable storage device is attached. Source and destination must never coexist.")
    session = ctx.store.load_session()
    c.line("")
    if session is None:
        c.line("Session     : none. Next step: insert ONLY the dirty USB and run 'ingest'.")
        return 0
    c.line("Session     : %s  phase %s%s" % (session["run_id"], session["phase"], "  (simulation)" if session.get("simulated") else ""))
    approved = sum(1 for f in session["files"] if f.get("approved"))
    c.line("Files       : %d quarantined, %d approved, %d rejected" % (len(session["files"]), approved, len(session["rejected"])))
    for b in session.get("blocking", []):
        c.blocking("%s: %s" % (b["code"], b["message"]))
    next_step = {
        PHASE_INGEST_IN_PROGRESS: "ingest did not finish; start over with 'ingest --new-session'",
        PHASE_INGESTED: "remove the dirty USB, then run 'review'",
        PHASE_SOURCE_REMOVED: "run 'review' to approve files, then 'release'" if not approved else "run 'release'",
        PHASE_RELEASED: "optional: 'verify-clean' re-checks the clean USB; 'report' prints the report",
        PHASE_BLOCKED: "session is blocked; inspect 'report', then 'ingest --new-session'",
        PHASE_CANCELLED: "session was cancelled; start over with 'ingest --new-session'",
    }.get(session["phase"], "")
    c.line("Next step   : %s" % next_step)
    return 0


# ---------------------------------------------------------------------------
# Commands: ingest
# ---------------------------------------------------------------------------

def cmd_ingest(ctx: Context) -> int:
    c = ctx.console
    c.heading("PHASE A: INGEST  (dirty source -> read-only -> quarantine)")
    env = ctx.backend.environment()
    print_environment_summary(ctx, env)
    existing = ctx.store.load_session()
    if existing is not None:
        if existing["phase"] not in TERMINAL_PHASES and not ctx.arg("new_session"):
            raise BlockingError("SESSION_ACTIVE", "session %s is in phase %s. Finish it, or discard it and start "
                                "over with: ingest --new-session" % (existing["run_id"], existing["phase"]))
        ctx.store.archive_session(existing)
        c.info("Previous session %s archived and its quarantine removed." % existing["run_id"])
    if ctx.arg("offline_lockdown"):
        do_network_lockdown(ctx, bool(ctx.arg("with_firewall")))
    net = ctx.backend.network_state()
    describe_network(c, net)
    session = new_session(ctx, env, net)
    if not env.get("live_detected"):
        add_warning(session, "NOT_LIVE_ENVIRONMENT", INSTALLED_OS_WARNING)
    ctx.store.save_session(session)
    ctx.attach_log(session["run_id"])
    ctx.log.event("ingest_start", run_id=session["run_id"], simulated=session["simulated"])
    try:
        try:
            scan = _ingest_device_and_scan(ctx, session)
            _ingest_finish(ctx, session, scan)
        except OSError as exc:
            raise BlockingError("IO_ERROR", "unexpected I/O error during ingest: %s" % display_text(exc, 300))
    except BlockingError as exc:
        session["phase"] = PHASE_BLOCKED
        add_blocking(session, exc.code, str(exc))
        ctx.store.save_session(session)
        ctx.store.wipe_quarantine(session["run_id"])
        ctx.log.event("ingest_blocked", code=exc.code, message=str(exc))
        raise
    except OperatorCancelled as exc:
        session["phase"] = PHASE_CANCELLED
        add_warning(session, "OPERATOR_CANCELLED", str(exc))
        ctx.store.save_session(session)
        ctx.store.wipe_quarantine(session["run_id"])
        ctx.log.event("ingest_cancelled")
        raise
    confirm_no_removable_present(ctx, session)
    c.line("")
    c.info("Next: python3 airlock.py review")
    return 0


def _ingest_device_and_scan(ctx: Context, session: Dict[str, Any]) -> ScanResult:
    c = ctx.console
    disk = wait_for_single_removable(ctx, "Insert ONLY the DIRTY USB now, then press Enter (q to stop): ")
    if disk.tran != "usb":
        raise BlockingError("NOT_USB_STORAGE", "the only removable device is not USB storage (transport %s)"
                            % (display_text(disk.tran) or "unknown"))
    if not disk.serial and not disk.by_id:
        raise BlockingError("IDENTITY_UNCERTAIN", "the device reports neither a serial number nor a by-id path")
    show_identity(c, "DIRTY SOURCE (untrusted, read-only ingest)", disk)
    if not disk.serial:
        c.warn("This device reports no serial number; identity relies on model, vendor, size and by-id path.")
        add_warning(session, "SOURCE_NO_SERIAL", "dirty source reports no serial number")
    c.confirm_phrase("YES", "Is this the DIRTY source USB you intend to ingest?")
    part = choose_partition(ctx, disk, SOURCE_FILESYSTEMS, "ingest")
    identity = disk.identity()
    part_identity = asdict(part)
    session["source"] = {"identity": identity, "partition": part_identity,
                         "by_id_path": ("/dev/disk/by-id/" + disk.preferred_by_id()) if disk.preferred_by_id() else "",
                         "confirmed_at": utc_now()}
    ctx.store.save_session(session)
    ctx.log.event("source_confirmed", identity=identity, partition=part.kname, fstype=part.fstype)

    session["source"]["automount_events"] = handle_existing_mounts(ctx, session, disk, "source")
    ctx.backend.ensure_privilege(c)
    disk, part = revalidate(ctx, identity, part.kname, part_identity)
    ro_ok, ro_details = ctx.backend.set_readonly(disk)
    session["source"]["block_readonly"] = {"verified": ro_ok, "details": ro_details}
    if ro_ok:
        c.passed("BLOCK DEVICE SET READ-ONLY (verified at the Linux block layer)")
    else:
        c.warn("The block device could NOT be verified read-only at the block layer.")
        add_warning(session, "BLOCK_READONLY_UNVERIFIED", "blockdev --setro could not be verified")
        c.confirm_phrase("PROCEED", "The filesystem will still be mounted read-only, but the block-layer "
                                    "protection is missing.")
    disk, part = revalidate(ctx, identity, part.kname, part_identity)
    kfstype, options = mount_options(part.fstype, "ro", ctx.uid, ctx.gid)
    target = prepare_mountpoint(ctx, "source")
    ensure_not_mounted(ctx, part)
    root = ctx.backend.mount(part, kfstype, target, options)
    try:
        minfo = ctx.backend.verify_mount(part, root, expect_ro=True)
        session["source"]["mount"] = {"fstype": kfstype, "requested_options": options, "verified": minfo}
        c.passed("SOURCE MOUNTED READ-ONLY (ro,nodev,nosuid,noexec)")
        ctx.store.save_session(session)
        scan = scan_source_tree(root, ctx.config, ctx.backend.expected_root_dev(part),
                                on_entry=lambda: ctx.backend.notify("scan_entry"))
        ctx.backend.verify_mount(part, root, expect_ro=True)
        revalidate(ctx, identity, part.kname, part_identity)
    finally:
        ctx.backend.unmount_partition(part, target)
    if ctx.backend.mounts_of(part):
        raise BlockingError("UNMOUNT_FAILED", "dirty source is still mounted")
    c.passed("Dirty source unmounted.")
    return scan


def _ingest_finish(ctx: Context, session: Dict[str, Any], scan: ScanResult) -> None:
    c = ctx.console
    source = session["source"]
    now = utc_now()
    for rec in scan.accepted:
        rec["source_device_by_id"] = source.get("by_id_path", "")
        rec["source_device_serial"] = display_text(source["identity"].get("serial", ""))
        rec["ingest_timestamp"] = now
        rec["hash_status"] = HASH_NOT_PREAUTHORIZED
        rec["trusted_hash"] = None
        rec["approved"] = False
        rec["approved_sha256"] = None
        rec["clamav"] = "NOT_SCANNED"
    session["scan"] = {"entries_examined": scan.entries_examined, "limit_reached": scan.limit_reached,
                       "accepted": len(scan.accepted), "rejected": len(scan.rejected), "total_bytes": scan.total_bytes}
    for warning in scan.warnings:
        add_warning(session, "SCAN_WARNING", warning)
    compare_source_supplied_hashes(session, scan.accepted)

    qdir = ctx.store.quarantine_dir(session["run_id"])
    if scan.accepted:
        free = shutil.disk_usage(str(ctx.store.root)).free
        if free < scan.total_bytes * 2 + 1024 * 1024:
            raise BlockingError("QUARANTINE_SPACE", "not enough space for quarantine in %s" % ctx.store.root)
    os.mkdir(qdir, 0o700)
    write_quarantine(qdir, scan.accepted)
    fstype = ctx.backend.filesystem_type_of(qdir)
    session["quarantine"] = {"path": str(qdir), "filesystem": fstype,
                             "tmpfs": fstype in ("tmpfs", "ramfs")}
    if fstype not in ("tmpfs", "ramfs", "simulated"):
        c.warn("Quarantine is on %s, not tmpfs. Use --state-dir on trusted local storage or tmpfs if possible." % (fstype or "unknown"))
        add_warning(session, "QUARANTINE_NOT_TMPFS", "quarantine filesystem: %s" % (fstype or "unknown"))
    for rec in scan.accepted:
        rec.pop("_data", None)
    session["files"] = scan.accepted
    session["rejected"] = scan.rejected
    ctx.log.event("quarantine_written", files=[{"path": r["relative_path_display"], "sha256": r["sha256"], "size": r["size"]}
                                               for r in session["files"]],
                  rejected=[{"path": r["relative_path_display"], "reasons": r["reasons"]} for r in session["rejected"]])

    trusted_path = ctx.arg("trusted_hashes")
    if trusted_path:
        hashes, meta = load_trusted_hashes(ctx, trusted_path)
        counts = apply_trusted_hashes(session, hashes, meta)
        ctx.log.event("trusted_hashes_applied", meta=meta, counts=counts)

    run_clamav(ctx, session, qdir)
    session["phase"] = PHASE_INGESTED
    ctx.store.save_session(session)
    print_ingest_summary(ctx, session)


def run_clamav(ctx: Context, session: Dict[str, Any], qdir: Path) -> None:
    c = ctx.console
    if not ctx.config["clamav_enabled"] or not session["files"]:
        session["clamav"] = {"available": False, "skipped": True}
        return
    paths = {str(qdir / rec["quarantine_name"]): rec for rec in session["files"]}
    info = ctx.backend.clamav_scan(sorted(paths))
    if not info.get("available"):
        session["clamav"] = {"available": False}
        c.warn("ClamAV is not installed; continuing with static validation and hashing (not fatal).")
        add_warning(session, "CLAMAV_UNAVAILABLE", "ClamAV not available; no signature scan performed")
        return
    results = info.get("results", {})
    for path, rec in paths.items():
        verdict = results.get(path, "NOT_REPORTED")
        rec["clamav"] = verdict
        if verdict not in ("OK", "NOT_REPORTED"):
            rec["review_flags"].append(make_flag("CLAMAV_DETECTION", SEV_BLOCKING, "ClamAV reported: %s" % verdict))
            add_blocking(session, "CLAMAV_DETECTION", "%s: %s" % (rec["relative_path_display"], verdict))
    session["clamav"] = {k: v for k, v in info.items() if k != "results"}
    session["clamav"]["note"] = "A clean ClamAV result is not proof that a file is benign."
    c.info("ClamAV %s (database %s, %s) exit status %s. A clean result is not proof that a file is benign."
           % (info.get("version"), info.get("database_version"), info.get("database_date"), info.get("exit_code")))
    if info.get("error"):
        c.warn("ClamAV reported an error: %s" % info["error"])
        add_warning(session, "CLAMAV_ERROR", info["error"])


def print_file_detail(c: Console, index: int, rec: Dict[str, Any]) -> None:
    c.line("")
    c.line("[%d] %s   (%s)" % (index, rec["relative_path_display"], human_size(rec["size"])))
    c.line("    SHA-256 : %s" % rec["sha256"])
    status = rec["hash_status"]
    if status == HASH_MATCH:
        c.passed("INTEGRITY VERIFIED AGAINST TRUSTED HASH (%s)" % rec["trusted_hash"]["matched_by"])
    elif status == HASH_MISMATCH:
        c.blocking("TRUSTED HASH MISMATCH - this file cannot be released")
    else:
        c.warn("NO TRUSTED SOURCE HASH AVAILABLE (HASH_NOT_PREAUTHORIZED)")
    flags = rec.get("review_flags", [])
    blocking = [f for f in flags if f["severity"] == SEV_BLOCKING]
    review = [f for f in flags if f["severity"] == SEV_REVIEW]
    info = [f for f in flags if f["severity"] == SEV_INFO]
    for f in blocking:
        c.blocking("%s: %s" % (f["code"], f["detail"]))
    if review:
        c.warn("STATIC REVIEW FLAGS PRESENT (informational; administrative scripts often trigger these):")
        for f in review:
            where = (" lines %s%s" % (",".join(str(n) for n in f["lines"]), "..." if f.get("line_count", 0) > len(f["lines"]) else "")) if f.get("lines") else ""
            c.line("      - %s: %s%s" % (f["code"], f["detail"], where))
    for f in info:
        c.line("    info: %s: %s" % (f["code"], f["detail"]))
    c.line("    ClamAV  : %s" % rec.get("clamav", "NOT_SCANNED"))
    c.line("    Approved: %s" % ("YES" if rec.get("approved") else "no"))


def print_ingest_summary(ctx: Context, session: Dict[str, Any]) -> None:
    c = ctx.console
    c.heading("INGEST SUMMARY  (run %s)" % session["run_id"])
    c.line("Entries examined: %d   quarantined: %d   rejected/skipped: %d"
           % (session["scan"]["entries_examined"], len(session["files"]), len(session["rejected"])))
    for index, rec in enumerate(session["files"], 1):
        print_file_detail(c, index, rec)
    if session["rejected"]:
        c.line("")
        c.line("Left behind on the dirty USB (not copied):")
        for rej in session["rejected"][:200]:
            c.line("  - %s [%s]: %s" % (rej["relative_path_display"], rej["kind"], ", ".join(rej["reasons"])))
        if len(session["rejected"]) > 200:
            c.line("  ... %d more (see report)" % (len(session["rejected"]) - 200))
    if not session["files"]:
        c.warn("No files were eligible for quarantine.")


# ---------------------------------------------------------------------------
# Commands: review
# ---------------------------------------------------------------------------

def cmd_review(ctx: Context) -> int:
    c = ctx.console
    session = load_session_checked(ctx)
    c.heading("VALIDATION / REVIEW  (run %s)" % session["run_id"])
    if session["phase"] not in (PHASE_INGESTED, PHASE_SOURCE_REMOVED):
        raise BlockingError("WRONG_PHASE", "review is not possible in phase %s" % session["phase"])
    require_source_removed(ctx, session)
    trusted_path = ctx.arg("trusted_hashes")
    if trusted_path:
        hashes, meta = load_trusted_hashes(ctx, trusted_path)
        counts = apply_trusted_hashes(session, hashes, meta)
        ctx.store.save_session(session)
        c.info("Trusted hash file applied: %d match, %d MISMATCH, %d files not listed."
               % (counts["match"], counts["mismatch"], counts["unlisted"]))
        ctx.log.event("trusted_hashes_applied", meta=meta, counts=counts)
    if not session["files"]:
        c.warn("No quarantined files to review.")
        return 0
    if ctx.arg("list_only"):
        for index, rec in enumerate(session["files"], 1):
            print_file_detail(c, index, rec)
        return 0
    qdir = ctx.store.quarantine_dir(session["run_id"])
    require_trusted = ctx.config["require_trusted_hashes"]
    for index, rec in enumerate(session["files"], 1):
        print_file_detail(c, index, rec)
        while True:
            if rec["hash_status"] == HASH_MISMATCH or any(f["severity"] == SEV_BLOCKING for f in rec["review_flags"]):
                c.blocking("This file has a BLOCKING finding and cannot be approved.")
                rec["approved"] = False
                break
            choice = c.ask("Approve file %d? [a]pprove  [r]eject  [h] enter trusted SHA-256  [s]kip  [q]uit: " % index).lower()
            if choice in ("q", "quit"):
                ctx.store.save_session(session)
                c.info("Review saved; nothing released.")
                return 0
            if choice in ("s", ""):
                break
            if choice == "r":
                rec["approved"] = False
                rec["approved_sha256"] = None
                ctx.log.event("file_rejected_by_operator", path=rec["relative_path_display"], sha256=rec["sha256"])
                break
            if choice == "h":
                entered = c.ask("Paste the independently trusted SHA-256 for this file: ").strip().lower()
                if not SHA256_RE.match(entered):
                    c.warn("That is not a 64-character hexadecimal SHA-256.")
                    continue
                outcome = {"result": "match" if entered == rec["sha256"] else "mismatch",
                           "matched_by": "operator_entered", "expected": entered}
                set_hash_result(session, rec, outcome, {"source": "operator_entered", "path": None})
                ctx.store.save_session(session)
                ctx.log.event("operator_hash_entered", path=rec["relative_path_display"], result=outcome["result"])
                if outcome["result"] == "match":
                    c.passed("INTEGRITY VERIFIED AGAINST TRUSTED HASH (operator-entered)")
                else:
                    c.blocking("TRUSTED HASH MISMATCH. This file is blocked and release is not allowed.")
                continue
            if choice == "a":
                if rec["hash_status"] != HASH_MATCH:
                    if require_trusted:
                        c.blocking("Configuration requires a trusted hash for every released file.")
                        continue
                    c.warn("NO TRUSTED SOURCE HASH AVAILABLE. The SHA-256 above only identifies the bytes you are "
                           "approving; it does not prove the file was originally trustworthy.")
                    if c.ask("Type APPROVE to approve based on your own review: ") != "APPROVE":
                        c.info("Not approved.")
                        continue
                data = read_quarantine_file(qdir, rec, rec["sha256"])
                rec["approved"] = True
                rec["approved_sha256"] = sha256_hex(data)
                rec["approved_at"] = utc_now()
                ctx.log.event("file_approved", path=rec["relative_path_display"], sha256=rec["approved_sha256"],
                              hash_status=rec["hash_status"])
                c.passed("Approved.")
                break
            c.warn("Unrecognised choice.")
        ctx.store.save_session(session)
    approved = sum(1 for f in session["files"] if f.get("approved"))
    c.line("")
    c.info("%d of %d files approved. Next: python3 airlock.py release" % (approved, len(session["files"])))
    return 0


# ---------------------------------------------------------------------------
# Commands: release
# ---------------------------------------------------------------------------

def _mkdir_open(parent_fd: int, name: str) -> int:
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    fd = open_dir_nofollow(name, dir_fd=parent_fd)
    return fd


def _write_new_file(dir_fd: int, name: str, data: bytes) -> None:
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    except FileExistsError:
        raise BlockingError("DESTINATION_COLLISION", "destination file already exists: %s" % display_text(name))
    try:
        write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


class DestinationWriter:
    """Writes the release tree beneath a freshly created directory, never following links."""

    def __init__(self, dest_root: Path, base_name: str, run_id: str):
        self.dest_root = Path(dest_root)
        self.base_name = base_name
        self.run_id = run_id
        self.transfer_dir = ""
        self._fds: Dict[str, int] = {}

    def open(self) -> str:
        try:
            root_fd = open_dir_nofollow(str(self.dest_root))
        except OSError as exc:
            raise BlockingError("DESTINATION_INVALID", "cannot open destination root without following links: %s" % exc.strerror)
        self._fds[""] = root_fd
        candidates = [self.base_name] + ["%s_%s" % (self.base_name, self.run_id.replace("-", "_"))]
        candidates += ["%s_%s_%d" % (self.base_name, self.run_id.replace("-", "_"), n) for n in range(2, 6)]
        for name in candidates:
            try:
                os.mkdir(name, 0o700, dir_fd=root_fd)
            except FileExistsError:
                continue
            self.transfer_dir = name
            break
        if not self.transfer_dir:
            raise BlockingError("DESTINATION_COLLISION", "could not create a new transfer directory on the destination")
        tfd = open_dir_nofollow(self.transfer_dir, dir_fd=root_fd)
        self._fds["."] = tfd
        for sub in ("FILES", "MANIFEST", "REPORTS"):
            self._fds[sub] = _mkdir_open(tfd, sub)
        return self.transfer_dir

    def _dir_fd(self, parts: List[str]) -> int:
        key = "FILES"
        fd = self._fds[key]
        for comp in parts:
            key = key + "/" + comp
            if key not in self._fds:
                self._fds[key] = _mkdir_open(fd, comp)
            fd = self._fds[key]
        return fd

    def write_file(self, rel_under_files: str, data: bytes) -> str:
        parts = validate_relative_path(rel_under_files, 255, True)
        fd = self._dir_fd(parts[:-1])
        _write_new_file(fd, parts[-1], data)
        real_transfer = os.path.realpath(os.path.join(str(self.dest_root), self.transfer_dir))
        real_file = os.path.realpath(os.path.join(real_transfer, "FILES", *parts))
        if not real_file.startswith(real_transfer + os.sep):
            raise BlockingError("PATH_TRAVERSAL", "destination path escaped the transfer directory")
        return "FILES/" + "/".join(parts)

    def write_meta(self, sub: str, name: str, data: bytes) -> str:
        if sub not in ("MANIFEST", "REPORTS") or check_name_component(name):
            raise BlockingError("PATH_TRAVERSAL", "invalid metadata path")
        _write_new_file(self._fds[sub], name, data)
        return "%s/%s" % (sub, name)

    def close(self) -> None:
        for key in sorted(self._fds, key=len, reverse=True):
            fsync_quiet(self._fds[key])
        for fd in self._fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds = {}


def inventory_tree(root: Path, transfer_dir: str, max_bytes: int) -> Tuple[Dict[str, str], List[str]]:
    """Hash every regular file beneath transfer_dir without following links. Returns (hashes, anomalies)."""
    hashes: Dict[str, str] = {}
    anomalies: List[str] = []
    root_fd = open_dir_nofollow(str(root))
    try:
        tfd = open_dir_nofollow(transfer_dir, dir_fd=root_fd)
    except OSError as exc:
        os.close(root_fd)
        raise BlockingError("DESTINATION_VERIFICATION_FAILED", "transfer directory not readable: %s" % exc.strerror)

    def walk(dfd: int, prefix: str, depth: int) -> None:
        if depth > 40:
            anomalies.append("directory nesting too deep at %s" % prefix)
            return
        with os.scandir(dfd) as it:
            names = sorted(e.name for e in it)
        for name in names:
            rel = (prefix + "/" + name) if prefix else name
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                sub = open_dir_nofollow(name, dir_fd=dfd)
                try:
                    walk(sub, rel, depth + 1)
                finally:
                    os.close(sub)
            elif stat.S_ISREG(st.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
                try:
                    data = read_bounded(fd, max_bytes + 1)
                finally:
                    os.close(fd)
                if len(data) > max_bytes:
                    anomalies.append("unexpectedly large file %s" % display_text(rel))
                hashes[rel] = sha256_hex(data)
            else:
                anomalies.append("non-regular entry %s" % display_text(rel))

    try:
        walk(tfd, "", 0)
    except OSError as exc:
        raise BlockingError("DESTINATION_VERIFICATION_FAILED", "error re-reading destination: %s" % exc.strerror)
    finally:
        os.close(tfd)
        os.close(root_fd)
    return hashes, anomalies


def compare_inventory(expected: Dict[str, str], actual: Dict[str, str], anomalies: List[str]) -> List[str]:
    problems = list(anomalies)
    for rel, digest in sorted(expected.items()):
        if rel not in actual:
            problems.append("MISSING %s" % display_text(rel))
        elif actual[rel] != digest:
            problems.append("HASH MISMATCH %s" % display_text(rel))
    for rel in sorted(set(actual) - set(expected)):
        problems.append("UNEXPECTED FILE %s" % display_text(rel))
    return problems


def build_release_manifest(session: Dict[str, Any], approved: List[Dict[str, Any]], dest_paths: Dict[str, str]) -> Dict[str, Any]:
    return {
        "application": {"name": APP_NAME, "version": APP_VERSION},
        "run_id": session["run_id"],
        "created_at": utc_now(),
        "note": ("Hashes identify the exact bytes written by the airlock. HASH_NOT_PREAUTHORIZED means no "
                 "independently trusted hash was available; such a hash does not prove the file was "
                 "originally trustworthy."),
        "files": [{
            "path": dest_paths[rec["relative_path"]],
            "original_name": rec["original_name"],
            "sanitized_display_name": rec["sanitized_display_name"],
            "relative_path": rec["relative_path"],
            "size": rec["size"],
            "sha256": rec["sha256"],
            "sha512": rec.get("sha512"),
            "source_device_by_id": rec.get("source_device_by_id"),
            "source_device_serial": rec.get("source_device_serial"),
            "ingest_timestamp": rec.get("ingest_timestamp"),
            "validation_status": "APPROVED",
            "hash_status": rec["hash_status"],
            "review_flags": sorted({f["code"] for f in rec.get("review_flags", [])}),
        } for rec in approved],
    }


def cmd_release(ctx: Context) -> int:
    c = ctx.console
    session = load_session_checked(ctx)
    c.heading("PHASE B: RELEASE  (quarantine -> clean USB)  run %s" % session["run_id"])
    print_environment_summary(ctx, ctx.backend.environment())
    if session["phase"] not in (PHASE_INGESTED, PHASE_SOURCE_REMOVED):
        raise BlockingError("WRONG_PHASE", "release is not possible in phase %s" % session["phase"])
    if any(f["hash_status"] == HASH_MISMATCH for f in session["files"]):
        raise BlockingError("TRUSTED_HASH_MISMATCH", "at least one file failed its trusted hash check; release is blocked")
    approved = [f for f in session["files"] if f.get("approved")]
    if not approved:
        raise BlockingError("NOTHING_APPROVED", "no files are approved; run: python3 airlock.py review")
    for rec in approved:
        if any(fl["severity"] == SEV_BLOCKING for fl in rec["review_flags"]):
            raise BlockingError("BLOCKING_FINDING", "%s has a blocking finding" % rec["relative_path_display"])
        if rec.get("approved_sha256") != rec["sha256"]:
            raise BlockingError("APPROVAL_INVALID", "approval for %s does not match its hash" % rec["relative_path_display"])
        if ctx.config["require_trusted_hashes"] and rec["hash_status"] != HASH_MATCH:
            raise BlockingError("TRUSTED_HASH_REQUIRED", "%s has no trusted hash match" % rec["relative_path_display"])
    require_source_removed(ctx, session)

    qdir = ctx.store.quarantine_dir(session["run_id"])
    payloads: Dict[str, bytes] = {}
    try:
        for rec in approved:
            payloads[rec["relative_path"]] = read_quarantine_file(qdir, rec, rec["approved_sha256"])
    except BlockingError as exc:
        session["phase"] = PHASE_BLOCKED
        add_blocking(session, exc.code, str(exc))
        ctx.store.save_session(session)
        raise
    c.passed("Quarantine contents re-verified against recorded SHA-256 values (%d files)." % len(approved))

    if ctx.arg("offline_lockdown"):
        do_network_lockdown(ctx, bool(ctx.arg("with_firewall")))
    describe_network(c, ctx.backend.network_state())

    attempt: Dict[str, Any] = {"started_at": utc_now(), "result": "IN_PROGRESS"}
    session["release_attempts"].append(attempt)
    ctx.store.save_session(session)
    try:
        try:
            result = _release_to_destination(ctx, session, approved, payloads, attempt)
        except OSError as exc:
            raise BlockingError("IO_ERROR", "unexpected I/O error during release: %s" % display_text(exc, 300))
    except BlockingError as exc:
        attempt["result"] = "BLOCKED"
        attempt["error"] = {"code": exc.code, "message": str(exc)}
        add_blocking(session, exc.code, str(exc))
        if exc.code == "QUARANTINE_TAMPERED":
            session["phase"] = PHASE_BLOCKED
        ctx.store.save_session(session)
        if attempt.get("transfer_dir"):
            c.blocking("The clean USB holds an UNVERIFIED directory %s. Do not use it; erase the drive "
                       "(prepare-clean-usb) before another attempt." % attempt["transfer_dir"])
        raise
    except OperatorCancelled as exc:
        attempt["result"] = "CANCELLED"
        attempt["error"] = {"code": "OPERATOR_CANCELLED", "message": str(exc)}
        ctx.store.save_session(session)
        raise
    attempt["result"] = "VERIFIED"
    session["release"] = result
    session["verification"] = result["verification"]
    session["phase"] = PHASE_RELEASED
    ctx.store.save_session(session)
    write_local_reports(ctx, session)
    c.heading("REMOVE CLEAN USB NOW")
    c.passed("DESTINATION HASH MATCH VERIFIED for %d files in %s." % (len(approved), result["transfer_dir"]))
    c.info("The clean USB is unmounted and can be removed. Local report: %s" % (ctx.store.root / "reports"))
    return 0


def _release_to_destination(ctx: Context, session: Dict[str, Any], approved: List[Dict[str, Any]],
                            payloads: Dict[str, bytes], attempt: Dict[str, Any]) -> Dict[str, Any]:
    c = ctx.console
    source_fp = session["source"]["identity"] if session.get("source") else {}
    disks, protected = enumerate_devices(ctx)
    present = removable_disks(disks, protected)
    if any(source_fp and matches_fingerprint(source_fp, d) for d in present):
        raise BlockingError("SOURCE_STILL_PRESENT", "the dirty source USB is attached. DO NOT ENTER RELEASE MODE. "
                            "Remove it physically and run release again.")
    if present:
        raise BlockingError("REMOVABLE_DEVICE_ALREADY_PRESENT",
                            "removable storage is already attached (%s). Remove all USB storage, run release again, "
                            "and insert the clean USB only when prompted."
                            % ", ".join(display_text(d.preferred_by_id() or d.kname) for d in present))
    disk = wait_for_single_removable(ctx, "Insert the CLEAN destination USB now, then press Enter (q to stop): ",
                                     event="await_destination_insertion", ask_first=True)
    if source_fp and matches_fingerprint(source_fp, disk):
        raise BlockingError("DESTINATION_IS_SOURCE", "this device matches the dirty source identity. STOP.")
    if disk.tran != "usb":
        raise BlockingError("NOT_USB_STORAGE", "destination is not USB storage")
    if disk.ro or any(p.ro for p in disk.partitions):
        raise BlockingError("DESTINATION_READ_ONLY", "destination is read-only at the block layer (it may be the "
                            "dirty source, which this tool sets read-only). STOP.")
    tail = serial_tail(disk)
    part = choose_partition(ctx, disk, DEST_FILESYSTEMS, "release")
    mounts = ctx.backend.mounts_of(part)
    show_identity(c, "CLEAN DESTINATION (will be written)", disk, part,
                  ", ".join(display_text(m.target) for m in mounts) or "(not mounted)")
    c.line("Only the %d approved files and a manifest/report will be written, into a new directory." % len(approved))
    c.confirm_phrase("WRITE %s" % tail, "Confirm this is the CLEAN destination by typing WRITE and the last 4 "
                                        "characters of its serial number.")
    identity = disk.identity()
    part_identity = asdict(part)
    attempt["destination"] = {"identity": identity, "partition": part_identity,
                              "by_id_path": ("/dev/disk/by-id/" + disk.preferred_by_id()) if disk.preferred_by_id() else ""}
    ctx.store.save_session(session)
    ctx.log.event("destination_confirmed", identity=identity, partition=part.kname)
    attempt["destination"]["automount_events"] = handle_existing_mounts(ctx, session, disk, "destination")
    ctx.backend.ensure_privilege(c)

    disk, part = revalidate(ctx, identity, part.kname, part_identity)
    if source_fp and matches_fingerprint(source_fp, disk):
        raise BlockingError("DESTINATION_IS_SOURCE", "device matches the dirty source identity")
    kfstype, rw_options = mount_options(part.fstype, "rw", ctx.uid, ctx.gid)
    target = prepare_mountpoint(ctx, "dest")
    ensure_not_mounted(ctx, part)
    root = ctx.backend.mount(part, kfstype, target, rw_options)
    writer = DestinationWriter(root, ctx.config["destination_dir_name"], session["run_id"])
    expected: Dict[str, str] = {}
    dest_paths: Dict[str, str] = {}
    try:
        attempt["mount_rw"] = ctx.backend.verify_mount(part, root, expect_ro=False)
        c.passed("DESTINATION MOUNTED (rw,nodev,nosuid,noexec)")
        total = sum(len(v) for v in payloads.values())
        if shutil.disk_usage(str(root)).free < total + 4 * 1024 * 1024:
            raise BlockingError("DESTINATION_SPACE", "not enough free space on the destination")
        attempt["destination"]["preexisting_root_entries"] = _inspect_destination_root(c, root)
        writer.open()
        attempt["transfer_dir"] = writer.transfer_dir
        ctx.store.save_session(session)
        for rec in approved:
            ctx.backend.notify("before_destination_write")
            revalidate(ctx, identity, part.kname, part_identity)
            data = payloads[rec["relative_path"]]
            if sha256_hex(data) != rec["approved_sha256"]:
                raise BlockingError("QUARANTINE_TAMPERED", "in-memory content changed unexpectedly")
            path = writer.write_file(rec["relative_path"], data)
            dest_paths[rec["relative_path"]] = path
            expected[path] = rec["sha256"]
            ctx.log.event("file_written", path=display_text(path), sha256=rec["sha256"])
        manifest = build_release_manifest(session, approved, dest_paths)
        sums = "".join("%s  %s\n" % (expected[p], p) for p in sorted(expected)).encode("utf-8")
        manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        preview = dict(session, release={"transfer_dir": writer.transfer_dir, "destination": attempt["destination"],
                                         "files_written": sorted(expected)})
        report = build_report(preview)
        report["post_write_verification"] = ("performed after this report was written (unmount, remount read-only, "
                                             "re-hash); the result is in the local report and can be repeated with verify-clean")
        report_json = (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii")
        report_txt = render_report_text(report).encode("utf-8")
        for sub, name, data in (("MANIFEST", "SHA256SUMS.txt", sums), ("MANIFEST", "manifest.json", manifest_bytes),
                                ("REPORTS", "transfer-report.txt", report_txt),
                                ("REPORTS", "transfer-report.json", report_json)):
            expected[writer.write_meta(sub, name, data)] = sha256_hex(data)
        revalidate(ctx, identity, part.kname, part_identity)
    finally:
        writer.close()
        try:
            os.sync()
        finally:
            ctx.backend.unmount_partition(part, target)
    if ctx.backend.mounts_of(part):
        raise BlockingError("UNMOUNT_FAILED", "destination is still mounted")
    ctx.backend.flush_buffers(part)
    c.passed("Files written, flushed, and destination unmounted.")
    ctx.backend.notify("after_destination_write")

    # Re-read from the device through a fresh read-only mount.
    disk, part = revalidate(ctx, identity, part.kname, part_identity)
    kfstype, ro_options = mount_options(part.fstype, "ro", ctx.uid, ctx.gid)
    ensure_not_mounted(ctx, part)
    root = ctx.backend.mount(part, kfstype, target, ro_options)
    try:
        attempt["mount_verify"] = ctx.backend.verify_mount(part, root, expect_ro=True)
        actual, anomalies = inventory_tree(root, writer.transfer_dir, max(ctx.config["max_file_bytes"], 16 * 1024 * 1024))
    finally:
        ctx.backend.unmount_partition(part, target)
    problems = compare_inventory(expected, actual, anomalies)
    verification = {"at": utc_now(), "files_checked": len(expected), "problems": problems,
                    "result": "PASS" if not problems else "MISMATCH"}
    attempt["verification"] = verification
    if problems:
        for p in problems:
            c.blocking(p)
        raise BlockingError("DESTINATION_VERIFICATION_MISMATCH",
                            "destination contents do not match what was written (%d problems)" % len(problems))
    return {"transfer_dir": writer.transfer_dir, "destination": attempt["destination"],
            "files_written": sorted(expected), "verification": verification, "completed_at": utc_now()}


def _inspect_destination_root(c: Console, root: Path) -> List[str]:
    try:
        rfd = open_dir_nofollow(str(root))
        try:
            names = sorted(os.listdir(rfd))
        finally:
            os.close(rfd)
    except OSError:
        return []
    ignore = {"system volume information", "lost+found"}
    others = [n for n in names if n.lower() not in ignore]
    if others:
        c.warn("The destination already contains %d other entries; they are not copied, read or verified." % len(others))
    if any(n.lower() in ("autorun.inf", "autorun.ini") for n in names):
        c.warn("The destination contains an autorun file. Consider erasing it with prepare-clean-usb.")
    return [display_text(n, 80) for n in others[:50]]


# ---------------------------------------------------------------------------
# Commands: verify-clean, prepare-clean-usb
# ---------------------------------------------------------------------------

def cmd_verify_clean(ctx: Context) -> int:
    c = ctx.console
    session = ctx.store.load_session()
    if session is not None:
        if bool(session.get("simulated")) != bool(ctx.backend.simulated):
            session = None
        else:
            ctx.attach_log(session["run_id"])
    c.heading("VERIFY CLEAN USB (read-only)")
    if session is not None and session["phase"] == PHASE_INGESTED:
        raise BlockingError("SOURCE_NOT_REMOVED", "dirty source removal has not been confirmed for the active session")
    disk = wait_for_single_removable(ctx, "Insert ONLY the CLEAN USB, then press Enter (q to stop): ",
                                     event="await_destination_insertion", ask_first=True)
    if session and session.get("source") and matches_fingerprint(session["source"]["identity"], disk):
        raise BlockingError("DESTINATION_IS_SOURCE", "this device matches the dirty source identity. STOP.")
    part = choose_partition(ctx, disk, DEST_FILESYSTEMS, "verification")
    show_identity(c, "CLEAN USB (read-only verification)", disk, part)
    c.confirm_phrase("YES", "Verify this device read-only?")
    identity, part_identity = disk.identity(), asdict(part)
    handle_existing_mounts(ctx, None, disk, "destination")
    ctx.backend.ensure_privilege(c)
    disk, part = revalidate(ctx, identity, part.kname, part_identity)
    kfstype, options = mount_options(part.fstype, "ro", ctx.uid, ctx.gid)
    target = prepare_mountpoint(ctx, "dest")
    ensure_not_mounted(ctx, part)
    root = ctx.backend.mount(part, kfstype, target, options)
    try:
        ctx.backend.verify_mount(part, root, expect_ro=True)
        rfd = open_dir_nofollow(str(root))
        try:
            dirs = sorted(n for n in os.listdir(rfd) if n.startswith(ctx.config["destination_dir_name"]))
        finally:
            os.close(rfd)
        if session and session.get("release") and session["release"]["transfer_dir"] in dirs:
            dirs = [session["release"]["transfer_dir"]]
        if not dirs:
            raise BlockingError("NO_TRANSFER_DIRECTORY", "no %s directory found" % ctx.config["destination_dir_name"])
        problems_total = 0
        results = []
        for tdir in dirs:
            actual, anomalies = inventory_tree(root, tdir, max(ctx.config["max_file_bytes"], 16 * 1024 * 1024))
            problems = list(anomalies)
            usb_sums = _read_usb_sums(root, tdir)
            files = {k: v for k, v in actual.items() if k.startswith("FILES/")}
            if usb_sums is None:
                problems.append("MANIFEST/SHA256SUMS.txt missing or unreadable")
            else:
                problems += compare_inventory(usb_sums.named, files, [])
            trusted_source = "the USB's own SHA256SUMS.txt (only as trustworthy as the USB itself)"
            if session and session.get("release") and session["release"]["transfer_dir"] == tdir:
                local = {"FILES/" + r["relative_path"]: r["sha256"] for r in session["files"] if r.get("approved")}
                problems += ["LOCAL SESSION: " + p for p in compare_inventory(local, files, [])]
                trusted_source = "the local session manifest and the USB's SHA256SUMS.txt"
            results.append({"transfer_dir": tdir, "problems": problems, "compared_against": trusted_source})
            problems_total += len(problems)
            if problems:
                for p in problems:
                    c.blocking("%s: %s" % (display_text(tdir), p))
            else:
                c.passed("DESTINATION HASH MATCH VERIFIED: %s (%d files, compared against %s)"
                         % (display_text(tdir), len(files), trusted_source))
    finally:
        ctx.backend.unmount_partition(part, target)
    if session is not None:
        session.setdefault("clean_verifications", []).append({"at": utc_now(), "device": identity, "results": results})
        ctx.store.save_session(session)
    if problems_total:
        raise BlockingError("DESTINATION_VERIFICATION_MISMATCH", "clean USB verification found %d problems" % problems_total)
    c.info("Clean USB unmounted; it can be removed.")
    return 0


def _read_usb_sums(root: Path, tdir: str) -> Optional[HashList]:
    try:
        rfd = open_dir_nofollow(str(root))
        try:
            tfd = open_dir_nofollow(tdir, dir_fd=rfd)
            try:
                mfd = open_dir_nofollow("MANIFEST", dir_fd=tfd)
                try:
                    fd = os.open("SHA256SUMS.txt", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=mfd)
                    try:
                        raw = read_bounded(fd, 1024 * 1024)
                    finally:
                        os.close(fd)
                finally:
                    os.close(mfd)
            finally:
                os.close(tfd)
        finally:
            os.close(rfd)
        hashes = parse_hash_text(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError):
        return None
    return None if hashes.errors else hashes


def cmd_prepare_clean_usb(ctx: Context) -> int:
    c = ctx.console
    c.heading("PREPARE CLEAN USB  (DESTRUCTIVE: erases the selected device)")
    session = ctx.store.load_session()
    if session is not None and bool(session.get("simulated")) == bool(ctx.backend.simulated):
        ctx.attach_log(session["run_id"])
        if session["phase"] in (PHASE_INGEST_IN_PROGRESS, PHASE_INGESTED):
            raise BlockingError("SOURCE_NOT_REMOVED", "dirty source removal has not been confirmed for the active session")
    else:
        session = None
    disk = wait_for_single_removable(ctx, "Insert ONLY the USB drive to ERASE, then press Enter (q to stop): ",
                                     event="await_destination_insertion", ask_first=True)
    if session and session.get("source") and matches_fingerprint(session["source"]["identity"], disk):
        raise BlockingError("DESTINATION_IS_SOURCE", "this device matches the dirty source identity. STOP.")
    if disk.tran != "usb":
        raise BlockingError("NOT_USB_STORAGE", "only USB storage can be prepared")
    if disk.ro or any(p.ro for p in disk.partitions):
        raise BlockingError("DESTINATION_READ_ONLY", "device is read-only at the block layer (possibly the dirty source)")
    tail = serial_tail(disk)
    show_identity(c, "DEVICE TO ERASE (all data will be destroyed)", disk)
    c.warn("ALL DATA ON THIS DEVICE WILL BE DESTROYED. It will receive one FAT32 partition labelled AIRLOCK.")
    c.confirm_phrase("ERASE %s" % tail, "Type ERASE and the last 4 characters of the serial number to confirm.")
    identity = disk.identity()
    handle_existing_mounts(ctx, None, disk, "destination")
    ctx.backend.ensure_privilege(c)
    disk, _ = revalidate(ctx, identity)
    ctx.log.event("prepare_clean_usb_start", identity=identity)
    part = ctx.backend.prepare_fat32(disk, "AIRLOCK")
    ctx.log.event("prepare_clean_usb_done", partition=part.kname)
    c.passed("FAT32 filesystem created on /dev/%s (label AIRLOCK). Desktop automount may now mount it; the "
             "airlock unmounts it before writing." % part.kname)
    return 0


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def _strip_private(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in rec.items() if not k.startswith("_")}


def build_report(session: Dict[str, Any]) -> Dict[str, Any]:
    files = [_strip_private(r) for r in session.get("files", [])]
    return {
        "application": {"name": APP_NAME, "version": APP_VERSION},
        "run_id": session["run_id"],
        "simulated": session.get("simulated", False),
        "generated_at": utc_now(),
        "started_at": session.get("created_at"),
        "last_updated_at": session.get("updated_at"),
        "phase": session.get("phase"),
        "environment": session.get("environment"),
        "network": session.get("network"),
        "source": session.get("source"),
        "scan": session.get("scan"),
        "quarantine": session.get("quarantine"),
        "files": files,
        "rejected": session.get("rejected", []),
        "trusted_hash_sources": session.get("trusted_hash_sources", []),
        "source_supplied_hash_lists": session.get("source_supplied_hash_lists", []),
        "clamav": session.get("clamav"),
        "release_attempts": session.get("release_attempts", []),
        "release": session.get("release"),
        "verification": session.get("verification"),
        "clean_verifications": session.get("clean_verifications", []),
        "warnings": session.get("warnings", []),
        "blocking": session.get("blocking", []),
        "statement": ("This report records the checks performed and their results. It does not establish that any "
                      "file is free of malicious content. Hashes without a trusted reference identify bytes; they "
                      "do not prove origin."),
    }


def render_report_text(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    add = lines.append
    env = report.get("environment") or {}
    add("MX USB TRANSFER AIRLOCK - TRANSFER REPORT")
    add("=" * 60)
    add("Application     : %s %s" % (APP_NAME, APP_VERSION))
    add("Run ID          : %s%s" % (report["run_id"], "  (SIMULATION)" if report.get("simulated") else ""))
    add("Phase           : %s" % report.get("phase"))
    add("Started         : %s" % report.get("started_at"))
    add("Report generated: %s" % report.get("generated_at"))
    add("")
    add("ENVIRONMENT (facts as observed)")
    add("  Distribution  : %s" % (env.get("os_release") or {}).get("PRETTY_NAME", "unknown"))
    add("  Kernel        : %s %s" % (env.get("kernel"), env.get("machine")))
    add("  PID 1         : %s" % env.get("pid1"))
    add("  Live env      : %s %s" % ("appears in use" if env.get("live_detected") else "NOT detected",
                                     ("(" + "; ".join(env.get("live_markers", [])) + ")") if env.get("live_markers") else ""))
    net = report.get("network") or {}
    add("  Network       : interfaces up: %s; default route: %s" % (
        ", ".join(net.get("interfaces_up", [])) or "none", net.get("default_route")))
    src = report.get("source") or {}
    if src:
        ident = src.get("identity", {})
        add("")
        add("SOURCE DEVICE (dirty, untrusted)")
        add("  Model/Vendor  : %s / %s" % (display_text(ident.get("model")), display_text(ident.get("vendor"))))
        add("  Serial        : %s" % (display_text(ident.get("serial")) or "(none)"))
        add("  Size          : %s bytes" % ident.get("size"))
        add("  By-id         : %s" % display_text(src.get("by_id_path")))
        part = src.get("partition") or {}
        add("  Filesystem    : %s UUID %s" % (display_text(part.get("fstype")), display_text(part.get("uuid"))))
        mount = src.get("mount") or {}
        add("  Mount options : %s" % mount.get("requested_options", "-"))
        ro = src.get("block_readonly") or {}
        add("  Block RO      : %s" % ("VERIFIED" if ro.get("verified") else "NOT VERIFIED"))
        for ev in src.get("automount_events", []) or []:
            add("  Automount     : %s at %s (%s)" % (ev["partition"], ev["target"], "rw" if ev["read_write"] else "ro"))
    add("")
    add("FILES QUARANTINED")
    for rec in report.get("files", []):
        add("  %s" % rec["relative_path_display"])
        add("      size %d  sha256 %s" % (rec["size"], rec["sha256"]))
        status = rec.get("hash_status")
        label = {HASH_MATCH: "PASS  INTEGRITY VERIFIED AGAINST TRUSTED HASH",
                 HASH_MISMATCH: "BLOCKING  TRUSTED HASH MISMATCH",
                 HASH_NOT_PREAUTHORIZED: "WARNING  NO TRUSTED SOURCE HASH AVAILABLE (HASH_NOT_PREAUTHORIZED)"}.get(status, status)
        add("      %s" % label)
        codes = sorted({f["code"] for f in rec.get("review_flags", []) if f["severity"] != SEV_INFO})
        if codes:
            add("      STATIC REVIEW FLAGS PRESENT: %s" % ", ".join(codes))
        add("      ClamAV: %s   Approved: %s" % (rec.get("clamav"), "yes" if rec.get("approved") else "no"))
    if not report.get("files"):
        add("  (none)")
    add("")
    add("LEFT BEHIND (rejected or skipped)")
    for rej in report.get("rejected", [])[:500]:
        add("  %s [%s]: %s" % (rej["relative_path_display"], rej["kind"], ", ".join(rej["reasons"])))
    if not report.get("rejected"):
        add("  (none)")
    clam = report.get("clamav") or {}
    add("")
    add("MALWARE SCAN")
    if clam.get("available"):
        add("  ClamAV %s, database %s (%s), exit %s" % (clam.get("version"), clam.get("database_version"),
                                                       clam.get("database_date"), clam.get("exit_code")))
        add("  A clean scan result is not proof that a file is benign.")
    else:
        add("  ClamAV not available or skipped (non-blocking).")
    for ts in report.get("trusted_hash_sources", []):
        add("  Trusted hash list: %s (%s entries, file sha256 %s) results %s" % (
            ts.get("path"), ts.get("entries"), ts.get("file_sha256"), ts.get("results")))
    rel = report.get("release")
    add("")
    add("RELEASE")
    if rel:
        dest = rel.get("destination") or {}
        ident = dest.get("identity", {})
        add("  Destination   : %s / %s serial %s" % (display_text(ident.get("model")), display_text(ident.get("vendor")),
                                                     display_text(ident.get("serial"))))
        add("  By-id         : %s" % display_text(dest.get("by_id_path")))
        add("  Directory     : %s" % rel.get("transfer_dir"))
        for path in rel.get("files_written", []):
            add("    wrote %s" % display_text(path))
    else:
        add("  not performed")
    ver = report.get("verification")
    if ver:
        if ver.get("result") == "PASS":
            add("  PASS  DESTINATION HASH MATCH VERIFIED (%d files re-read from a read-only mount)" % ver["files_checked"])
        else:
            add("  BLOCKING  DESTINATION VERIFICATION FAILED: %s" % "; ".join(ver.get("problems", [])))
    elif report.get("post_write_verification"):
        add("  Post-write verification: %s" % report["post_write_verification"])
    add("")
    add("WARNINGS")
    for w in report.get("warnings", []):
        add("  WARNING  %s: %s" % (w["code"], w["message"]))
    if not report.get("warnings"):
        add("  (none)")
    add("")
    add("BLOCKING FAILURES")
    for b in report.get("blocking", []):
        add("  BLOCKING  %s: %s" % (b["code"], b["message"]))
    if not report.get("blocking"):
        add("  (none)")
    add("")
    add(report["statement"])
    return "\n".join(lines) + "\n"


def write_local_reports(ctx: Context, session: Dict[str, Any]) -> Tuple[Path, Path]:
    report = build_report(session)
    base = ctx.store.root / "reports"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    unique = "%s-%s-%s" % (session["run_id"], stamp, secrets.token_hex(3))
    txt = base / ("transfer-report-%s.txt" % unique)
    js = base / ("transfer-report-%s.json" % unique)
    for path, payload in ((txt, render_report_text(report).encode("utf-8")),
                          (js, (json.dumps(report, indent=2, ensure_ascii=True) + "\n").encode("ascii"))):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
    return txt, js


def cmd_report(ctx: Context) -> int:
    session = load_session_checked(ctx)
    txt, js = write_local_reports(ctx, session)
    ctx.console.line(render_report_text(build_report(session)))
    ctx.console.info("Reports written: %s and %s" % (txt, js))
    return 0


# ---------------------------------------------------------------------------
# Commands: network and session housekeeping
# ---------------------------------------------------------------------------

def cmd_network_lockdown(ctx: Context) -> int:
    ctx.attach_log(None)
    describe_network(ctx.console, ctx.backend.network_state())
    do_network_lockdown(ctx, bool(ctx.arg("with_firewall")))
    describe_network(ctx.console, ctx.backend.network_state())
    return 0


def cmd_network_restore(ctx: Context) -> int:
    c = ctx.console
    ctx.attach_log(None)
    if not os.path.lexists(str(ctx.store.lockdown_path)):
        c.info("No saved lockdown state; nothing to restore.")
        return 0
    ctx.backend.ensure_privilege(c)
    result = ctx.backend.network_restore(ctx.store.lockdown_path)
    ctx.log.event("network_restore", failures=result["failures"])
    if result["failures"]:
        c.warn("Some actions could not be reverted: %s. Saved state kept at %s." % (result["failures"], ctx.store.lockdown_path))
        return 1
    _write_private_json(ctx.store.root / "archive" / ("network_lockdown-%s.json" % secrets.token_hex(4)),
                        _read_private_json(ctx.store.lockdown_path))
    os.unlink(ctx.store.lockdown_path)
    c.passed("Network state restored (%d actions reverted)." % result["restored_actions"])
    describe_network(c, result["after"])
    return 0


def cmd_discard_session(ctx: Context) -> int:
    c = ctx.console
    session = load_session_checked(ctx)
    c.confirm_phrase("DISCARD", "Discard session %s and delete its quarantined files?" % session["run_id"])
    ctx.store.archive_session(session)
    c.passed("Session archived and quarantine removed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

COMMANDS: Dict[str, Callable[[Context], int]] = {
    "status": cmd_status,
    "ingest": cmd_ingest,
    "review": cmd_review,
    "release": cmd_release,
    "verify-clean": cmd_verify_clean,
    "prepare-clean-usb": cmd_prepare_clean_usb,
    "report": cmd_report,
    "network-lockdown": cmd_network_lockdown,
    "network-restore": cmd_network_restore,
    "discard-session": cmd_discard_session,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock.py",
        description="MX USB transfer airlock: dirty USB -> read-only ingest -> quarantine -> removal -> "
                    "review -> clean USB -> verified release.")
    parser.add_argument("--version", action="version", version="%s %s" % (APP_NAME, APP_VERSION))
    parser.add_argument("--state-dir", help="private state/quarantine directory (default: tmpfs under XDG_RUNTIME_DIR or /dev/shm)")
    parser.add_argument("--config", help="inert JSON configuration file (see config.example.json)")
    parser.add_argument("--simulate", metavar="SCENARIO_JSON", help="practice mode with simulated devices (no real device access)")
    parser.add_argument("--live-device", action="append", default=[], metavar="BY_ID_PATH",
                        help="declare /dev/disk/by-id/... as live boot media so it is never selectable (repeatable)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show environment, devices and session state (read-only)")
    p = sub.add_parser("ingest", help="PHASE A: read-only ingest of the dirty USB into quarantine")
    p.add_argument("--trusted-hashes", help="operator-created trusted SHA-256 list (sha256sum text or JSON), NOT from the dirty USB")
    p.add_argument("--new-session", action="store_true", help="discard an unfinished session and start over")
    p.add_argument("--offline-lockdown", action="store_true", help="reversibly disable networking first")
    p.add_argument("--with-firewall", action="store_true", help="with --offline-lockdown: also add a temporary nftables drop policy")
    p = sub.add_parser("review", help="validate quarantined files and approve them for release")
    p.add_argument("--trusted-hashes", help="operator-created trusted SHA-256 list")
    p.add_argument("--list", dest="list_only", action="store_true", help="only list files and findings")
    p = sub.add_parser("release", help="PHASE B: write approved files to the clean USB and verify")
    p.add_argument("--offline-lockdown", action="store_true")
    p.add_argument("--with-firewall", action="store_true")
    sub.add_parser("verify-clean", help="re-verify a clean USB read-only")
    sub.add_parser("prepare-clean-usb", help="DESTRUCTIVE: erase a USB drive and create one FAT32 partition")
    sub.add_parser("report", help="print and save the text and JSON report")
    p = sub.add_parser("network-lockdown", help="reversibly disable networking (saves prior state)")
    p.add_argument("--with-firewall", action="store_true")
    sub.add_parser("network-restore", help="restore networking saved by a lockdown")
    sub.add_parser("discard-session", help="archive the current session and delete its quarantine")
    return parser


def resolve_live_devices(paths: List[str]) -> Set[str]:
    knames = set()
    for raw in paths:
        if not raw.startswith("/dev/disk/by-id/") or "/" in raw[len("/dev/disk/by-id/"):]:
            raise ConfigError("--live-device must be a /dev/disk/by-id/ path")
        real = os.path.realpath(raw)
        kname = os.path.basename(real)
        if os.path.dirname(real) != "/dev" or not KNAME_RE.match(kname):
            raise ConfigError("--live-device does not resolve to a block device: %s" % display_text(raw))
        knames.add(kname)
    return knames


def main(argv: Optional[List[str]] = None, console: Optional[Console] = None, backend: Any = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    console = console or Console()
    ctx: Optional[Context] = None
    try:
        config = load_config(args.config)
        if backend is None:
            if args.simulate:
                store_root = Path(args.state_dir) if args.state_dir else StateStore.default_root(simulated=True)
                source_removed = _peek_source_removed(store_root)
                backend = load_simulation_scenario(args.simulate, source_removed)
            else:
                if not sys.platform.startswith("linux"):
                    raise ConfigError("this tool runs on Linux only")
                backend = LinuxBackend(CommandRunner())
        store = StateStore(Path(args.state_dir) if args.state_dir else StateStore.default_root(backend.simulated))
        store.ensure()
        live = resolve_live_devices(args.live_device) if not backend.simulated else set()
        ctx = Context(console, backend, config, store, args, live)
        return COMMANDS[args.command](ctx)
    except BlockingError as exc:
        console.blocking("%s: %s" % (exc.code, exc))
        console.blocking("Processing stopped (fail closed). Nothing further was written.")
        if ctx is not None:
            ctx.log.event("blocking", code=exc.code, message=str(exc))
        return 1
    except OperatorCancelled as exc:
        console.warn("Cancelled: %s" % exc)
        return 2
    except (ConfigError, ToolMissing) as exc:
        console.blocking(str(exc))
        return 3
    except KeyboardInterrupt:
        console.warn("Interrupted.")
        return 2
    except Exception as exc:  # fail closed on anything unexpected
        console.blocking("INTERNAL ERROR (%s): %s. Processing stopped." % (type(exc).__name__, display_text(str(exc), 300)))
        if ctx is not None:
            ctx.log.event("internal_error", error=type(exc).__name__, trace=traceback.format_exc()[-4000:])
        return 1
    finally:
        if ctx is not None:
            ctx.log.close()


def _peek_source_removed(store_root: Path) -> bool:
    try:
        session = StateStore(store_root).load_session()
    except (BlockingError, OSError):
        return False
    return bool(session) and session.get("phase") in (PHASE_SOURCE_REMOVED, PHASE_RELEASED)


if __name__ == "__main__":
    sys.exit(main())
