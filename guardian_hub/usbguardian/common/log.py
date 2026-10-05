# SPDX-License-Identifier: GPL-3.0-or-later
"""Structured logging foundation.

Events are JSON lines with a fixed shape:

    {"ts": ..., "level": ..., "logger": ..., "event": ..., "fields": {...}}

Rules enforced here, not left to callers:

* fields whose name looks secret (key, token, pin, passphrase, ...) are
  redacted, and binary values are never logged, only their length
* untrusted strings are truncated and rendered as escaped ASCII, so a hostile
  device label cannot forge log lines or inject terminal escapes
* exceptions are logged as type and error code; tracebacks only on request
* log files are created 0600 with O_NOFOLLOW and size-rotated
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import stat
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import GuardianError, SecurityViolation
from .text import display_text

ROOT_LOGGER = "usbguardian"
EVENT_RE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_FIELD_TEXT = 512
MAX_FIELDS = 64
MAX_NESTING = 4
REDACTED = "<redacted>"

_SECRET_WORDS = frozenset({
    "secret", "secrets", "password", "passwd", "passphrase", "token", "tokens", "private", "credential",
    "credentials", "pin", "puk", "otp", "seed", "mnemonic", "cookie", "dek", "kek", "plaintext",
    "key", "keys", "privkey", "apikey", "signature_key", "hmac",
})
# Field names containing "key" as a word that are safe identifiers, not material.
_SAFE_KEY_FIELDS = frozenset({"key_id", "key_epoch", "key_slot", "key_label", "key_fingerprint",
                              "public_key_fingerprint", "key_count"})


def is_secret_field(name: str) -> bool:
    lowered = name.lower()
    if lowered in _SAFE_KEY_FIELDS:
        return False
    words = re.split(r"[_\-.]+", lowered)
    return any(w in _SECRET_WORDS for w in words) or "password" in lowered or "secret" in lowered


def sanitize_value(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "<binary len=%d redacted>" % len(bytes(value))
    if depth >= MAX_NESTING:
        return "<nested value omitted>"
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for i, (k, v) in enumerate(value.items()):
            if i >= MAX_FIELDS:
                out["_omitted"] = len(value) - MAX_FIELDS
                break
            name = display_text(k, 64)
            out[name] = REDACTED if is_secret_field(name) else sanitize_value(v, depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        out_list = [sanitize_value(v, depth + 1) for v in items[:MAX_FIELDS]]
        if len(items) > MAX_FIELDS:
            out_list.append("<%d more omitted>" % (len(items) - MAX_FIELDS))
        return out_list
    return display_text(value, MAX_FIELD_TEXT)


def _utc_iso(created: float) -> str:
    dt = datetime.datetime.fromtimestamp(created, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def _record_fields(record: logging.LogRecord) -> Dict[str, Any]:
    fields = getattr(record, "guardian_fields", None)
    return fields if isinstance(fields, dict) else {}


def _exception_info(record: logging.LogRecord, include_traceback: bool) -> Optional[Dict[str, Any]]:
    if not record.exc_info or record.exc_info[1] is None:
        return None
    exc = record.exc_info[1]
    info: Dict[str, Any] = {"type": type(exc).__name__}
    if isinstance(exc, GuardianError):
        info["code"] = exc.code
    if include_traceback:
        info["traceback"] = display_text(logging.Formatter().formatException(record.exc_info), 8000)
    return info


class JsonLineFormatter(logging.Formatter):
    def __init__(self, include_traceback: bool = False):
        super().__init__()
        self.include_traceback = include_traceback

    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, str) and EVENT_RE.match(record.msg) else "message"
        entry: Dict[str, Any] = {
            "ts": _utc_iso(record.created),
            "level": record.levelname,
            "logger": display_text(record.name, 64),
            "event": event,
            "fields": sanitize_value(_record_fields(record)),
        }
        if event == "message":
            entry["fields"]["text"] = display_text(record.getMessage(), MAX_FIELD_TEXT)
        exc = _exception_info(record, self.include_traceback)
        if exc:
            entry["exception"] = exc
        # ensure_ascii keeps every log line printable ASCII.
        return json.dumps(entry, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event = record.msg if isinstance(record.msg, str) and EVENT_RE.match(record.msg) else None
        fields = sanitize_value(_record_fields(record))
        head = "%s %s" % (record.levelname, event or display_text(record.getMessage(), MAX_FIELD_TEXT))
        parts = ["%s=%s" % (k, display_text(json.dumps(v, ensure_ascii=True, sort_keys=True), 200))
                 for k, v in sorted(fields.items())]
        exc = _exception_info(record, False)
        if exc:
            parts.append("exception=%s" % exc["type"] + ("/" + exc["code"] if "code" in exc else ""))
        return head + (" " + " ".join(parts) if parts else "")


class PrivateFileHandler(logging.Handler):
    """Append-only 0600 log file with size-based rotation."""

    def __init__(self, path: Path, *, max_bytes: int = 5 * 1024 * 1024, backups: int = 3,
                 include_traceback: bool = False):
        super().__init__()
        if max_bytes < 4096 or not 0 <= backups <= 20:
            raise ValueError("invalid rotation settings")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups
        self._io_lock = threading.Lock()
        self._fd = self._open()
        self.setFormatter(JsonLineFormatter(include_traceback))

    def _open(self) -> int:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise SecurityViolation("cannot open log file %s: %s" % (display_text(self.path), exc.strerror),
                                    code="LOG_INVALID") from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            os.close(fd)
            raise SecurityViolation("log file %s is not a private regular file" % display_text(self.path),
                                    code="LOG_INVALID")
        return fd

    def _rotate(self) -> None:
        os.close(self._fd)
        self._fd = -1
        try:
            if self.backups == 0:
                os.truncate(self.path, 0)
            else:
                for i in range(self.backups - 1, 0, -1):
                    src = Path("%s.%d" % (self.path, i))
                    if os.path.lexists(src):
                        os.replace(src, "%s.%d" % (self.path, i + 1))
                os.replace(self.path, "%s.1" % self.path)
        finally:
            # Keep logging even if a rename failed.
            self._fd = self._open()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = (self.format(record) + "\n").encode("ascii", "replace")
            with self._io_lock:
                if self._fd < 0:
                    return
                if os.fstat(self._fd).st_size + len(line) > self.max_bytes:
                    self._rotate()
                os.write(self._fd, line)
        except Exception:  # logging must never take the caller down
            self.handleError(record)

    def close(self) -> None:
        with self._io_lock:
            if self._fd >= 0:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = -1
        super().close()


def get_logger(name: str = "") -> logging.Logger:
    if name and not re.fullmatch(r"[a-z][a-z0-9_.]{0,63}", name):
        raise ValueError("invalid logger name")
    return logging.getLogger(ROOT_LOGGER + ("." + name if name else ""))


def log_event(logger: logging.Logger, level: int, event: str, *, exc_info: Any = None, **fields: Any) -> None:
    """Log a structured event.  ``event`` is a fixed identifier, never data."""
    if not EVENT_RE.match(event):
        raise ValueError("invalid event name")
    for name in fields:
        if not FIELD_NAME_RE.match(name):
            raise ValueError("invalid field name")
    logger.log(level, event, extra={"guardian_fields": fields}, exc_info=exc_info)


def configure_logging(log_file: Optional[Path] = None, *, level: int = logging.INFO, console: bool = True,
                      include_traceback: bool = False) -> logging.Logger:
    """Install Guardian handlers on the ``usbguardian`` logger (idempotent)."""
    root = logging.getLogger(ROOT_LOGGER)
    for handler in list(root.handlers):
        if getattr(handler, "_guardian_handler", False):
            root.removeHandler(handler)
            handler.close()
    root.setLevel(level)
    root.propagate = False
    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(ConsoleFormatter())
        ch._guardian_handler = True  # type: ignore[attr-defined]
        root.addHandler(ch)
    if log_file is not None:
        fh = PrivateFileHandler(log_file, include_traceback=include_traceback)
        fh._guardian_handler = True  # type: ignore[attr-defined]
        root.addHandler(fh)
    return root
