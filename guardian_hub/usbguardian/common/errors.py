# SPDX-License-Identifier: GPL-3.0-or-later
"""Error hierarchy.

Every expected failure carries a stable machine-readable ``code``.  Codes and
sanitized messages are what crosses process boundaries (IPC, reports); Python
tracebacks and exception internals never do.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Type

from .text import display_text

ERROR_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
MAX_WIRE_MESSAGE = 500


class GuardianError(Exception):
    """Base class for expected, reportable failures."""

    code = "GUARDIAN_ERROR"

    def __init__(self, message: str, *, code: Optional[str] = None):
        super().__init__(message)
        if code is not None:
            if not isinstance(code, str) or not ERROR_CODE_RE.match(code):
                raise ValueError("invalid error code")
            self.code = code
        self.message = message

    def to_wire(self) -> Dict[str, str]:
        return {"code": self.code, "message": display_text(self.message, MAX_WIRE_MESSAGE)}


class ValidationError(GuardianError):
    """Input was rejected; nothing was changed."""

    code = "VALIDATION_FAILED"


class ConfigError(GuardianError):
    code = "CONFIG_INVALID"


class NotFound(GuardianError):
    code = "NOT_FOUND"


class PermissionDenied(GuardianError):
    code = "PERMISSION_DENIED"


class ResourceLimitExceeded(GuardianError):
    code = "RESOURCE_LIMIT"


class OperationTimeout(GuardianError):
    code = "TIMEOUT"


class WorkerFailure(GuardianError):
    code = "WORKER_FAILED"


class InternalError(GuardianError):
    code = "INTERNAL_ERROR"


class SecurityViolation(GuardianError):
    """A security-critical condition.  Processing stops (fail closed)."""

    code = "SECURITY_VIOLATION"


class IntegrityError(SecurityViolation):
    code = "INTEGRITY_FAILURE"


class ProtocolError(SecurityViolation):
    """A peer sent malformed or out-of-contract data."""

    code = "PROTOCOL_ERROR"


_WIRE_CLASSES: Dict[str, Type[GuardianError]] = {
    cls.code: cls for cls in (
        GuardianError, ValidationError, ConfigError, NotFound, PermissionDenied,
        ResourceLimitExceeded, OperationTimeout, WorkerFailure, InternalError,
        SecurityViolation, IntegrityError, ProtocolError,
    )
}


def error_from_wire(obj: Any) -> GuardianError:
    """Rebuild an error received from a peer.

    The peer is not trusted: an unknown code keeps its value but maps to the
    base class, and anything malformed becomes a ProtocolError.
    """
    if (not isinstance(obj, dict) or set(obj) != {"code", "message"}
            or not isinstance(obj["code"], str) or not isinstance(obj["message"], str)
            or not ERROR_CODE_RE.match(obj["code"])):
        return ProtocolError("peer sent a malformed error object")
    message = display_text(obj["message"], MAX_WIRE_MESSAGE)
    cls = _WIRE_CLASSES.get(obj["code"], GuardianError)
    return cls(message, code=obj["code"])


def as_guardian_error(exc: BaseException) -> GuardianError:
    """Map any exception to a reportable error without leaking internals."""
    if isinstance(exc, GuardianError):
        return exc
    if isinstance(exc, MemoryError):
        return ResourceLimitExceeded("out of memory")
    return InternalError("internal error (%s)" % type(exc).__name__)
