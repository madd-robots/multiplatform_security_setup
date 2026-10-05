# SPDX-License-Identifier: GPL-3.0-or-later
"""The broker: validate, authorize, dispatch, answer.

For every request, in this order and with no shortcuts:

1. the envelope must match the protocol schema
2. the operation must exist in the broker's fixed table
3. the kernel-identified principal must hold the operation's capability
   (and any factor the capability requires)
4. the parameters must match the operation's schema
5. the operation runs inline (small trusted logic) or in a fresh worker
6. the result must be canonical and fit in one frame

Every authorization decision and every outcome is logged.  Parameters and
results are not logged, since they may carry sensitive data.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional

from .. import APP_NAME, APP_VERSION
from ..common.errors import (GuardianError, NotFound, PermissionDenied, ResourceLimitExceeded,
                             as_guardian_error)
from ..common.log import get_logger, log_event
from . import authz, ipc
from . import schema as S
from .workers import WorkerLauncher, WorkerProfile

InlineFunc = Callable[[authz.Principal, Dict[str, Any]], Any]


@dataclass(frozen=True)
class Operation:
    name: str
    capability: str
    params: S.Spec
    inline: Optional[InlineFunc] = None
    worker_handler: Optional[str] = None
    profile: Optional[WorkerProfile] = None

    def __post_init__(self) -> None:
        if self.capability not in authz.CAPABILITIES:
            raise ValueError("operation %s uses unknown capability %s" % (self.name, self.capability))
        if (self.inline is None) == (self.worker_handler is None):
            raise ValueError("operation %s needs exactly one of inline or worker_handler" % self.name)
        if self.worker_handler is not None and self.profile is None:
            raise ValueError("worker operation %s needs a profile" % self.name)


def _status(principal: authz.Principal, params: Dict[str, Any]) -> Any:
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "protocol": ipc.PROTOCOL_VERSION,
        "principal": principal.name,
        "capabilities": sorted(principal.granted),
        "factors": sorted(principal.factors),
    }


def default_operations() -> Iterable[Operation]:
    diag = WorkerProfile(name="diagnostics", cpu_seconds=2, memory_bytes=256 * 1024 * 1024, wall_timeout=10.0)
    return (
        Operation("runtime.status", "runtime.status", S.EMPTY, inline=_status),
        Operation("runtime.echo", "runtime.diagnostics", S.Obj({"value": S.Str(max_len=4096)}),
                  worker_handler="runtime.echo", profile=diag),
        Operation("runtime.sandbox_report", "runtime.diagnostics", S.EMPTY,
                  worker_handler="runtime.sandbox_report", profile=diag),
    )


class Broker:
    def __init__(self, operations: Iterable[Operation], launcher: WorkerLauncher, *,
                 max_concurrent_workers: int = 4, logger: Optional[logging.Logger] = None):
        self.operations: Dict[str, Operation] = {}
        for op in operations:
            if op.name in self.operations:
                raise ValueError("operation %s defined twice" % op.name)
            self.operations[op.name] = op
        self.launcher = launcher
        self.logger = logger or get_logger("broker")
        self._worker_slots = threading.BoundedSemaphore(max_concurrent_workers)

    def handle(self, principal: authz.Principal, message: Any) -> Dict[str, Any]:
        """Answer one request.  Never raises; every failure becomes an error response."""
        request_id = "invalid"
        op_name = "invalid"
        started = time.monotonic()
        if isinstance(message, dict):
            candidate = message.get("id")
            if isinstance(candidate, str) and re.fullmatch(ipc.REQUEST_ID_PATTERN, candidate):
                request_id = candidate
        try:
            request = S.validate(ipc.REQUEST_SPEC, message)
            op_name = request["op"]
            op = self.operations.get(op_name)
            if op is None:
                raise NotFound("unknown operation")
            decision = authz.decide(principal, op.capability)
            log_event(self.logger, logging.INFO if decision.allowed else logging.WARNING, "authz.decision",
                      principal=principal.name, uid=principal.uid, op=op_name, capability=op.capability,
                      allowed=decision.allowed, reason=decision.reason, request_id=request_id)
            if not decision.allowed:
                raise PermissionDenied("operation requires %s (%s)" % (op.capability, decision.reason))
            params = S.validate(op.params, request["params"], "$.params")
            result = self._execute(op, principal, params)
            response = ipc.ok_response(request_id, result)
            ipc.encode_frame(response)  # result must be canonical and fit in a frame
            outcome = "OK"
        except Exception as exc:
            err = as_guardian_error(exc)
            if not isinstance(exc, GuardianError):
                log_event(self.logger, logging.ERROR, "broker.internal_error", op=op_name,
                          request_id=request_id, exc_info=exc)
            response = ipc.error_response(request_id, err)
            outcome = err.code
        log_event(self.logger, logging.INFO, "op.completed", principal=principal.name, op=op_name,
                  request_id=request_id, outcome=outcome, ms=int((time.monotonic() - started) * 1000))
        return response

    def _execute(self, op: Operation, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        if op.inline is not None:
            return op.inline(principal, params)
        assert op.worker_handler is not None and op.profile is not None
        if not self._worker_slots.acquire(timeout=5):
            raise ResourceLimitExceeded("too many concurrent workers")
        try:
            return self.launcher.run(op.profile, op.worker_handler, params)
        finally:
            self._worker_slots.release()
