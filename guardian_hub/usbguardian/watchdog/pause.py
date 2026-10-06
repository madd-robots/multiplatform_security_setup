# SPDX-License-Identifier: GPL-3.0-or-later
"""What a watchdog signal can do: pause write operations. Nothing else.

    watchdog.report  (watchdog.report)          one report from the watchdog's own account; the
                                                adapter turns it into signals, Guardian's fixed
                                                policy decides whether to pause
    watchdog.status  (runtime.status)           adapter, pauses, recent signals
    watchdog.resume  (watchdog.resume, 1 touch) the owner lifts every pause

Pause classes, and the operations they cover (``Operation.pause_class``):

    intake          vault.intake
    transfer_write  transfer.write, forge.write
    release         transfer.release
    device_modify   device.surface_test

A pause can only refuse operations. No signal can resume, grant a
capability, satisfy the owner factor, touch a lease or the trust log,
choose a device or a file, run anything, or start a destructive
operation. Verification, status, audit and lease operations are never
paused. Pauses survive a broker restart; a state file that cannot be read
pauses everything until the owner resumes (fail closed).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import GuardianError, PermissionDenied, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from .adapter import MAX_SIGNALS_PER_REPORT, SEVERITIES, SIGNAL_KINDS, DisabledAdapter, Signal, \
    WatchdogAdapter, check_signal

PAUSE_CLASSES = ("intake", "transfer_write", "release", "device_modify")
# Guardian's policy, not the watchdog's: only critical space signals pause, and they pause every
# class that writes. Warnings and notices are recorded only.
PAUSING = {("space_pressure", "critical"), ("fill_suspected", "critical")}
MAX_RECENT = 16

STATE_SPEC = S.Obj({
    "version": S.Const(1),
    "paused": S.List(S.Enum(PAUSE_CLASSES), max_items=len(PAUSE_CLASSES), unique=True),
    "since": S.Nullable(S.Int(min_value=0, max_value=2 ** 40)),
    "reason": S.Str(max_len=300),
    "recent": S.List(S.Obj({"time": S.Int(min_value=0, max_value=2 ** 40), "kind": S.Enum(SIGNAL_KINDS),
                            "severity": S.Enum(SEVERITIES), "detail": S.Str(max_len=300)}),
                     max_items=MAX_RECENT),
})


class PauseController:
    def __init__(self, directory: Path, *, adapter: Optional[WatchdogAdapter] = None, audit: Optional[Any] = None,
                 clock: Callable[[], int] = lambda: int(time.time())):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.path = self.directory / "state.json"
        self.adapter = adapter if adapter is not None else DisabledAdapter()
        self.audit = audit
        self.clock = clock
        self._lock = threading.Lock()
        self.state = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "paused": [], "since": None, "reason": "", "recent": []}
        try:
            doc = canonical_loads(read_file_bounded(self.path, 64 * 1024, require_private=True),
                                  require_canonical=True, max_bytes=64 * 1024)
            return S.validate(STATE_SPEC, doc, "$.watchdog_state")
        except GuardianError:
            return {"version": 1, "paused": list(PAUSE_CLASSES), "since": self.clock(),
                    "reason": "watchdog pause state unreadable; paused until the owner resumes", "recent": []}

    def _save(self, state: Dict[str, Any]) -> None:
        atomic_write(self.path, canonical_dumps(state))
        self.state = state

    # -- broker gate ---------------------------------------------------------------------------

    def check(self, op: Operation) -> None:
        if op.pause_class is not None and op.pause_class in self.state["paused"]:
            raise PermissionDenied("%s is paused by a watchdog alert (%s); the owner can resume"
                                   % (op.name, self.state["reason"]), code="WATCHDOG_PAUSED")

    # -- operations ----------------------------------------------------------------------------

    def report(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        if params["adapter"] != self.adapter.name or not self.adapter.enabled:
            raise ValidationError("report is not for the configured watchdog adapter", code="WATCHDOG_DISABLED")
        try:
            translated = list(self.adapter.translate(params["payload"]))[:MAX_SIGNALS_PER_REPORT + 1]
        except GuardianError:
            raise
        except Exception:
            raise ValidationError("watchdog report could not be translated", code="WATCHDOG_REPORT_INVALID") from None
        if len(translated) > MAX_SIGNALS_PER_REPORT:
            raise ValidationError("too many signals in one report")
        signals: List[Signal] = [check_signal(s) for s in translated]
        with self._lock:
            now = self.clock()
            state = dict(self.state, paused=list(self.state["paused"]), recent=list(self.state["recent"]))
            newly: List[str] = []
            for sig in signals:
                state["recent"] = (state["recent"] + [dict(sig.to_document(), time=now)])[-MAX_RECENT:]
                if (sig.kind, sig.severity) in PAUSING:
                    newly += [c for c in PAUSE_CLASSES if c not in state["paused"] and c not in newly]
            if newly:
                state["paused"] = [c for c in PAUSE_CLASSES if c in state["paused"] or c in newly]
                state["since"] = state["since"] or now
                first = next(s for s in signals if (s.kind, s.severity) in PAUSING)
                state["reason"] = "%s %s from %s" % (first.severity, first.kind, self.adapter.name)
            # The pause applies in memory first: when the disk is full, saving (or the audit
            # entry) may fail, and the pause must hold regardless.
            self.state = state
            self._save(state)
            if self.audit is not None:
                self.audit.append("watchdog.report", adapter=self.adapter.name, principal=principal.name,
                                  signals=[s.to_document() for s in signals], paused=newly)
            return {"accepted": len(signals), "paused": state["paused"], "newly_paused": newly}

    def status(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        with self._lock:
            return {"adapter": self.adapter.name, "enabled": self.adapter.enabled, "paused": self.state["paused"],
                    "since": self.state["since"], "reason": self.state["reason"], "recent": self.state["recent"]}

    def resume(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        with self._lock:
            lifted = list(self.state["paused"])
            if self.audit is not None:
                self.audit.append("watchdog.resume", principal=principal.name, lifted=lifted)
            self._save(dict(self.state, paused=[], since=None, reason=""))
            return {"lifted": lifted}

    def operations(self) -> Iterable[Operation]:
        return (
            Operation("watchdog.report", "watchdog.report",
                      S.Obj({"adapter": S.Str(pattern=r"[a-z][a-z0-9-]{0,31}", max_len=32), "payload": S.Any_()}),
                      inline=self.report),
            Operation("watchdog.status", "runtime.status", S.EMPTY, inline=self.status),
            Operation("watchdog.resume", "watchdog.resume", S.EMPTY, inline=self.resume),
        )
