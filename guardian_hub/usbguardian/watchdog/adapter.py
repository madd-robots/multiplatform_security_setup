# SPDX-License-Identifier: GPL-3.0-or-later
"""Signals and the adapter protocol.

A ``Signal`` is Guardian's vocabulary, not the watchdog's format. Its
fields are closed enumerations plus a short display text, so whatever an
adapter receives, the only thing it can hand to Guardian is "this kind of
pressure, this severity". There is no field for a path, a device, a
command, a key, a lease or a capability, and so no way to ask for one.

Data reaching an adapter is untrusted (the reporting process may itself be
compromised, and fields such as file names come from an attacker filling
the disk). An adapter must bound and validate it; ``check_signal``
re-validates every signal the adapter returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Protocol

from ..common.errors import GuardianError, ValidationError
from ..common.text import display_text

SIGNAL_KINDS = ("space_pressure", "fill_suspected", "notice")
SEVERITIES = ("info", "warning", "critical")
MAX_SIGNALS_PER_REPORT = 16
MAX_DETAIL = 200


@dataclass(frozen=True)
class Signal:
    kind: str
    severity: str
    detail: str = ""

    def to_document(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "detail": self.detail}


def check_signal(value: Any) -> Signal:
    if type(value) is not Signal:  # exact type: no subclass smuggling extra behaviour
        raise ValidationError("adapter returned something other than a Signal")
    if value.kind not in SIGNAL_KINDS or value.severity not in SEVERITIES or not isinstance(value.detail, str):
        raise ValidationError("adapter returned an invalid signal")
    return Signal(value.kind, value.severity, display_text(value.detail, MAX_DETAIL))


class WatchdogAdapter(Protocol):
    name: str
    enabled: bool

    def translate(self, payload: Any) -> List[Signal]:
        """Turn one report from the watchdog into signals, or raise ValidationError."""


class WatchdogDisabled(GuardianError):
    code = "WATCHDOG_DISABLED"


class DisabledAdapter:
    """The default: no watchdog is integrated, and reports are refused."""

    name = "disabled"
    enabled = False

    def translate(self, payload: Any) -> List[Signal]:
        raise WatchdogDisabled("no watchdog adapter is configured; reports are refused")
