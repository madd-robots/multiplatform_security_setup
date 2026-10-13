# SPDX-License-Identifier: GPL-3.0-or-later
"""Data for each screen.  Every call is independent: one failing section never hides the others."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..common.errors import GuardianError

# screen -> [(section, operation, params)]
SCREENS: Dict[str, List[Tuple[str, str, Dict[str, Any]]]] = {
    "dashboard": [("status", "runtime.status", {}), ("trust", "trust.status", {}), ("lease", "lease.status", {}),
                  ("forge", "forge.list", {}), ("watchdog", "watchdog.status", {}), ("audit", "audit.status", {}),
                  ("devices", "device.list", {}), ("jobs", "device.jobs", {}), ("airlock", "airlock.sessions", {}),
                  ("reports", "assurance.reports", {"since": 0, "limit": 64})],
    "devices": [("devices", "device.list", {}), ("jobs", "device.jobs", {}), ("drives", "assurance.drives", {})],
    "keys": [("trust", "trust.status", {})],
    "vault": [("records", "vault.records", {"since": 0, "limit": 128})],
    "airlock": [("airlock", "airlock.sessions", {})],
    "forge": [("forge", "forge.list", {}), ("lease", "lease.status", {})],
    "reports": [("reports", "assurance.reports", {"since": 0, "limit": 64})],
    "audit": [("audit", "audit.status", {})],
    "watchdog": [("watchdog", "watchdog.status", {})],
}
ORDER = ("dashboard", "devices", "keys", "vault", "airlock", "forge", "reports", "audit", "watchdog")


def fetch(client: Any, op: str, params: Dict[str, Any]) -> Dict[str, Any]:
    try:
        return {"ok": True, "result": client.call(op, params)}
    except GuardianError as exc:
        reason = {"NOT_FOUND": "not available on this instance",
                  "PERMISSION_DENIED": "not permitted for this user"}.get(exc.code, exc.message)
        return {"ok": False, "code": exc.code, "message": reason}


def collect(client: Any, screen: str) -> Dict[str, Dict[str, Any]]:
    return {section: fetch(client, op, params) for section, op, params in SCREENS[screen]}


def audit_page(client: Any, head_seq: int, offset: int, rows: int) -> Dict[str, Any]:
    """Entries ending ``offset`` entries before the head (offset 0 = newest page)."""
    end = max(head_seq - offset, -1)
    start = max(end - rows + 1, 0)
    if end < 0:
        return {"ok": True, "result": {"entries": []}}
    return fetch(client, "audit.entries", {"since": start, "limit": min(rows, 64)})
