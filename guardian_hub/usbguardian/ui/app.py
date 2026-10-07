# SPDX-License-Identifier: GPL-3.0-or-later
"""The terminal UI loop.  ``Controller`` holds the state and handles keys; ``run`` draws it with curses.

Start it with ``guardian.py ui --socket S [--auth KEY.pub HANDLE]``. Without
--auth the UI is read-only apart from the operations the broker allows
without a touch (assurance reports, cancelling an erase, verifying the
audit chain).
"""

from __future__ import annotations

import curses
from typing import Any, Callable, Dict, List, Optional

from ..common.errors import GuardianError, ProtocolError
from . import actions
from .model import ORDER, audit_page, collect, fetch
from .views import render

AUDIT_ROWS = 20


class Controller:
    def __init__(self, client: Any, signer: Optional[Any], prompt: Callable[[str], str],
                 notice: Callable[[str], None]):
        self.client = client
        self.signer = signer
        self.prompt = prompt
        self.notice = notice
        self.screen = "dashboard"
        self.selected = 0
        self.audit_offset = 0
        self.detail: Optional[Dict[str, Any]] = None
        self.message = "Guardian UI. Owner operations need a YubiKey touch." + (
            "" if signer else " Read-only: started without --auth.")
        self.data: Dict[str, Dict[str, Any]] = {}
        self.page: Optional[Dict[str, Any]] = None
        self.refresh()

    # -- data ------------------------------------------------------------------------------------

    def refresh(self) -> None:
        self.data = collect(self.client, self.screen)
        if self.screen == "audit":
            head = (self.data.get("audit") or {}).get("result")
            self.page = audit_page(self.client, head["head_seq"], self.audit_offset, AUDIT_ROWS) if head else None
        rows = self._rows()
        self.selected = min(self.selected, max(len(rows) - 1, 0))

    def _rows(self) -> List[Dict[str, Any]]:
        key = {"devices": ("devices", "devices"), "vault": ("records", "records"),
               "airlock": ("airlock", "sessions"), "reports": ("reports", "reports")}.get(self.screen)
        if key is None:
            return []
        sec = self.data.get(key[0]) or {}
        return (sec.get("result") or {}).get(key[1], []) if sec.get("ok") else []

    def current(self) -> Optional[Dict[str, Any]]:
        rows = self._rows()
        return rows[self.selected] if 0 <= self.selected < len(rows) else None

    def lines(self, width: int, height: int) -> List[str]:
        return render(self.screen, self.data, width=width, height=height, message=self.message,
                      selected=self.selected, detail=self.detail, page=self.page)

    # -- keys ------------------------------------------------------------------------------------

    def on_key(self, key: str) -> bool:
        """Handle one key; returns False to quit."""
        if key == "q":
            return False
        if key.isdigit() and 1 <= int(key) <= len(ORDER):
            self.screen, self.selected, self.detail, self.audit_offset = ORDER[int(key) - 1], 0, None, 0
        elif key == "\t":
            self.screen = ORDER[(ORDER.index(self.screen) + 1) % len(ORDER)]
            self.selected, self.detail, self.audit_offset = 0, None, 0
        elif key in ("up", "k") and self.screen != "audit":
            self.selected = max(self.selected - 1, 0)
            self.detail = None
        elif key in ("down", "j"):
            self.selected += 1
            self.detail = None
        elif key == "pgup" and self.screen == "audit":
            self.audit_offset += AUDIT_ROWS
        elif key == "pgdn" and self.screen == "audit":
            self.audit_offset = max(self.audit_offset - AUDIT_ROWS, 0)
        elif key == "r":
            pass
        else:
            self.message = self._action(key) or self.message
        self.refresh()
        return True

    def _action(self, key: str) -> Optional[str]:
        row = self.current()
        if self.screen == "devices" and row is not None:
            if key == "a":
                return actions.assurance_report(self.client, row["kname"])
            if key == "e":
                return actions.erase_verify(self.client, self.signer, row, self.prompt, self.notice)
            if key == "c":
                return actions.cancel_erase(self.client, row["kname"])
        if self.screen == "airlock" and row is not None and key == "enter":
            out = fetch(self.client, "airlock.session", {"session_id": row["session_id"], "since": 0, "limit": 64})
            self.detail = out["result"] if out["ok"] else None
            return None if out["ok"] else out["message"]
        if self.screen == "reports" and row is not None:
            if key == "enter":
                out = fetch(self.client, "assurance.report", {"report_id": row["report_id"]})
                self.detail = out["result"] if out["ok"] else None
                return None if out["ok"] else out["message"]
            if key == "s":
                return actions.sign_report(self.client, self.signer, row["report_id"], self.notice)
        if self.screen == "audit":
            if key == "v":
                return actions.verify_audit(self.client)
            if key == "k" and self.signer is not None:
                return actions.checkpoint_audit(self.client, self.signer, self.notice)
        if self.screen == "watchdog" and key == "R":
            return actions.resume_watchdog(self.client, self.signer, self.notice)
        return None


class ReconnectingClient:
    """Keeps the UI alive across broker restarts: a lost connection is reopened and the call reported failed."""

    def __init__(self, factory: Callable[[], Any]):
        self.factory = factory
        self.client = factory()
        self.client.connect()

    def call(self, op: str, params: Optional[Dict[str, Any]] = None, fds: Any = ()) -> Any:
        try:
            return self.client.call(op, params or {}, fds)
        except (OSError, ProtocolError):
            try:
                self.client.close()
            except OSError:
                pass
            self.client = self.factory()
            try:
                self.client.connect()
            except OSError:
                raise GuardianError("broker unreachable", code="BROKER_UNREACHABLE") from None
            raise GuardianError("connection to the broker was lost and reopened; try again",
                                code="RECONNECTED") from None

    def close(self) -> None:
        self.client.close()


KEYMAP = {curses.KEY_UP: "up", curses.KEY_DOWN: "down", curses.KEY_PPAGE: "pgup", curses.KEY_NPAGE: "pgdn",
          10: "enter", 13: "enter", curses.KEY_ENTER: "enter", 9: "\t"}


def run(stdscr: Any, client: Any, signer: Optional[Any], refresh_seconds: float = 2.0) -> None:
    curses.curs_set(0)
    stdscr.timeout(int(refresh_seconds * 1000))

    def draw(lines: List[str]) -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        for i, line in enumerate(lines[:height]):
            try:
                stdscr.addnstr(i, 0, line, max(width - 1, 1))
            except curses.error:
                pass
        stdscr.refresh()

    def notice(text: str) -> None:
        height, width = stdscr.getmaxyx()
        lines = controller.lines(width, height)
        lines[-1] = text[:width - 1]
        draw(lines)

    def prompt(text: str) -> str:
        height, width = stdscr.getmaxyx()
        notice(text)
        curses.echo()
        curses.curs_set(1)
        stdscr.timeout(-1)
        try:
            raw = stdscr.getstr(height - 1, min(len(text), width - 34), 32)
        finally:
            curses.noecho()
            curses.curs_set(0)
            stdscr.timeout(int(refresh_seconds * 1000))
        return raw.decode("ascii", "replace") if isinstance(raw, bytes) else ""

    controller = Controller(client, signer, prompt, notice)
    while True:
        height, width = stdscr.getmaxyx()
        draw(controller.lines(width, height))
        code = stdscr.getch()
        if code == -1:
            try:
                controller.refresh()
            except GuardianError as exc:
                controller.message = "refresh failed: %s" % exc.code
            continue
        key = KEYMAP.get(code) or (chr(code) if 32 <= code < 127 else "")
        if key and not controller.on_key(key):
            return
