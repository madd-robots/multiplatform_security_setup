# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 9 terminal UI tests: escaping, every screen, controller actions, a real broker, and a curses smoke run."""

import os
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.sshsig import tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.runtime.session import Session  # noqa: E402
from usbguardian.ui import actions  # noqa: E402
from usbguardian.ui.app import Controller  # noqa: E402
from usbguardian.ui.model import ORDER  # noqa: E402
from usbguardian.ui.views import render  # noqa: E402

HOSTILE = "\x1b[2J\x1b]0;owned\x07Evil‮TXT.exe\r\nfake line"
DEVICE = {"kname": "sdb", "transport": "usb", "size_bytes": 8 * 2 ** 30, "vendor": HOSTILE, "model": HOSTILE,
          "usb_id": "0781:5583", "fingerprint": "f" * 64, "candidate": True, "blocking": []}


def ok(result):
    return {"ok": True, "result": result}


SAMPLE = {
    "status": ok({"version": "0.2.0", "principal": "owner", "capabilities": ["a"], "factors": []}),
    "trust": ok({"initialized": True, "anchor": "a" * 64, "head": "b" * 64, "seq": 1,
                 "active": [{"key_id": "sha256-" + "c" * 64, "label": HOSTILE, "serial": None,
                             "key_type": "sk-ssh-ed25519@openssh.com", "openssh_fingerprint": "SHA256:x",
                             "enrolled_seq": 0}], "revoked": []}),
    "lease": {"ok": False, "code": "NOT_FOUND", "message": "not available on this instance"},
    "forge": ok({"deployments": [{"instance_id": "desk", "platform": "debian-mx", "profile": "storage",
                                  "status": "active", "lease": {"generation": 1, "not_after": 1800000000}}]}),
    "watchdog": ok({"adapter": "disabled", "enabled": False, "paused": [], "since": None, "reason": "",
                    "recent": [{"time": 1, "kind": "notice", "severity": "info", "detail": HOSTILE}]}),
    "audit": ok({"head_seq": 41, "head": "d" * 64, "checkpoint_digest": "e" * 64, "namespace": "x"}),
    "devices": ok({"devices": [DEVICE]}),
    "jobs": ok({"jobs": [{"kname": "sdb", "fingerprint": "f" * 64, "phase": "write", "done": 1, "total": 4,
                          "started": 0}]}),
    "drives": ok({"drives": []}),
    "airlock": ok({"sessions": [{"session_id": "20261007T000000Z-00000000", "state": "inspected", "items": 2,
                                 "skipped": 1, "states": {"PASS": 1, "BLOCKED": 1}}]}),
    "records": ok({"total": 1, "records": [{"record_id": "0" * 32, "sha256": "1" * 64, "length": 10,
                                            "source_name": HOSTILE, "intake_time": "2026-10-07T00:00:00Z"}]}),
    "reports": ok({"reports": [{"report_id": "2" * 24, "kind": "device_assurance", "created": "2026-10-07T00:00:00Z",
                                "result": "PASS", "subject": {"kname": HOSTILE}}]}),
}


def screen_data(screen):
    from usbguardian.ui.model import SCREENS
    return {sec: SAMPLE[sec] for sec, _op, _p in SCREENS[screen]}


class ViewTests(unittest.TestCase):
    def check(self, lines, width, height):
        self.assertEqual(len(lines), height)
        for line in lines:
            self.assertLessEqual(len(line), width)
            self.assertTrue(line.isascii() and line.isprintable(), repr(line))
            self.assertNotIn("\x1b", line)

    def test_every_screen_escapes_and_fits(self):
        for screen in ORDER:
            for width, height in ((120, 40), (40, 10)):
                with self.subTest(screen=screen, size=(width, height)):
                    lines = render(screen, screen_data(screen), width=width, height=height, message=HOSTILE,
                                   selected=0)
                    self.check(lines, width, height)
        text = "\n".join(render("vault", screen_data("vault"), width=200, height=30))
        self.assertIn("\\x1b", text)  # shown escaped, not executed
        self.assertIn("\\u202e", text)

    def test_unavailable_sections_and_bad_data(self):
        missing = {sec: {"ok": False, "code": "PERMISSION_DENIED", "message": "not permitted for this user"}
                   for sec in SAMPLE}
        for screen in ORDER:
            from usbguardian.ui.model import SCREENS
            data = {sec: missing[sec] for sec, _o, _p in SCREENS[screen]}
            self.check(render(screen, data, width=100, height=20), 100, 20)
        broken = {"devices": ok({"devices": [{"kname": 5}]}), "jobs": ok({"jobs": []}), "drives": ok({"drives": []})}
        lines = render("devices", broken, width=100, height=20)
        self.assertTrue(any("could not be displayed" in line for line in lines))


class FakeClient:
    def __init__(self):
        self.calls = []

    def call(self, op, params=None, fds=()):
        self.calls.append(op)
        from usbguardian.ui.model import SCREENS
        for screen in SCREENS.values():
            for sec, o, _p in screen:
                if o == op:
                    item = SAMPLE[sec]
                    if not item["ok"]:
                        raise E.GuardianError(item["message"], code=item["code"])
                    return item["result"]
        if op == "assurance.device":
            return {"report_id": "3" * 24, "result": "PASS", "body": {"registry": "UNKNOWN"}}
        if op == "device.cancel":
            return {"cancelling": True}
        if op == "audit.entries":
            return {"entries": []}
        raise E.NotFound("unknown operation")


class ControllerTests(unittest.TestCase):
    def controller(self, answer="", signer=None):
        self.client = FakeClient()
        self.notices = []
        return Controller(self.client, signer, lambda q: answer, self.notices.append)

    def test_navigation_and_read_only_actions(self):
        c = self.controller()
        self.assertIn("Read-only", c.message)
        for i in range(1, len(ORDER) + 1):
            c.on_key(str(i))
            self.assertEqual(c.screen, ORDER[i - 1])
            c.lines(100, 30)
        c.on_key("2")
        c.on_key("a")
        self.assertIn("report 333333333333333333333333: PASS", c.message)
        c.on_key("c")
        self.assertEqual(c.message, "cancel requested")
        c.on_key("e")
        self.assertIn("--auth", c.message)  # no signer: no owner operations
        self.assertNotIn("device.surface_test", self.client.calls)
        self.assertFalse(c.on_key("q"))

    def test_erase_needs_typed_name_and_owner(self):
        calls = []
        original = actions.call_as_owner
        actions.call_as_owner = lambda client, signer, op, params, fds=(): calls.append((op, params)) or {
            "result": {"cancelled": False, "passed": True}, "report_id": "4" * 24}
        try:
            c = self.controller(answer="sdc", signer=object())
            c.on_key("2")
            c.on_key("e")
            self.assertEqual(c.message, "erase-verify cancelled")
            self.assertEqual(calls, [])
            c = self.controller(answer="sdb", signer=object())
            c.on_key("2")
            c.on_key("e")
            self.assertEqual(calls, [("device.surface_test", {"kname": "sdb", "fingerprint": "f" * 64})])
            self.assertIn("PASSED", c.message)
            self.assertTrue(any("Touch the YubiKey" in n for n in self.notices))
        finally:
            actions.call_as_owner = original


class LocalClient:
    """One in-process 'connection' to a real broker, with the session a socket connection would have."""

    def __init__(self, broker):
        self.broker = broker
        self.session = Session(os.geteuid(), os.getegid(), os.getpid())
        self.n = 0

    def call(self, op, params=None, fds=()):
        self.n += 1
        principal = authz.Principal("owner", os.geteuid(), frozenset(authz.CAPABILITIES), frozenset({"peer_uid"}))
        resp = self.broker.handle(principal, {"v": 1, "type": "request", "id": "u%d" % self.n, "op": op,
                                              "params": params or {}}, self.session)
        if not resp["ok"]:
            raise E.error_from_wire(resp["error"])
        return resp["result"]


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class BrokerUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        cls.A = _keygen(Path(cls._keys.name), "a")

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def setUp(self):
        from test_runtime import launcher
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o755)
        self.services = build_services(launcher(), self.root / "state", sig_check=tool_verify,
                                       allowed_key_types=TEST_TYPES)
        self.services.trust.append(EN.genesis([(self.A, "A", None)]))

    def tearDown(self):
        self.tmp.cleanup()

    def test_screens_and_owner_actions_against_a_real_broker(self):
        c = Controller(LocalClient(self.services.broker), self.A, lambda q: "", lambda n: None)
        for i in range(1, len(ORDER) + 1):
            c.on_key(str(i))
            for line in c.lines(120, 40):
                self.assertTrue(line.isascii() and line.isprintable())
        c.on_key("8")
        c.on_key("v")
        self.assertIn("audit chain intact", c.message)
        c.on_key("k")
        self.assertIn("checkpoint signed", c.message)
        c.on_key("v")
        self.assertIn("1 checkpoint(s)", c.message)
        c.on_key("9")
        c.on_key("R")
        self.assertEqual(c.message, "lifted: nothing was paused")
        c.on_key("8")
        self.assertIn("watchdog.resume        lifted=[]", "\n".join(c.lines(160, 60)))  # audit viewer, newest page

    def test_curses_smoke_in_a_pseudo_terminal(self):
        policy = authz.Policy([("owner", os.geteuid(), sorted(authz.CAPABILITIES))])
        server = BrokerServer(self.services.broker, policy, self.root / "b.sock", idle_timeout=60.0)
        server.bind()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        master, slave = os.openpty()
        env = {"TERM": "xterm", "PATH": "/usr/bin:/bin", "LINES": "30", "COLUMNS": "120"}
        proc = subprocess.Popen([sys.executable, "-I", "-B", str(ROOT / "guardian.py"), "ui", "--socket",
                                 str(self.root / "b.sock")], stdin=slave, stdout=slave, stderr=slave, env=env,
                                close_fds=True)
        os.close(slave)
        seen = b""
        try:
            deadline = time.monotonic() + 20
            sent = False
            while time.monotonic() < deadline and proc.poll() is None:
                ready, _, _ = select.select([master], [], [], 0.5)
                if ready:
                    try:
                        seen += os.read(master, 65536)
                    except OSError:
                        break
                if not sent and b"Dashboard" in seen and b"Owner keys" in seen:
                    os.write(master, b"8")
                    time.sleep(0.5)
                    os.write(master, b"q")
                    sent = True
            proc.wait(timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()
            os.close(master)
            server.stop()
            thread.join(5)
        self.assertEqual(proc.returncode, 0, seen[-2000:])
        self.assertIn(b"Ledger head", seen)


if __name__ == "__main__":
    unittest.main()
