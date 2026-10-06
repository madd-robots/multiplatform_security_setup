# SPDX-License-Identifier: GPL-3.0-or-later
"""Watchdog boundary tests: disabled by default, pause-only effect, owner-only resume.

FixtureAdapter's payload format is a test fixture. It is not, and does not
guess, the real watchdog's interface (which does not exist yet).
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.identity.sshsig import tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.watchdog.adapter import Signal  # noqa: E402
from usbguardian.watchdog.pause import PAUSE_CLASSES  # noqa: E402

ALL_CAPS = sorted(authz.CAPABILITIES)


class FixtureAdapter:
    name = "fixture"
    enabled = True

    def translate(self, payload):
        if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
            raise E.ValidationError("fixture payload malformed")
        return [Signal(e["k"], e["s"], e.get("d", "")) for e in payload["events"]]


class HostileAdapter:
    name = "hostile"
    enabled = True

    def __init__(self, result):
        self.result = result

    def translate(self, payload):
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class SneakySignal(Signal):
    pass


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        from test_runtime import launcher
        self.launcher = launcher()
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state"
        self.ids = 0

    def tearDown(self):
        self.tmp.cleanup()

    def services(self, adapter=None):
        return build_services(self.launcher, self.state, sig_check=tool_verify, watchdog_adapter=adapter)

    def call(self, svc, op, params=None, caps=ALL_CAPS, factors=("peer_uid",)):
        self.ids += 1
        principal = authz.Principal("p", os.geteuid(), frozenset(caps), frozenset(factors))
        resp = svc.broker.handle(principal, {"v": 1, "type": "request", "id": "r%d" % self.ids, "op": op,
                                             "params": params if params is not None else {}})
        if not resp["ok"]:
            raise E.error_from_wire(resp["error"])
        return resp["result"]

    def report(self, svc, *events, adapter="fixture"):
        return self.call(svc, "watchdog.report", {"adapter": adapter, "payload": {"events": list(events)}},
                         caps=["watchdog.report"])

    def surface_code(self, svc):
        try:
            self.call(svc, "device.surface_test", {"kname": "sdz", "fingerprint": "0" * 64},
                      factors=("peer_uid", "owner_key"))
        except E.GuardianError as exc:
            return exc.code
        return "OK"

    def test_disabled_by_default(self):
        svc = self.services()
        self.assertEqual(self.call(svc, "watchdog.status")["enabled"], False)
        with self.assertRaises(E.GuardianError) as cm:
            self.report(svc, {"k": "fill_suspected", "s": "critical"}, adapter="disabled")
        self.assertEqual(cm.exception.code, "WATCHDOG_DISABLED")
        self.assertEqual(self.call(svc, "watchdog.status")["paused"], [])
        self.assertNotEqual(self.surface_code(svc), "WATCHDOG_PAUSED")  # Guardian works without it

    def test_only_critical_space_signals_pause_and_only_writes(self):
        svc = self.services(FixtureAdapter())
        out = self.report(svc, {"k": "space_pressure", "s": "warning", "d": "92% used"}, {"k": "notice", "s": "critical"})
        self.assertEqual(out["paused"], [])
        self.assertNotEqual(self.surface_code(svc), "WATCHDOG_PAUSED")
        out = self.report(svc, {"k": "fill_suspected", "s": "critical", "d": "/home growing 2 GiB/min"})
        self.assertEqual(out["paused"], list(PAUSE_CLASSES))
        self.assertEqual(self.surface_code(svc), "WATCHDOG_PAUSED")
        paused_ops = sorted(op.name for op in svc.broker.operations.values()
                            if op.pause_class is not None and op.pause_class in out["paused"])
        self.assertEqual(paused_ops, ["device.surface_test", "forge.write", "transfer.release",
                                      "transfer.write", "vault.intake"])
        for op in svc.broker.operations.values():
            if op.pause_class is None:
                svc.watchdog.check(op)  # verification, status, trust, lease, audit: never paused
        self.call(svc, "audit.verify")
        self.call(svc, "runtime.status")

    def test_resume_needs_the_owner(self):
        svc = self.services(FixtureAdapter())
        self.report(svc, {"k": "space_pressure", "s": "critical"})
        self.report(svc, {"k": "notice", "s": "info"})  # no signal can lift a pause
        self.assertEqual(self.call(svc, "watchdog.status")["paused"], list(PAUSE_CLASSES))
        with self.assertRaises(E.PermissionDenied):
            self.call(svc, "watchdog.resume")  # no touch
        with self.assertRaises(E.PermissionDenied):  # the watchdog's own account cannot resume
            self.call(svc, "watchdog.resume", caps=["watchdog.report"], factors=("peer_uid", "owner_key"))
        self.assertEqual(self.call(svc, "watchdog.resume", factors=("peer_uid", "owner_key"))["lifted"],
                         list(PAUSE_CLASSES))
        self.assertNotEqual(self.surface_code(svc), "WATCHDOG_PAUSED")
        self.assertIn("watchdog.resume", [r["entry"]["event"] for r in svc.audit.entries(0, 200)])
        self.assertNotIn(authz.FACTOR_OWNER_KEY, authz.CAPABILITIES["watchdog.report"].required_factors)
        self.assertIn(authz.FACTOR_OWNER_KEY, authz.CAPABILITIES["watchdog.resume"].required_factors)

    def test_hostile_adapter_output_refused(self):
        cases = [
            [{"kind": "fill_suspected", "severity": "critical"}],          # not a Signal
            [SneakySignal("fill_suspected", "critical")],                   # subclass
            [Signal("erase_device", "critical")],                           # unknown kind
            [Signal("fill_suspected", "apocalyptic")],                      # unknown severity
            [Signal("notice", "info")] * 17,                                # too many
            RuntimeError("adapter bug"),                                    # crash
        ]
        for result in cases:
            with self.subTest(result=repr(result)[:60]):
                svc = self.services(HostileAdapter(result))
                with self.assertRaises(E.GuardianError):
                    self.call(svc, "watchdog.report", {"adapter": "hostile", "payload": {}}, caps=["watchdog.report"])
                self.assertEqual(self.call(svc, "watchdog.status")["paused"], [])
        svc = self.services(HostileAdapter([Signal("notice", "info", "\x1b[2Jfake\nlog line")]))
        self.call(svc, "watchdog.report", {"adapter": "hostile", "payload": {}}, caps=["watchdog.report"])
        detail = self.call(svc, "watchdog.status")["recent"][-1]["detail"]
        self.assertNotIn("\x1b", detail)
        self.assertNotIn("\n", detail)
        with self.assertRaises(E.GuardianError):  # a report addressed to another adapter
            self.call(svc, "watchdog.report", {"adapter": "fixture", "payload": {}}, caps=["watchdog.report"])

    def test_pause_survives_restart_and_fails_closed(self):
        svc = self.services(FixtureAdapter())
        self.report(svc, {"k": "fill_suspected", "s": "critical"})
        self.assertEqual(self.surface_code(self.services()), "WATCHDOG_PAUSED")  # even with the adapter gone
        (self.state / "watchdog" / "state.json").write_bytes(b"garbage")
        status = self.call(self.services(), "watchdog.status")
        self.assertEqual(status["paused"], list(PAUSE_CLASSES))
        self.assertIn("unreadable", status["reason"])

    def test_pause_holds_when_the_disk_is_full(self):
        svc = self.services(FixtureAdapter())

        def full(state):
            raise OSError(28, "No space left on device")
        svc.watchdog._save = full
        with self.assertRaises(E.GuardianError):
            self.report(svc, {"k": "space_pressure", "s": "critical"})
        self.assertEqual(self.surface_code(svc), "WATCHDOG_PAUSED")


if __name__ == "__main__":
    unittest.main()
