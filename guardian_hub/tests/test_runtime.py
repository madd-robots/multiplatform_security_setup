# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 2 security runtime tests.

When the suite runs as root, workers drop to uid/gid 65534 (the real
production path, which needs a root-owned code tree).  As a normal user they
run under the same uid in development mode.  Both paths apply the same
resource limits and process flags.
"""

import logging
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_dumps  # noqa: E402
from usbguardian.runtime import authz, ipc  # noqa: E402
from usbguardian.runtime import schema as S  # noqa: E402
from usbguardian.runtime.broker import Broker, Operation, default_operations  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.sandbox import SandboxProfile  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.runtime.workers import WorkerLauncher, WorkerProfile  # noqa: E402

UNPRIVILEGED = 65534
logging.getLogger("usbguardian").addHandler(logging.NullHandler())
logging.getLogger("usbguardian").propagate = False

_LAUNCHER = None
_LAUNCHER_ERROR = None


def launcher():
    global _LAUNCHER, _LAUNCHER_ERROR
    if _LAUNCHER is None and _LAUNCHER_ERROR is None:
        try:
            if os.geteuid() == 0:
                _LAUNCHER = WorkerLauncher(worker_uid=UNPRIVILEGED, worker_gid=UNPRIVILEGED,
                                           enable_test_handlers=True)
            else:
                _LAUNCHER = WorkerLauncher(enable_test_handlers=True)
        except E.GuardianError as exc:
            _LAUNCHER_ERROR = exc
    if _LAUNCHER is None:
        raise unittest.SkipTest("worker launcher unavailable here: %s" % _LAUNCHER_ERROR)
    return _LAUNCHER


def principal(*caps, factors=("peer_uid",)):
    return authz.Principal("tester", 1000, frozenset(caps), frozenset(factors))


class SchemaTests(unittest.TestCase):
    def test_types_are_strict(self):
        with self.assertRaises(E.ValidationError):
            S.Int(min_value=0, max_value=5).check(True, "$")
        with self.assertRaises(E.ValidationError):
            S.Bool().check(1, "$")
        with self.assertRaises(E.ValidationError):
            S.Const(1).check(True, "$")
        with self.assertRaises(E.ValidationError):
            S.Str(pattern=r"[a-z]+").check("abc\n", "$")
        with self.assertRaises(E.ValidationError):
            S.List(S.Int(min_value=0, max_value=9), unique=True).check([1, 1], "$")

    def test_objects(self):
        spec = S.Obj({"a": S.Int(min_value=0, max_value=9), "b": S.Str()}, optional=["b"])
        self.assertEqual(spec.check({"a": 1}, "$"), {"a": 1})
        for bad in ({}, {"a": 1, "c": 2}, {"a": "1"}, [], None):
            with self.assertRaises(E.ValidationError):
                spec.check(bad, "$")
        with self.assertRaises(ValueError):
            S.Obj({"a": S.Str()}, optional=["zzz"])


class IpcTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_roundtrip(self):
        msg = ipc.make_request("r1", "runtime.status", {"x": [1, "y"]})
        ipc.send_frame(self.a.fileno(), msg)
        self.assertEqual(ipc.recv_frame(self.b.fileno(), timeout=2), msg)

    def test_clean_eof_and_truncation(self):
        self.a.shutdown(socket.SHUT_WR)
        self.assertIsNone(ipc.recv_frame(self.b.fileno(), timeout=2, allow_eof=True))
        a2, b2 = socket.socketpair()
        a2.sendall(struct.pack(">I", 10) + b"{}")
        a2.close()
        with self.assertRaises(E.ProtocolError):
            ipc.recv_frame(b2.fileno(), timeout=2, allow_eof=True)
        b2.close()

    def test_rejects_bad_frames(self):
        cases = [
            struct.pack(">I", 0),
            struct.pack(">I", ipc.MAX_FRAME + 1),
            struct.pack(">I", 3) + b"1.5",
            struct.pack(">I", 8) + b'{"b":1, }',
            struct.pack(">I", 13) + b'{"b":1,"a":2}',  # not canonical
            struct.pack(">I", 13) + b'{"a":1,"a":2}',  # duplicate key
        ]
        for raw in cases:
            a, b = socket.socketpair()
            a.sendall(raw)
            with self.assertRaises(E.ProtocolError, msg=repr(raw)):
                ipc.recv_frame(b.fileno(), timeout=2)
            a.close()
            b.close()

    def test_timeout_on_silent_or_slow_peer(self):
        with self.assertRaises(E.OperationTimeout):
            ipc.recv_frame(self.b.fileno(), timeout=0.2)
        self.a.sendall(struct.pack(">I", 100) + b"{")
        with self.assertRaises(E.OperationTimeout):
            ipc.recv_frame(self.b.fileno(), timeout=0.2)

    def test_oversized_send_refused(self):
        with self.assertRaises(E.ResourceLimitExceeded):
            ipc.encode_frame({"x": "a" * 100}, max_frame=50)

    def test_request_envelope(self):
        for bad in (("bad id", "a.b", {}), ("ok", "noprefix", {}), ("ok", "A.b", {}), ("x" * 65, "a.b", {})):
            with self.assertRaises(E.ValidationError):
                ipc.make_request(*bad)

    def test_validate_response(self):
        ok = ipc.ok_response("r", {"a": 1})
        self.assertEqual(ipc.validate_response(ok), ok)
        err = ipc.error_response("r", E.NotFound("x"))
        self.assertEqual(ipc.validate_response(err)["error"]["code"], "NOT_FOUND")
        for bad in ({}, dict(ok, extra=1), dict(ok, ok=1), dict(err, error={"code": "bad"}), dict(ok, v=2)):
            with self.assertRaises(E.ProtocolError):
                ipc.validate_response(bad)


class AuthzTests(unittest.TestCase):
    def test_policy_and_decisions(self):
        policy = authz.Policy.from_document({"version": 1, "principals": [
            {"name": "operator", "uid": 1000, "capabilities": ["runtime.status", "device.inspect", "vault.read"]},
        ]})
        self.assertIsNone(policy.principal_for_uid(0))  # root gets nothing implicitly
        self.assertIsNone(policy.principal_for_uid(1001))
        p = policy.principal_for_uid(1000)
        self.assertEqual(p.factors, frozenset({"peer_uid"}))
        self.assertTrue(authz.decide(p, "device.inspect").allowed)
        self.assertEqual(authz.decide(p, "device.modify").reason, "CAPABILITY_NOT_GRANTED")
        self.assertEqual(authz.decide(p, "vault.read").reason, "FACTOR_REQUIRED")
        self.assertEqual(authz.decide(p, "nope.nope").reason, "UNKNOWN_CAPABILITY")
        self.assertTrue(authz.decide(p.with_factor("owner_key"), "vault.read").allowed)
        with self.assertRaises(E.PermissionDenied):
            authz.require(p, "vault.read")
        with self.assertRaises(ValueError):
            p.with_factor("made_up")

    def test_owner_capabilities_require_owner_key(self):
        for name in ("device.modify", "vault.read", "vault.write", "keys.manage", "forge.build"):
            self.assertIn("owner_key", authz.CAPABILITIES[name].required_factors, name)

    def test_invalid_policies(self):
        bad_docs = [
            {"version": 2, "principals": []},
            {"version": 1, "principals": [{"name": "a", "uid": 1, "capabilities": ["root.everything"]}]},
            {"version": 1, "principals": [{"name": "a", "uid": 1, "capabilities": []},
                                          {"name": "b", "uid": 1, "capabilities": []}]},
            {"version": 1, "principals": [{"name": "a", "uid": 1, "capabilities": []},
                                          {"name": "a", "uid": 2, "capabilities": []}]},
            {"version": 1, "principals": [{"name": "a", "uid": True, "capabilities": []}]},
            {"version": 1, "principals": [{"name": "a", "uid": 1, "capabilities": [], "admin": True}]},
            {"version": 1, "principals": [{"name": "a", "uid": 1,
                                           "capabilities": ["runtime.status", "runtime.status"]}]},
        ]
        for doc in bad_docs:
            with self.assertRaises(E.ConfigError, msg=repr(doc)):
                authz.Policy.from_document(doc)

    def test_policy_file_must_be_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            path = Path(tmp) / "policy.json"
            path.write_bytes(canonical_dumps({"version": 1, "principals": [
                {"name": "me", "uid": os.geteuid(), "capabilities": ["runtime.status"]}]}))
            os.chmod(path, 0o644)
            owners = (0, os.geteuid())
            self.assertIsNotNone(authz.Policy.load(path, allowed_owners=owners).principal_for_uid(os.geteuid()))
            os.chmod(path, 0o664)
            with self.assertRaises(E.SecurityViolation):
                authz.Policy.load(path, allowed_owners=owners)
            os.chmod(path, 0o644)
            path.write_bytes(b'{"version":1,"version":1,"principals":[]}')
            with self.assertRaises(E.ConfigError):
                authz.Policy.load(path, allowed_owners=owners)


class SandboxProfileTests(unittest.TestCase):
    def test_profile_validation(self):
        good = {"name": "p", "cpu_seconds": 1, "memory_bytes": 64 * 1024 * 1024, "max_open_files": 8,
                "max_file_size": 0, "allow_subprocess": False, "run_as_uid": None, "run_as_gid": None,
                "io_timeout": 1, "test_handlers": False}
        SandboxProfile.from_document(good)
        for change in ({"run_as_uid": 0, "run_as_gid": 0}, {"run_as_uid": 5}, {"cpu_seconds": 0},
                       {"extra": 1}, {"memory_bytes": 1}):
            with self.assertRaises(E.GuardianError, msg=repr(change)):
                SandboxProfile.from_document(dict(good, **change))

    def test_launcher_refuses_root_workers(self):
        with self.assertRaises(E.ConfigError):
            WorkerLauncher(worker_uid=0, worker_gid=0)
        with self.assertRaises(E.ConfigError):
            WorkerLauncher(worker_uid=UNPRIVILEGED)
        if os.geteuid() == 0:
            with self.assertRaises(E.ConfigError):
                WorkerLauncher()
        else:
            with self.assertRaises(E.ConfigError):
                WorkerLauncher(worker_uid=os.geteuid() + 1, worker_gid=os.getegid())


class WorkerTests(unittest.TestCase):
    profile = WorkerProfile(name="test", cpu_seconds=2, memory_bytes=256 * 1024 * 1024, wall_timeout=10.0)

    def setUp(self):
        self.launcher = launcher()

    def run_handler(self, handler, params=None, profile=None):
        return self.launcher.run(profile or self.profile, handler, params or {})

    def test_echo(self):
        self.assertEqual(self.run_handler("runtime.echo", {"value": "h\u00e9llo"}), {"value": "h\u00e9llo"})

    def test_sandbox_state(self):
        r = self.run_handler("runtime.sandbox_report")
        self.assertEqual(r["no_new_privs"], 1)
        self.assertEqual(r["dumpable"], 0)
        self.assertEqual(r["umask"], 0o077)
        self.assertEqual(r["cwd"], "/")
        self.assertEqual(r["env_keys"], ["LC_ALL", "PATH"])
        self.assertTrue(0 < r["open_fds"] <= 5, r["open_fds"])
        self.assertEqual(r["limits"]["core"], {"soft": 0, "hard": 0})
        self.assertEqual(r["limits"]["fsize"], {"soft": 0, "hard": 0})
        self.assertEqual(r["limits"]["nproc"], {"soft": 0, "hard": 0})
        self.assertEqual(r["limits"]["cpu"]["soft"], 2)
        self.assertEqual(r["limits"]["as"]["soft"], 256 * 1024 * 1024)
        self.assertNotIn(0, r["uid"])
        if os.geteuid() == 0:
            self.assertEqual(r["uid"], [UNPRIVILEGED] * 3)
            self.assertEqual(r["gid"], [UNPRIVILEGED] * 3)
            self.assertEqual(r["groups"], [])
            self.assertEqual(r["cap_eff"], "0000000000000000")
            self.assertEqual(self.run_handler("test.regain_root"), {"regained": False})

    def test_cpu_limit(self):
        with self.assertRaises(E.ResourceLimitExceeded):
            self.run_handler("test.spin", profile=WorkerProfile(name="cpu", cpu_seconds=1, wall_timeout=20.0))

    def test_wall_timeout_kills_worker(self):
        started = time.monotonic()
        with self.assertRaises(E.OperationTimeout):
            self.run_handler("test.sleep", {"seconds": 60}, WorkerProfile(name="slow", wall_timeout=1.0))
        self.assertLess(time.monotonic() - started, 10)

    def test_memory_limit(self):
        with self.assertRaises(E.ResourceLimitExceeded):
            self.run_handler("test.allocate", {"mib": 1024})
        self.assertEqual(self.run_handler("test.allocate", {"mib": 16}), {"allocated": 16 * 1024 * 1024})

    def test_output_flood_bounded(self):
        with self.assertRaises(E.ResourceLimitExceeded):
            self.run_handler("test.flood", {"mib": 64})

    def test_stderr_flood_bounded_and_sanitized(self):
        with self.assertLogs("usbguardian.workers", level="WARNING") as cm:
            self.assertEqual(self.run_handler("test.stderr_flood", {"mib": 2}), {})
        record = cm.records[0]
        self.assertLessEqual(len(record.guardian_fields["stderr"]), 2100)
        self.assertNotIn("\x1b", record.guardian_fields["stderr"])

    def test_cannot_write_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o777)
            target = os.path.join(tmp, "out")
            with self.assertRaises(E.GuardianError):
                self.run_handler("test.write_file", {"path": target})
            self.assertTrue(not os.path.exists(target) or os.path.getsize(target) == 0)

    def test_cannot_fork(self):
        r = self.run_handler("test.fork")
        self.assertFalse(r["forked"])

    def test_internal_error_does_not_leak(self):
        with self.assertRaises(E.InternalError) as cm:
            self.run_handler("test.raise")
        self.assertNotIn("secret", cm.exception.message)

    def test_hostile_output_rejected(self):
        with self.assertRaises(E.ProtocolError):
            self.run_handler("test.garbage")
        with self.assertRaises(E.ProtocolError):
            self.run_handler("test.extra_frame")
        with self.assertRaises(E.WorkerFailure):
            self.run_handler("test.exit", {"code": 3})
        with self.assertRaises(E.WorkerFailure):
            self.run_handler("test.exit", {"code": 0})

    def test_unknown_handler_and_bad_params(self):
        with self.assertRaises(E.NotFound):
            self.run_handler("nope.handler")
        with self.assertRaises(E.ValidationError):
            self.run_handler("runtime.echo", {"value": 5})
        with self.assertRaises(E.ValidationError):
            self.run_handler("runtime.echo", {"value": "x", "extra": 1})

    def test_test_handlers_absent_in_production_launcher(self):
        if os.geteuid() == 0:
            prod = WorkerLauncher(worker_uid=UNPRIVILEGED, worker_gid=UNPRIVILEGED)
        else:
            prod = WorkerLauncher()
        with self.assertRaises(E.NotFound):
            prod.run(self.profile, "test.spin", {})

    def test_oversized_result_reported(self):
        with self.assertRaises(E.ResourceLimitExceeded):
            self.run_handler("runtime.echo", {"value": "x" * 4000},
                             WorkerProfile(name="small", max_output=1000))


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.broker = Broker(default_operations(), launcher())

    def req(self, op, params=None, rid="r1"):
        return {"v": 1, "type": "request", "id": rid, "op": op, "params": params or {}}

    def test_status_inline(self):
        p = principal("runtime.status")
        resp = self.broker.handle(p, self.req("runtime.status"))
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["principal"], "tester")
        self.assertEqual(resp["id"], "r1")

    def test_worker_operation(self):
        resp = self.broker.handle(principal("runtime.diagnostics"), self.req("runtime.echo", {"value": "x"}))
        self.assertEqual(resp["result"], {"value": "x"})

    def test_default_deny_and_logging(self):
        with self.assertLogs("usbguardian.broker", level="INFO") as cm:
            resp = self.broker.handle(principal("runtime.status"), self.req("runtime.echo", {"value": "x"}))
        self.assertFalse(resp["ok"])
        self.assertEqual(resp["error"]["code"], "PERMISSION_DENIED")
        decisions = [r for r in cm.records if r.msg == "authz.decision"]
        self.assertEqual(decisions[0].guardian_fields["allowed"], False)
        self.assertEqual(decisions[0].guardian_fields["reason"], "CAPABILITY_NOT_GRANTED")

    def test_authorization_happens_before_param_validation(self):
        resp = self.broker.handle(principal(), self.req("runtime.echo", {"value": 5}))
        self.assertEqual(resp["error"]["code"], "PERMISSION_DENIED")

    def test_unknown_op_and_bad_envelopes(self):
        p = principal("runtime.status", "runtime.diagnostics")
        self.assertEqual(self.broker.handle(p, self.req("nope.op"))["error"]["code"], "NOT_FOUND")
        for bad in (None, [], {"v": 1}, dict(self.req("runtime.status"), v=2),
                    dict(self.req("runtime.status"), extra=1), dict(self.req("runtime.status"), params=[])):
            resp = self.broker.handle(p, bad)
            self.assertFalse(resp["ok"])
            self.assertEqual(resp["error"]["code"], "VALIDATION_FAILED")
        resp = self.broker.handle(p, dict(self.req("runtime.status"), id="bad id!"))
        self.assertEqual(resp["id"], "invalid")
        resp = self.broker.handle(p, self.req("runtime.echo", {"value": 5}))
        self.assertEqual(resp["error"]["code"], "VALIDATION_FAILED")

    def test_factor_gated_operation(self):
        seen = []
        op = Operation("vault.peek", "vault.read", S.EMPTY, inline=lambda pr, params: seen.append(1) or "data")
        broker = Broker([op], launcher())
        p = principal("vault.read")
        self.assertEqual(broker.handle(p, self.req("vault.peek"))["error"]["code"], "PERMISSION_DENIED")
        self.assertEqual(seen, [])
        self.assertEqual(broker.handle(p.with_factor("owner_key"), self.req("vault.peek"))["result"], "data")

    def test_inline_failure_is_contained(self):
        def boom(pr, params):
            raise RuntimeError("/etc/shadow contents")
        broker = Broker([Operation("runtime.status", "runtime.status", S.EMPTY, inline=boom)], launcher())
        resp = broker.handle(principal("runtime.status"), self.req("runtime.status"))
        self.assertEqual(resp["error"]["code"], "INTERNAL_ERROR")
        self.assertNotIn("shadow", resp["error"]["message"])

    def test_non_canonical_result_rejected(self):
        broker = Broker([Operation("runtime.status", "runtime.status", S.EMPTY, inline=lambda pr, p: 1.5)],
                        launcher())
        resp = broker.handle(principal("runtime.status"), self.req("runtime.status"))
        self.assertEqual(resp["error"]["code"], "VALIDATION_FAILED")

    def test_operation_definitions_checked(self):
        with self.assertRaises(ValueError):
            Operation("a.b", "made.up", S.EMPTY, inline=lambda pr, p: 1)
        with self.assertRaises(ValueError):
            Operation("a.b", "runtime.status", S.EMPTY)
        with self.assertRaises(ValueError):
            Operation("a.b", "runtime.status", S.EMPTY, worker_handler="x.y")
        op = Operation("a.b", "runtime.status", S.EMPTY, inline=lambda pr, p: 1)
        with self.assertRaises(ValueError):
            Broker([op, op], launcher())


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        os.chmod(self.dir, 0o755)
        self.sock_path = self.dir / "broker.sock"
        self.server = None

    def tearDown(self):
        if self.server is not None:
            self.server.stop()
            self.thread.join(5)
        self.tmp.cleanup()

    def start(self, caps):
        policy = authz.Policy([("me", os.geteuid(), caps)] if caps is not None else [])
        self.server = BrokerServer(Broker(default_operations(), launcher()), policy, self.sock_path,
                                   idle_timeout=2.0, max_connections=2)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_end_to_end(self):
        self.start(["runtime.status", "runtime.diagnostics"])
        self.assertEqual(os.stat(self.sock_path).st_mode & 0o777, 0o600)
        with BrokerClient(self.sock_path, timeout=10) as client:
            status = client.call("runtime.status")
            self.assertEqual(status["principal"], "me")
            self.assertEqual(status["factors"], ["peer_uid"])
            self.assertEqual(client.call("runtime.echo", {"value": "ping"}), {"value": "ping"})
            report = client.call("runtime.sandbox_report")
            self.assertEqual(report["no_new_privs"], 1)

    def test_denied_operation_over_socket(self):
        self.start(["runtime.status"])
        with BrokerClient(self.sock_path, timeout=10) as client:
            with self.assertRaises(E.PermissionDenied):
                client.call("runtime.echo", {"value": "x"})
            with self.assertRaises(E.NotFound):
                client.call("runtime.missing")
            self.assertEqual(client.call("runtime.status")["principal"], "me")

    def test_unknown_uid_refused(self):
        self.start(None)
        with BrokerClient(self.sock_path, timeout=10) as client:
            with self.assertRaises(E.PermissionDenied):
                client.call("runtime.status")

    def test_malformed_frame_drops_connection(self):
        self.start(["runtime.status"])
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.sock_path))
        s.sendall(struct.pack(">I", 3) + b"1.5")
        resp = ipc.validate_response(ipc.recv_frame(s.fileno(), timeout=5))
        self.assertEqual(resp["error"]["code"], "PROTOCOL_ERROR")
        self.assertIsNone(ipc.recv_frame(s.fileno(), timeout=5, allow_eof=True))
        s.close()

    def test_oversized_frame_header_refused(self):
        self.start(["runtime.status"])
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(str(self.sock_path))
        s.sendall(struct.pack(">I", 0x7FFFFFFF))
        resp = ipc.validate_response(ipc.recv_frame(s.fileno(), timeout=5))
        self.assertEqual(resp["error"]["code"], "PROTOCOL_ERROR")
        s.close()

    def test_refuses_to_replace_non_socket(self):
        self.sock_path.write_bytes(b"precious")
        policy = authz.Policy([])
        server = BrokerServer(Broker(default_operations(), launcher()), policy, self.sock_path)
        with self.assertRaises(E.SecurityViolation):
            server.bind()
        self.assertEqual(self.sock_path.read_bytes(), b"precious")

    def test_overlong_socket_path_rejected(self):
        with self.assertRaises(E.ConfigError):
            BrokerServer(Broker(default_operations(), launcher()), authz.Policy([]), self.dir / ("s" * 120))
        with self.assertRaises(E.ConfigError):
            BrokerClient(self.dir / ("s" * 120))

    def test_refuses_world_writable_socket_dir(self):
        os.chmod(self.dir, 0o777)
        server = BrokerServer(Broker(default_operations(), launcher()), authz.Policy([]), self.sock_path)
        with self.assertRaises(E.SecurityViolation):
            server.bind()

    def test_connection_limit(self):
        self.start(["runtime.status"])
        held = []
        for _ in range(2):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(self.sock_path))
            held.append(s)
        time.sleep(0.3)
        extra = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        extra.connect(str(self.sock_path))
        self.assertIsNone(ipc.recv_frame(extra.fileno(), timeout=5, allow_eof=True))
        for s in held + [extra]:
            s.close()

    def test_socket_removed_on_stop(self):
        self.start(["runtime.status"])
        self.server.stop()
        self.thread.join(5)
        self.server = None
        self.assertFalse(self.sock_path.exists())


if __name__ == "__main__":
    unittest.main()
