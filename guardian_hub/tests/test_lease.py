# SPDX-License-Identifier: GPL-3.0-or-later
"""D5 lease tests: pure state transitions, then Guardian Main and spinoffs end to end (real ssh-keygen)."""

import base64
import os
import shutil
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_dumps  # noqa: E402
from usbguardian.common.fsutil import atomic_write, ensure_private_dir  # noqa: E402
from usbguardian.forge.descriptor import build_descriptor  # noqa: E402
from usbguardian.forge.registry import DeploymentRegistry  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.sshsig import NS_DEPLOY, NS_LEASE, tool_verify  # noqa: E402
from usbguardian.lease import records as R  # noqa: E402
from usbguardian.lease.machine import machine_identity  # noqa: E402
from usbguardian.lease.spinoff import apply_record, fresh_state  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.vault.custody import utc_timestamp  # noqa: E402

ALL_CAPS = sorted(authz.CAPABILITIES)
DAY = R.DAY


def _key_line():
    blob = b"".join(struct.pack(">I", len(f)) + f for f in (b"ssh-ed25519", os.urandom(32)))
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _kid(line):
    return R.parse_spinoff_key(line).key_id


class TransitionTests(unittest.TestCase):
    """apply_record alone: signatures and binding are checked before it runs."""

    def setUp(self):
        self.k1, self.k2, self.other = _key_line(), _key_line(), _key_line()
        self.seq = 0

    def rec(self, kind="lease", generation=1, key=None, seq=None):
        self.seq = seq if seq is not None else self.seq + 1
        lease = kind == "lease"
        record = {"format": "guardian-lease", "version": 1, "kind": kind, "record_id": os.urandom(16).hex(),
                  "instance_id": "laptop", "machine_id": "a" * 64, "generation": generation, "seq": self.seq,
                  "spinoff_key": (key or self.k1) if lease else None, "not_before": 1000 if lease else None,
                  "not_after": 1000 + 90 * DAY if lease else None, "warn_seconds": 14 * DAY if lease else None,
                  "issued": 1000, "reason": "", "trust_anchor": "b" * 64,
                  "issuer": {"instance_id": "guardian-main", "key_id": "sha256-" + "c" * 64}}
        env = {"record": R.check_record(record), "signature": "sig"}
        return env, R.record_digest(record).hex()

    def apply(self, state, env_digest, key=None, pending=None):
        env, digest = env_digest
        return apply_record(state, env, digest, key_id=_kid(key or self.k1),
                            pending_key_id=_kid(pending) if pending else None)

    def test_first_lease_renewal_and_replay(self):
        first = self.rec()
        s, out = self.apply(fresh_state("laptop"), first)
        self.assertEqual((out, s["generation"], s["seq"]), ("lease_accepted", 1, 1))
        self.assertEqual(self.apply(s, first)[1], "already_imported")
        renewal = self.rec()
        s, out = self.apply(s, renewal)
        self.assertEqual((out, s["generation"], s["seq"]), ("lease_accepted", 1, 2))
        with self.assertRaises(E.IntegrityError) as cm:  # an older record (seq 1, different content)
            self.apply(s, self.rec(seq=1))
        self.assertEqual(cm.exception.code, "LEASE_STALE")
        with self.assertRaises(E.IntegrityError) as cm:  # generation change without a fresh key
            self.apply(s, self.rec(generation=2, seq=5))
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_MISMATCH")

    def test_supersession_is_sticky(self):
        s, _ = self.apply(fresh_state("laptop"), self.rec())
        s, out = self.apply(s, self.rec(generation=2, key=self.other))
        self.assertEqual((out, s["superseded_by"], s["generation"]), ("superseded", 2, 1))
        with self.assertRaises(E.IntegrityError) as cm:  # a later renewal of the old generation
            self.apply(s, self.rec(generation=1))
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_SUPERSEDED")
        with self.assertRaises(E.IntegrityError) as cm:  # someone else's key, not newer
            self.apply(s, self.rec(generation=1, key=self.other, seq=40))
        self.assertIn(cm.exception.code, ("LEASE_GENERATION_SUPERSEDED", "LEASE_KEY_MISMATCH"))

    def test_revocation_then_reissue_with_fresh_key(self):
        s, _ = self.apply(fresh_state("laptop"), self.rec())
        s, out = self.apply(s, self.rec(kind="revocation", generation=1))
        self.assertEqual((out, s["revoked_generation"]), ("revoked", 1))
        with self.assertRaises(E.IntegrityError) as cm:
            self.apply(s, self.rec(generation=1))
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_REVOKED")
        with self.assertRaises(E.IntegrityError):  # reissue never reuses the revoked key
            self.apply(s, self.rec(generation=2))
        s, out = self.apply(s, self.rec(generation=2, key=self.k2), pending=self.k2)
        self.assertEqual((out, s["generation"]), ("lease_rekeyed", 2))

    def test_record_shape(self):
        env, _ = self.rec()
        bad = dict(env["record"], not_after=env["record"]["not_before"])
        with self.assertRaises(E.ValidationError):
            R.check_record(bad)
        with self.assertRaises(E.ValidationError):
            R.check_record(dict(env["record"], kind="revocation"))
        with self.assertRaises(E.ValidationError):  # owner hardware keys never act as spinoff keys
            R.parse_spinoff_key("sk-ssh-ed25519@openssh.com AAAA")


class MachineTests(unittest.TestCase):
    def test_sources_and_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(E.ConfigError):
                machine_identity(root)
            (root / "etc").mkdir()
            (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
            dmi = root / "sys/class/dmi/id"
            dmi.mkdir(parents=True)
            (dmi / "product_serial").write_text("To Be Filled By O.E.M.\n")
            (dmi / "product_uuid").write_text("00000000-0000-0000-0000-000000000000\n")
            digest, sources = machine_identity(root)
            self.assertEqual(sources, ["os_machine_id"])
            (dmi / "board_serial").write_text("PF3XYZ12\n")
            digest2, sources = machine_identity(root)
            self.assertEqual(sources, ["dmi_board_serial", "os_machine_id"])
            self.assertNotEqual(digest, digest2)


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class LeaseFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        kd = Path(cls._keys.name)
        cls.A, cls.B, cls.X = (_keygen(kd, n) for n in ("a", "b", "x"))

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def setUp(self):
        from test_runtime import launcher
        self.launcher = launcher()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o755)
        self.main = build_services(self.launcher, self.root / "main", sig_check=tool_verify,
                                   allowed_key_types=TEST_TYPES)
        policy = authz.Policy([("owner", os.geteuid(), ALL_CAPS)])
        self.server = BrokerServer(self.main.broker, policy, self.root / "b.sock", idle_timeout=60.0)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BrokerClient(self.root / "b.sock", timeout=120)
        self.client.connect()
        self.client.call("trust.init", {"envelope": EN.genesis([(self.A, "A", None), (self.B, "B", None)])})
        self.register("laptop")
        self.now = int(time.time())
        self.ids = 0

    def tearDown(self):
        self.client.close()
        self.server.stop()
        self.thread.join(5)
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------------------------------

    def register(self, instance_id):
        DeploymentRegistry(self.root / "main" / "forge").add({
            "instance_id": instance_id, "deployment_id": os.urandom(16).hex(), "platform": "debian-mx",
            "profile": "storage", "issued": utc_timestamp(), "package_sha256": "0" * 64, "status": "active",
            "retired": None})

    def machine(self, name="m1", machine_id="0123456789abcdef0123456789abcdef"):
        root = self.root / ("machine-" + name)
        (root / "etc").mkdir(parents=True, exist_ok=True)
        (root / "etc/machine-id").write_text(machine_id + "\n")
        return root

    def spinoff(self, name="s1", instance_id="laptop", machine=None):
        """A spinoff state directory as the installer leaves it, then its services."""
        state = self.root / name
        if not state.exists():
            ensure_private_dir(state)
            ensure_private_dir(state / "trust")
            for f in ("trust.log", "trust.anchor"):
                atomic_write(state / "trust" / f, (self.root / "main" / "trust" / f).read_bytes())
            trust = self.main.trust.require_state()
            desc = build_descriptor(deployment_id=os.urandom(16).hex(), instance_id=instance_id,
                                    platform="debian-mx", profile="storage", issued=utc_timestamp(),
                                    trust={"anchor": trust.anchor, "head": trust.head, "seq": trust.seq},
                                    issuer_instance="guardian-main", key_id=self.A.key_id,
                                    code=[{"path": "guardian.py", "sha256": "0" * 64, "length": 1}])
            atomic_write(state / "deployment.json", canonical_dumps(desc))
        svc = build_services(self.launcher, state, instance_id=instance_id, sig_check=tool_verify,
                             allowed_key_types=TEST_TYPES, machine_root=machine or self.machine())
        self.assertEqual(svc.role, "spinoff")
        svc.lease.clock = lambda: self.now
        return svc

    def call(self, svc, op, params=None, factors=("peer_uid",)):
        self.ids += 1
        principal = authz.Principal("owner", os.geteuid(), frozenset(ALL_CAPS), frozenset(factors))
        resp = svc.broker.handle(principal, {"v": 1, "type": "request", "id": "r%d" % self.ids, "op": op,
                                             "params": params or {}})
        if not resp["ok"]:
            raise E.error_from_wire(resp["error"])
        return resp["result"]

    def request(self, svc, rekey=False):
        return self.call(svc, "lease.request", {"rekey": rekey})["envelope"]

    def issue(self, request, signer=None, namespace=NS_LEASE, **extra):
        signer = signer or self.A
        prepared = self.client.call("lease.prepare", dict({"action": "issue", "instance_id": "laptop",
                                                           "key_id": signer.key_id, "request": request}, **extra))
        sig = signer.sign_ns(namespace, bytes.fromhex(prepared["digest"]))
        return self.client.call("lease.commit", {"record_id": prepared["record_id"],
                                                 "signature": sig.decode()})["envelope"]

    def revoke(self, reason="lost laptop"):
        prepared = self.client.call("lease.prepare", {"action": "revoke", "instance_id": "laptop",
                                                      "key_id": self.B.key_id, "reason": reason})
        sig = self.B.sign_ns(NS_LEASE, bytes.fromhex(prepared["digest"]))
        return self.client.call("lease.commit", {"record_id": prepared["record_id"],
                                                 "signature": sig.decode()})["envelope"]

    def state(self, svc):
        return self.call(svc, "lease.status")["state"]

    def gate_code(self, svc):
        """Error code of a gated destructive operation (owner factor already present)."""
        try:
            self.call(svc, "device.surface_test", {"kname": "sdz", "fingerprint": "0" * 64},
                      factors=("peer_uid", "owner_key"))
        except E.GuardianError as exc:
            return exc.code
        return "OK"

    # -- tests -----------------------------------------------------------------------------------

    def test_gated_operations(self):
        gated = sorted(op.name for op in self.main.broker.operations.values() if op.requires_active)
        self.assertEqual(gated, ["device.surface_test", "transfer.write", "vault.intake"])
        self.assertIsNone(self.main.broker.lease_gate)  # Main is the authority
        svc = self.spinoff()
        self.assertNotIn("lease.prepare", svc.broker.operations)  # a spinoff never issues
        self.assertNotIn("forge.prepare", svc.broker.operations)
        self.assertIn("transfer.verify", svc.broker.operations)  # recovery stays available
        self.assertFalse(svc.broker.operations["transfer.release"].requires_active)

    def test_issue_import_active(self):
        svc = self.spinoff()
        self.assertEqual(self.state(svc), "UNLEASED")
        self.assertEqual(self.gate_code(svc), "LEASE_NOT_ACTIVE")
        env = self.issue(self.request(svc))
        result = self.call(svc, "lease.import", {"envelope": env})
        self.assertEqual((result["outcome"], result["state"], result["generation"]), ("lease_accepted", "ACTIVE", 1))
        self.assertNotEqual(self.gate_code(svc), "LEASE_NOT_ACTIVE")
        self.assertEqual(self.call(svc, "lease.import", {"envelope": env})["outcome"], "already_imported")
        entry = DeploymentRegistry(self.root / "main" / "forge").get("laptop")
        self.assertEqual([(g["generation"], g["status"]) for g in entry["lease"]["generations"]], [(1, "active")])
        self.assertEqual([e["entry"]["fields"]["outcome"] for e in svc.audit.entries(0, 100)
                          if e["entry"]["event"] == "lease.accepted"], ["lease_accepted"])
        # survives a restart
        self.assertEqual(self.state(self.spinoff()), "ACTIVE")

    def test_expiry_warning_clock_and_renewal(self):
        svc = self.spinoff()
        self.call(svc, "lease.import", {"envelope": self.issue(self.request(svc), days=2, warn_days=1)})
        self.now += 600
        self.assertEqual(self.state(svc), "ACTIVE")
        self.now -= 1200  # clock set back beyond the tolerance
        self.assertEqual(self.state(svc), "UNKNOWN")
        self.assertEqual(self.gate_code(svc), "LEASE_NOT_ACTIVE")
        self.now += 1200  # corrected again
        self.assertEqual(self.state(svc), "ACTIVE")
        self.now += int(1.5 * DAY)
        self.assertEqual(self.state(svc), "EXPIRING")
        self.assertNotEqual(self.gate_code(svc), "LEASE_NOT_ACTIVE")
        self.now += DAY
        self.assertEqual(self.state(svc), "EXPIRED")
        self.now -= 2 * DAY  # rolling the clock back never revives it
        self.assertEqual(self.state(svc), "EXPIRED")
        self.assertEqual(self.state(self.spinoff()), "EXPIRED")
        self.now = int(time.time())
        result = self.call(svc, "lease.import", {"envelope": self.issue(self.request(svc))})
        self.assertEqual((result["state"], result["generation"], result["seq"]), ("ACTIVE", 1, 2))

    def test_revocation_and_reissue(self):
        svc = self.spinoff()
        self.call(svc, "lease.import", {"envelope": self.issue(self.request(svc))})
        old_fp = self.call(svc, "lease.status")["key_fingerprint"]
        files = sorted(os.listdir(self.root / "s1"))
        result = self.call(svc, "lease.import", {"envelope": self.revoke()})
        self.assertEqual((result["outcome"], result["state"]), ("revoked", "REVOKED"))
        self.assertEqual(self.gate_code(svc), "LEASE_NOT_ACTIVE")
        self.assertEqual(sorted(os.listdir(self.root / "s1")), files)  # nothing erased
        with self.assertRaises(E.GuardianError) as cm:  # Main refuses the revoked generation's key
            self.issue(self.request(svc))
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_REVOKED")
        rekey = self.request(svc, rekey=True)
        with self.assertRaises(E.GuardianError) as cm:  # a new key needs the owner's explicit reissue
            self.issue(rekey)
        self.assertEqual(cm.exception.code, "LEASE_REISSUE_REQUIRED")
        result = self.call(svc, "lease.import", {"envelope": self.issue(rekey, reissue=True)})
        self.assertEqual((result["outcome"], result["state"], result["generation"]), ("lease_rekeyed", "ACTIVE", 2))
        status = self.call(svc, "lease.status")
        self.assertNotEqual(status["key_fingerprint"], old_fp)
        self.assertIsNone(status["pending_key_fingerprint"])
        entry = DeploymentRegistry(self.root / "main" / "forge").get("laptop")
        self.assertEqual([(g["generation"], g["status"]) for g in entry["lease"]["generations"]],
                         [(1, "revoked"), (2, "active")])

    def test_superseded_installation(self):
        old = self.spinoff("s1")
        self.call(old, "lease.import", {"envelope": self.issue(self.request(old))})
        stale_request = self.request(old)
        new = self.spinoff("s2")  # reinstall on the same machine: fresh key, generation 2
        self.call(new, "lease.import", {"envelope": self.issue(self.request(new), reissue=True)})
        self.assertEqual(self.state(new), "ACTIVE")
        with self.assertRaises(E.GuardianError) as cm:  # Main rejects the old generation
            self.issue(stale_request)
        self.assertEqual(cm.exception.code, "LEASE_GENERATION_SUPERSEDED")
        check = self.client.call("lease.check", {"request": stale_request})
        self.assertEqual((check["status"], check["generation"]), ("superseded", 2))
        result = self.call(old, "lease.import", {"envelope": check["latest"]})
        self.assertEqual((result["outcome"], result["state"]), ("superseded", "SUPERSEDED"))
        self.assertEqual(self.gate_code(old), "LEASE_NOT_ACTIVE")

    def test_binding_and_signature_rejections(self):
        svc = self.spinoff()
        req = self.request(svc)
        tampered = {"request": dict(req["request"], generation=7), "key_id": req["key_id"],
                    "signature": req["signature"]}
        with self.assertRaises(E.GuardianError) as cm:
            self.issue(tampered)
        self.assertEqual(cm.exception.code, "LEASE_REQUEST_INVALID")
        with self.assertRaises(E.PermissionDenied):  # owner signature in the wrong namespace
            self.issue(req, namespace=NS_DEPLOY)
        with self.assertRaises(E.ValidationError):  # outsider key
            self.issue(req, signer=self.X)
        env = self.issue(req)
        forged = {"record": dict(env["record"], not_after=env["record"]["not_after"] + 365 * DAY),
                  "signature": env["signature"]}
        with self.assertRaises(E.GuardianError) as cm:  # a spinoff cannot extend its own lease
            self.call(svc, "lease.import", {"envelope": forged})
        self.assertEqual(cm.exception.code, "LEASE_SIGNATURE_INVALID")
        other_machine = self.spinoff("s2", machine=self.machine("m2", "fedcba9876543210fedcba9876543210"))
        with self.assertRaises(E.GuardianError) as cm:
            self.call(other_machine, "lease.import", {"envelope": env})
        self.assertEqual(cm.exception.code, "LEASE_WRONG_MACHINE")
        with self.assertRaises(E.GuardianError) as cm:  # Main: renewal request from another machine
            self.issue(self.request(other_machine))
        self.assertIn(cm.exception.code, ("LEASE_WRONG_MACHINE", "LEASE_REISSUE_REQUIRED"))
        self.register("desktop")
        desktop = self.spinoff("s3", instance_id="desktop")
        with self.assertRaises(E.GuardianError) as cm:
            self.call(desktop, "lease.import", {"envelope": env})
        self.assertEqual(cm.exception.code, "LEASE_WRONG_SPINOFF")
        self.assertEqual(self.call(svc, "lease.import", {"envelope": env})["state"], "ACTIVE")
        # the machine changes under an installed lease: fails closed
        moved = self.spinoff("s1", machine=self.machine("m3", "11111111111111111111111111111111"))
        self.assertEqual(self.state(moved), "UNKNOWN")

    def test_local_rollback_detected_through_audit_ledger(self):
        svc = self.spinoff()
        self.call(svc, "lease.import", {"envelope": self.issue(self.request(svc))})
        saved = (self.root / "s1/lease/state.json").read_bytes()
        renewal = self.issue(self.request(svc))
        self.call(svc, "lease.import", {"envelope": renewal})
        atomic_write(self.root / "s1/lease/state.json", saved)  # restore the older state
        rolled = self.spinoff()
        status = self.call(rolled, "lease.status")
        self.assertEqual(status["state"], "UNKNOWN")
        self.assertIn("older than the audit ledger", status["reason"])
        self.assertEqual(self.call(rolled, "lease.import", {"envelope": renewal})["state"], "ACTIVE")

    def test_retired_gets_no_lease_but_can_be_revoked(self):
        svc = self.spinoff()
        self.call(svc, "lease.import", {"envelope": self.issue(self.request(svc))})
        DeploymentRegistry(self.root / "main" / "forge").retire("laptop", utc_timestamp())
        with self.assertRaises(E.GuardianError) as cm:
            self.issue(self.request(svc))
        self.assertEqual(cm.exception.code, "LEASE_REFUSED")
        self.assertEqual(self.client.call("lease.check", {"request": self.request(svc)})["status"], "retired")
        self.assertEqual(self.call(svc, "lease.import", {"envelope": self.revoke()})["state"], "REVOKED")

    def test_cli_round_trip(self):
        import contextlib
        import io
        import guardian
        svc = self.spinoff()
        policy = authz.Policy([("owner", os.geteuid(), ALL_CAPS)])
        server = BrokerServer(svc.broker, policy, self.root / "s.sock", idle_timeout=60.0)
        server.bind()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        media = self.root / "media"
        media.mkdir()
        auth = [self.A.handle_path + ".pub", self.A.handle_path]

        def run(*argv):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = guardian.main(list(argv))
            self.assertEqual(code, 0, err.getvalue())
            return out.getvalue(), err.getvalue()

        try:
            _, err = run("lease-request", "--socket", str(self.root / "s.sock"), "--out", str(media / "req.json"))
            self.assertIn("spinoff key SHA256:", err)
            _, err = run("lease-issue", "--socket", str(self.root / "b.sock"), "--auth", *auth,
                         "--request", str(media / "req.json"), "--out", str(media / "lease.json"), "--days", "30")
            self.assertIn("first lease", err)
            out, _ = run("lease-import", "--socket", str(self.root / "s.sock"), str(media / "lease.json"))
            self.assertIn('"state": "ACTIVE"', out)
            out, _ = run("lease-check", "--socket", str(self.root / "b.sock"), "--request", str(media / "req.json"),
                         "--out", str(media / "latest.json"))
            self.assertIn('"status": "current"', out)
            self.assertEqual((media / "latest.json").read_bytes(), (media / "lease.json").read_bytes())
            run("lease-revoke", "--socket", str(self.root / "b.sock"), "--auth", *auth, "--instance-id", "laptop",
                "--out", str(media / "revoke.json"), "--reason", "retired")
            out, _ = run("lease-status", "--socket", str(self.root / "s.sock"))
            self.assertIn('"state": "ACTIVE"', out)  # nothing changes until the record is imported
            out, _ = run("lease-import", "--socket", str(self.root / "s.sock"), str(media / "revoke.json"))
            self.assertIn('"state": "REVOKED"', out)
        finally:
            server.stop()
            thread.join(5)

    def test_role_cannot_be_switched_by_deleting_the_descriptor(self):
        self.spinoff()
        with self.assertRaises(E.ConfigError) as cm:
            build_services(self.launcher, self.root / "s1", instance_id="other", sig_check=tool_verify,
                           allowed_key_types=TEST_TYPES, machine_root=self.machine())
        self.assertEqual(cm.exception.code, "ROLE_MISMATCH")
        os.unlink(self.root / "s1/deployment.json")
        with self.assertRaises(E.ConfigError) as cm:
            build_services(self.launcher, self.root / "s1", instance_id="laptop", sig_check=tool_verify,
                           allowed_key_types=TEST_TYPES, machine_root=self.machine())
        self.assertEqual(cm.exception.code, "ROLE_MISMATCH")
        shutil.rmtree(self.root / "s1")


if __name__ == "__main__":
    unittest.main()
