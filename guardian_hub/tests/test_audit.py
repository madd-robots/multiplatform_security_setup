# SPDX-License-Identifier: GPL-3.0-or-later
"""Audit ledger tests: chain integrity, tamper detection, redaction, signed checkpoints, broker hook."""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.audit.ledger import AuditLedger, checkpoint_digest, verify_segments  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_dumps, canonical_loads  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity import trust as T  # noqa: E402
from usbguardian.identity.sshsig import NS_AUDIT, NS_TRANSFER, tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime import schema as S  # noqa: E402
from usbguardian.runtime.broker import Broker, Operation  # noqa: E402


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "audit"

    def tearDown(self):
        self.tmp.cleanup()

    def ledger(self, **kw):
        return AuditLedger(self.dir, **kw)

    def lines(self, name="ledger-000001.jsonl"):
        return (self.dir / name).read_bytes().splitlines(keepends=True)

    def rewrite(self, lines, name="ledger-000001.jsonl"):
        (self.dir / name).write_bytes(b"".join(lines))

    def test_chain_and_reopen(self):
        led = self.ledger()
        for i in range(5):
            led.append("test.event", i=i)
        self.assertEqual(led.head()[0], 4)
        reopened = self.ledger()
        self.assertEqual(reopened.head(), led.head())
        report = reopened.verify()
        self.assertEqual(report["entries"], 5)
        self.assertEqual([r["entry"]["fields"]["i"] for r in reopened.entries(2, 10)], [2, 3, 4])
        self.assertEqual(stat.S_IMODE(os.lstat(self.dir / "ledger-000001.jsonl").st_mode), 0o600)

    def test_tampering_detected(self):
        led = self.ledger()
        for i in range(4):
            led.append("test.event", i=i)
        original = self.lines()
        cases = {
            "edited field": [original[0], original[1].replace(b'"i":1', b'"i":7')] + original[2:],
            "deleted entry": original[:1] + original[2:],
            "reordered": [original[1], original[0]] + original[2:],
            "partial line": original[:3] + [original[3][:-10]],
            "garbage": original + [b"not json\n"],
        }
        for label, lines in cases.items():
            with self.subTest(label):
                self.rewrite(lines)
                with self.assertRaises(E.IntegrityError) as cm:
                    self.ledger()
                self.assertEqual(cm.exception.code, "AUDIT_BROKEN")
        self.rewrite(original)
        self.ledger()

    def test_segments_rotate_and_gaps_detected(self):
        led = self.ledger(segment_bytes=1024)
        for i in range(30):
            led.append("test.event", i=i, pad="x" * 100)
        names = sorted(os.listdir(self.dir))
        self.assertGreater(len(names), 2)
        self.assertEqual(self.ledger(segment_bytes=1024).verify()["entries"], 30)
        report = verify_segments([self.dir / n for n in names])
        self.assertEqual(report["head"], led.head()[1])
        os.rename(self.dir / names[1], Path(self.tmp.name) / "moved")
        with self.assertRaises(E.IntegrityError):
            self.ledger(segment_bytes=1024)

    def test_unsafe_permissions_refused(self):
        self.ledger().append("test.event")
        os.chmod(self.dir / "ledger-000001.jsonl", 0o644)
        with self.assertRaises(E.IntegrityError):
            self.ledger()

    def test_secrets_never_recorded(self):
        led = self.ledger()
        led.append("vault.unlock", passphrase="hunter2", pin="123456", blob=b"\x00secret", key_id="kid")
        data = (self.dir / "ledger-000001.jsonl").read_bytes()
        for secret in (b"hunter2", b"123456", b"secret"):
            self.assertNotIn(secret, data)
        self.assertIn(b"kid", data)
        with self.assertRaises(ValueError):
            led.append("Bad Event")


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class CheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keys = tempfile.TemporaryDirectory()
        kd = Path(cls._keys.name)
        cls.A, cls.X = _keygen(kd, "a"), _keygen(kd, "x")
        cls.state = T.apply_event(None, EN.genesis([(cls.A, "A", None)]), tool_verify, allowed_types=TEST_TYPES)

    @classmethod
    def tearDownClass(cls):
        cls._keys.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "audit"
        self.led = AuditLedger(self.dir)
        for i in range(3):
            self.led.append("test.event", i=i)
        verifier = T.TrustVerifier(self.state, tool_verify, NS_AUDIT)
        self.check = lambda key_id, digest, sig: verifier.verify("sshsig", key_id, digest, sig)

    def tearDown(self):
        self.tmp.cleanup()

    def test_signed_checkpoint(self):
        seq, head = self.led.head()
        sig = self.A.sign_ns(NS_AUDIT, checkpoint_digest(seq, head))
        self.led.add_checkpoint(seq, head, self.A.key_id, sig, self.check)
        self.led.append("test.after")
        report = self.led.verify(self.check)
        self.assertEqual(report["checkpoints"], [{"at": 3, "seq": 2, "key_id": self.A.key_id}])

    def test_bad_checkpoints_rejected(self):
        seq, head = self.led.head()
        with self.assertRaises(E.IntegrityError):  # outsider key
            self.led.add_checkpoint(seq, head, self.X.key_id, self.X.sign_ns(NS_AUDIT, checkpoint_digest(seq, head)),
                                    self.check)
        with self.assertRaises(E.IntegrityError):  # owner key, wrong namespace
            self.led.add_checkpoint(seq, head, self.A.key_id,
                                    self.A.sign_ns(NS_TRANSFER, checkpoint_digest(seq, head)), self.check)
        with self.assertRaises(E.ValidationError):  # names an entry that does not exist
            self.led.add_checkpoint(seq, "f" * 64, self.A.key_id,
                                    self.A.sign_ns(NS_AUDIT, checkpoint_digest(seq, "f" * 64)), self.check)

    def test_forged_checkpoint_needs_signature_check(self):
        # Someone with write access appends a well-chained checkpoint with a bogus signature.
        seq, head = self.led.head()
        self.led.append("audit.checkpoint", exact={"seq": seq, "hash": head, "key_id": self.A.key_id, "signature":
                        "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"})
        self.led.verify()  # the chain alone is consistent ...
        with self.assertRaises(E.IntegrityError):
            self.led.verify(self.check)  # ... but the signature check exposes the forgery


class BrokerAuditTests(unittest.TestCase):
    def setUp(self):
        from test_runtime import launcher
        self.tmp = tempfile.TemporaryDirectory()
        self.led = AuditLedger(Path(self.tmp.name) / "audit")
        ops = [Operation("runtime.status", "runtime.status", S.EMPTY, inline=lambda p, params: "ok")]
        self.broker = Broker(ops, launcher(), audit=self.led)

    def tearDown(self):
        self.tmp.cleanup()

    def req(self, rid="r1"):
        return {"v": 1, "type": "request", "id": rid, "op": "runtime.status", "params": {}}

    def test_decisions_and_outcomes_recorded(self):
        allowed = authz.Principal("owner", 0, frozenset({"runtime.status"}), frozenset({"peer_uid"}))
        denied = authz.Principal("guest", 1, frozenset(), frozenset({"peer_uid"}))
        self.assertTrue(self.broker.handle(allowed, self.req("a1"))["ok"])
        self.assertFalse(self.broker.handle(denied, self.req("d1"))["ok"])
        events = [(r["entry"]["event"], r["entry"]["fields"].get("request_id"), r["entry"]["fields"].get("allowed"),
                   r["entry"]["fields"].get("outcome")) for r in self.led.entries(0, 10)]
        self.assertEqual(events, [("authz.decision", "a1", True, None), ("op.completed", "a1", None, "OK"),
                                  ("authz.decision", "d1", False, None),
                                  ("op.completed", "d1", None, "PERMISSION_DENIED")])

    def test_operation_refused_when_audit_fails(self):
        def broken(*a, **k):
            raise OSError(28, "No space left on device")
        self.led.append = broken
        allowed = authz.Principal("owner", 0, frozenset({"runtime.status"}), frozenset({"peer_uid"}))
        resp = self.broker.handle(allowed, self.req())
        self.assertEqual(resp["error"]["code"], "AUDIT_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
