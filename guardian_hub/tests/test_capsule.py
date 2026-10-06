# SPDX-License-Identifier: GPL-3.0-or-later
"""age capsule tests (D7).  Software X25519 keys stand in for YubiKey recipients under the test policy only."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.tools import find_tool  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity import trust as T  # noqa: E402
from usbguardian.identity.sshsig import NS_RECIPIENTS, NS_TRANSFER, tool_verify  # noqa: E402
from usbguardian.vault import capsule as CAP  # noqa: E402

AGE_KEYGEN = find_tool("age-keygen")


def _age_identity(directory, name):
    path = directory / name
    subprocess.run([AGE_KEYGEN, "-o", str(path)], check=True, capture_output=True)
    recipient = [ln.split(": ", 1)[1] for ln in path.read_text().splitlines() if ln.startswith("# public key")][0]
    return path, recipient


@unittest.skipIf(SSH_KEYGEN is None or AGE_KEYGEN is None or find_tool("age") is None, "age or ssh-keygen missing")
class CapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        d = Path(cls._tmp.name)
        cls.d = d
        cls.A, cls.B, cls.X = (_keygen(d, n) for n in ("a", "b", "x"))
        cls.idA, cls.rA = _age_identity(d, "age-a")
        cls.idB, cls.rB = _age_identity(d, "age-b")
        cls.idX, cls.rX = _age_identity(d, "age-x")
        cls.state = T.apply_event(None, EN.genesis([(cls.A, "A", None), (cls.B, "B", None)]), tool_verify,
                                  allowed_types=TEST_TYPES)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def recipient_set(self, entries=None, signer=None, ns=NS_RECIPIENTS, state=None):
        doc = {"format": "guardian-capsule-recipients", "version": 1, "trust_anchor": self.state.anchor,
               "recipients": entries if entries is not None else [
                   {"owner_key_id": self.A.key_id, "recipient": self.rA, "label": "YubiKey A"},
                   {"owner_key_id": self.B.key_id, "recipient": self.rB, "label": "YubiKey B"}]}
        signer = signer or self.A
        sig = signer.sign_ns(ns, CAP.recipient_set_digest(doc))
        return CAP.capsule_recipients(doc, signer.key_id, sig, state or self.state, tool_verify,
                                      policy=CAP.TEST_POLICY)

    def test_gate_closed_and_hardware_only_policy(self):
        self.assertFalse(CAP.HARDWARE_GATE_PASSED)
        self.assertIn("deferred", CAP.gate_status()["status"])
        self.assertEqual(CAP.recipient_kind(self.rA), "x25519")
        self.assertEqual(CAP.recipient_kind("age1yubikey1" + "q" * 50), "yubikey")
        with self.assertRaises(E.ValidationError) as cm:  # production refuses software recipients
            CAP.seal(0, 1, [self.rA])
        self.assertEqual(cm.exception.code, "CAPSULE_RECIPIENT_NOT_ALLOWED")

    def test_recipient_set_rules(self):
        self.assertEqual(self.recipient_set(), [self.rA, self.rB])
        with self.assertRaises(E.ValidationError) as cm:  # B could not open: refused (D3: either key alone)
            self.recipient_set([{"owner_key_id": self.A.key_id, "recipient": self.rA, "label": "A"}])
        self.assertEqual(cm.exception.code, "CAPSULE_RECIPIENTS_INCOMPLETE")
        for kwargs in ({"signer": self.X}, {"ns": NS_TRANSFER}):
            with self.assertRaises(E.IntegrityError) as cm:
                self.recipient_set(**kwargs)
            self.assertEqual(cm.exception.code, "CAPSULE_RECIPIENTS_INVALID")
        revoked = T.apply_event(self.state, EN.revoke(self.state.head, self.state.seq, self.B.key_id, self.A, "lost"),
                                tool_verify, allowed_types=TEST_TYPES)
        self.assertEqual(self.recipient_set(state=revoked), [self.rA])  # a revoked key's recipient is dropped
        doc = {"format": "guardian-capsule-recipients", "version": 1, "trust_anchor": self.state.anchor,
               "recipients": [{"owner_key_id": self.A.key_id, "recipient": self.rA, "label": "A"},
                              {"owner_key_id": self.B.key_id, "recipient": self.rB, "label": "B"}]}
        sig = self.A.sign_ns(NS_RECIPIENTS, CAP.recipient_set_digest(doc))
        with self.assertRaises(E.ValidationError):  # production policy: hardware recipients only
            CAP.capsule_recipients(doc, self.A.key_id, sig, self.state, tool_verify)

    def test_seal_and_open(self):
        plain = self.d / "plain"
        plain.write_bytes(b"signed transfer package bytes\x00\xff" * 1000)
        sealed = self.d / "sealed.age"
        with open(plain, "rb") as src, open(sealed, "wb") as dst:
            CAP.seal(src.fileno(), dst.fileno(), self.recipient_set(), policy=CAP.TEST_POLICY)
        for identity in (self.idA, self.idB):  # either key alone opens it
            out = self.d / "out"
            with open(sealed, "rb") as src, open(out, "wb") as dst:
                CAP.open_capsule(src.fileno(), dst.fileno(), str(identity), policy=CAP.TEST_POLICY)
            self.assertEqual(out.read_bytes(), plain.read_bytes())
        with self.assertRaises(E.GuardianError) as cm:  # an unrelated key cannot
            with open(sealed, "rb") as src, open(self.d / "out2", "wb") as dst:
                CAP.open_capsule(src.fileno(), dst.fileno(), str(self.idX), policy=CAP.TEST_POLICY)
        self.assertEqual(cm.exception.code, "CAPSULE_FAILED")
        data = bytearray(sealed.read_bytes())
        data[-20] ^= 1
        (self.d / "tampered.age").write_bytes(bytes(data))
        with self.assertRaises(E.GuardianError):
            with open(self.d / "tampered.age", "rb") as src, open(self.d / "out3", "wb") as dst:
                CAP.open_capsule(src.fileno(), dst.fileno(), str(self.idA), policy=CAP.TEST_POLICY)
        with self.assertRaises(E.ValidationError) as cm:  # production never opens with a software secret key
            with open(sealed, "rb") as src, open(self.d / "out4", "wb") as dst:
                CAP.open_capsule(src.fileno(), dst.fileno(), str(self.idA))
        self.assertEqual(cm.exception.code, "CAPSULE_IDENTITY_NOT_ALLOWED")


if __name__ == "__main__":
    unittest.main()
