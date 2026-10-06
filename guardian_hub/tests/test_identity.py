# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 5 identity tests: keys, SSHSIG, trust log, owner assertions, end-to-end transfers.

These run the real ``ssh-keygen -Y sign/verify`` code path. No YubiKey is
attached in CI, so the keys are ordinary ``ssh-ed25519`` keys and every test
that needs them opts in to a test-only key-type policy explicitly.
Production accepts only hardware security keys (``sk-ssh-ed25519``,
``sk-ecdsa``); a test below proves the default policy rejects these test
keys. The touch requirement itself must be validated with real YubiKeys
(see TESTING notes in README.md).
"""

import base64
import hashlib
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.tools import find_tool  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity import sshkeys as K  # noqa: E402
from usbguardian.identity import trust as T  # noqa: E402
from usbguardian.identity.owner import assertion_digest, call_as_owner  # noqa: E402
from usbguardian.identity.sshsig import (NS_ENROLL, NS_OWNER, NS_TRANSFER, NS_TRUST, SshKeygenSigner,  # noqa: E402
                                         check_armor, tool_verify)
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.runtime.session import Session  # noqa: E402
from usbguardian.vault.custody import CustodyStore  # noqa: E402
from usbguardian.vault.package import build_manifest, verify_package, write_package  # noqa: E402
from usbguardian.vault.release import release_package  # noqa: E402

SSH_KEYGEN = find_tool("ssh-keygen")
TEST_TYPES = K.KNOWN_KEY_TYPES  # explicit test-only opt-in (see module docstring)
ALL_CAPS = sorted(authz.CAPABILITIES)


def _keygen(directory, name):
    subprocess.run([SSH_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(directory / name)],
                   check=True, stdin=subprocess.DEVNULL)
    key = K.parse_public_key((directory / (name + ".pub")).read_text())
    return SshKeygenSigner(str(directory / name), key)


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class KeysCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.keydir = Path(cls._tmp.name)
        cls.A, cls.B, cls.C, cls.X = (_keygen(cls.keydir, n) for n in ("a", "b", "c", "x"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def digest(self, data=b"payload"):
        return hashlib.sha256(data).digest()


def _blob(*fields):
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def _line(key_type, blob):
    return "%s %s comment" % (key_type, base64.b64encode(blob).decode())


class PublicKeyTests(KeysCase):
    def test_ed25519_and_fingerprint_matches_ssh_keygen(self):
        out = subprocess.run([SSH_KEYGEN, "-l", "-f", str(self.keydir / "a.pub")], capture_output=True, text=True,
                             check=True).stdout
        self.assertIn(self.A.key.openssh_fingerprint, out)
        self.assertRegex(self.A.key.key_id, "^" + K.KEY_ID_PATTERN + "$")
        self.assertEqual(K.parse_public_key(self.A.key.to_line()), self.A.key)

    def test_security_key_types_parse(self):
        sk = K.parse_public_key(_line(K.SK_ED25519, _blob(K.SK_ED25519.encode(), b"\x01" * 32, b"ssh:guardian")))
        self.assertEqual(sk.key_type, K.SK_ED25519)
        K.check_key_type(sk, K.HARDWARE_KEY_TYPES)
        ecdsa = K.parse_public_key(_line(K.SK_ECDSA, _blob(K.SK_ECDSA.encode(), b"nistp256", b"\x04" + b"\x02" * 64,
                                                           b"ssh:")))
        self.assertEqual(ecdsa.key_type, K.SK_ECDSA)

    def test_malformed_keys_rejected(self):
        good = _blob(K.SK_ED25519.encode(), b"\x01" * 32, b"ssh:guardian")
        bad_lines = [
            "", "ssh-rsa AAAA", "ssh-ed25519", "ssh-ed25519 !!!notbase64",
            _line(K.SK_ED25519, good + b"x"),  # trailing data
            _line(K.SK_ED25519, _blob(K.ED25519.encode(), b"\x01" * 32)),  # type mismatch
            _line(K.SK_ED25519, _blob(K.SK_ED25519.encode(), b"\x01" * 31, b"ssh:")),  # short key
            _line(K.SK_ED25519, _blob(K.SK_ED25519.encode(), b"\x01" * 32, b"https://evil")),  # application
            _line(K.SK_ECDSA, _blob(K.SK_ECDSA.encode(), b"nistp384", b"\x04" + b"\x02" * 64, b"ssh:")),
            'command="x" ' + self.A.key.to_line(),  # options are not accepted
            self.A.key.to_line() + "\nssh-ed25519 AAAA",
        ]
        for line in bad_lines:
            with self.assertRaises(E.ValidationError, msg=line[:40]):
                K.parse_public_key(line)

    def test_production_policy_is_hardware_only(self):
        with self.assertRaises(E.ValidationError) as cm:
            K.check_key_type(self.A.key, K.HARDWARE_KEY_TYPES)
        self.assertEqual(cm.exception.code, "KEY_TYPE_NOT_ALLOWED")


class SshsigTests(KeysCase):
    def test_sign_and_verify(self):
        d = self.digest()
        sig = self.A.sign_ns(NS_TRANSFER, d)
        self.assertTrue(tool_verify(self.A.key, NS_TRANSFER, d, sig))

    def test_rejections(self):
        d = self.digest()
        sig = self.A.sign_ns(NS_TRANSFER, d)
        self.assertFalse(tool_verify(self.A.key, NS_OWNER, d, sig))  # namespace separation
        self.assertFalse(tool_verify(self.A.key, NS_TRANSFER, self.digest(b"other"), sig))
        self.assertFalse(tool_verify(self.B.key, NS_TRANSFER, d, sig))  # other key
        with self.assertRaises(E.ValidationError):
            tool_verify(self.A.key, "evil@v1", d, sig)

    def test_armor_checks(self):
        sig = self.A.sign_ns(NS_TRANSFER, self.digest())
        check_armor(sig)
        for bad in (b"", b"x" * 20000, sig.replace(b"\n", b"\r\n"), b"-----BEGIN SSH SIGNATURE-----\n$$$\n"
                    b"-----END SSH SIGNATURE-----\n", sig.replace(b"SSH SIGNATURE", b"PGP SIGNATURE"), "text"):
            with self.assertRaises(E.ValidationError):
                check_armor(bad)

    def test_signer_detects_wrong_handle(self):
        mismatched = SshKeygenSigner(self.A.handle_path, self.B.key)
        with self.assertRaises(E.IntegrityError):
            mismatched.sign_ns(NS_OWNER, self.digest())

    def test_only_digests_are_signed(self):
        with self.assertRaises(E.ValidationError):
            self.A.sign_ns(NS_OWNER, b"short")


class TrustLogTests(KeysCase):
    def apply(self, state, env, types=TEST_TYPES):
        return T.apply_event(state, env, tool_verify, allowed_types=types)

    def genesis(self, *signers):
        signers = signers or (self.A, self.B)
        return EN.genesis([(s, "Key %d" % i, None) for i, s in enumerate(signers)])

    def test_full_lifecycle(self):
        st = self.apply(None, self.genesis())
        self.assertEqual(set(st.active), {self.A.key_id, self.B.key_id})
        st = self.apply(st, EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))  # A revokes B
        st = self.apply(st, EN.enroll(st.head, st.seq, self.C, "Key C", None, self.A))  # A enrolls C
        self.assertEqual(set(st.active), {self.A.key_id, self.C.key_id})
        st = self.apply(st, EN.revoke(st.head, st.seq, self.A.key_id, self.C, "A retired"))  # C revokes A
        self.assertEqual(set(st.active), {self.C.key_id})
        self.assertEqual(set(st.revoked), {self.A.key_id, self.B.key_id})
        self.assertEqual(st.seq, 3)

    def test_production_policy_rejects_software_keys(self):
        with self.assertRaises(E.IntegrityError):
            self.apply(None, self.genesis(), types=K.HARDWARE_KEY_TYPES)

    def test_genesis_rules(self):
        env = self.genesis()
        env["proofs"] = env["proofs"][:1]  # B never proved possession
        with self.assertRaises(E.IntegrityError):
            self.apply(None, env)
        env = self.genesis()
        env["proofs"][1] = dict(env["proofs"][1], signature=env["proofs"][0]["signature"])
        with self.assertRaises(E.IntegrityError):
            self.apply(None, env)
        env = self.genesis()
        env["event"]["keys"][0]["label"] = "Tampered"  # signed content changed
        with self.assertRaises(E.IntegrityError):
            self.apply(None, env)
        with self.assertRaises(E.IntegrityError):
            self.apply(None, EN.revoke("0" * 64, -1, self.A.key_id, self.A, "x"))  # must start with genesis

    def test_enroll_rules(self):
        st = self.apply(None, self.genesis(self.A))
        # proof must come from the new key itself
        env = EN.enroll(st.head, st.seq, self.C, "C", None, self.A)
        env["proofs"] = [{"key_id": self.C.key_id, "signature": self.A.sign_ns(NS_ENROLL, T.event_digest(
            env["event"])).decode()}]
        with self.assertRaises(E.IntegrityError):
            self.apply(st, env)
        # authorizer must be active: an outsider cannot enroll their own key
        with self.assertRaises(E.IntegrityError):
            self.apply(st, EN.enroll(st.head, st.seq, self.X, "X", None, self.X))
        st = self.apply(st, EN.enroll(st.head, st.seq, self.B, "B", None, self.A))
        with self.assertRaises(E.IntegrityError):  # two keys already active
            self.apply(st, EN.enroll(st.head, st.seq, self.C, "C", None, self.A))

    def test_revoked_key_never_returns_and_loses_authority(self):
        st = self.apply(None, self.genesis())
        st = self.apply(st, EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))
        with self.assertRaises(E.IntegrityError):
            self.apply(st, EN.enroll(st.head, st.seq, self.B, "B again", None, self.A))
        with self.assertRaises(E.IntegrityError):  # revoked B cannot enroll anything
            self.apply(st, EN.enroll(st.head, st.seq, self.C, "C", None, self.B))

    def test_last_key_cannot_be_revoked(self):
        st = self.apply(None, self.genesis(self.A))
        with self.assertRaises(E.IntegrityError):
            self.apply(st, EN.revoke(st.head, st.seq, self.A.key_id, self.A, "oops"))

    def test_sequence_and_forks(self):
        st = self.apply(None, self.genesis())
        with self.assertRaises(E.IntegrityError) as cm:
            self.apply(st, self.genesis())
        self.assertEqual(cm.exception.code, "TRUST_FORK")
        with self.assertRaises(E.IntegrityError) as cm:
            self.apply(st, EN.revoke("f" * 64, st.seq, self.B.key_id, self.A, "x"))
        self.assertEqual(cm.exception.code, "TRUST_FORK")
        with self.assertRaises(E.IntegrityError) as cm:
            self.apply(st, EN.revoke(st.head, st.seq + 5, self.B.key_id, self.A, "x"))
        self.assertEqual(cm.exception.code, "TRUST_FORK")
        g = self.genesis()
        branch_a = [g, EN.revoke(T.event_digest(g["event"]).hex(), 0, self.B.key_id, self.A, "a")]
        branch_b = [g, EN.revoke(T.event_digest(g["event"]).hex(), 0, self.A.key_id, self.B, "b")]
        self.assertEqual(T.check_extension(branch_a[:1], branch_a), branch_a[1:])
        with self.assertRaises(E.IntegrityError) as cm:
            T.check_extension(branch_a, branch_b)
        self.assertEqual(cm.exception.code, "TRUST_FORK")

    def test_replay_with_pinned_anchor(self):
        g = self.genesis()
        st = T.replay([g], tool_verify, allowed_types=TEST_TYPES)
        T.replay([g], tool_verify, anchor=st.anchor, allowed_types=TEST_TYPES)
        other = self.genesis(self.C)
        with self.assertRaises(E.IntegrityError) as cm:
            T.replay([other], tool_verify, anchor=st.anchor, allowed_types=TEST_TYPES)
        self.assertEqual(cm.exception.code, "TRUST_ANCHOR_MISMATCH")

    def test_trust_verifier(self):
        st = self.apply(None, self.genesis())
        d = self.digest()
        sig_b = self.B.sign_ns(NS_TRANSFER, d)
        T.TrustVerifier(st, tool_verify, NS_TRANSFER).verify("sshsig", self.B.key_id, d, sig_b)
        with self.assertRaises(E.IntegrityError):  # right key, wrong purpose
            T.TrustVerifier(st, tool_verify, NS_OWNER).verify("sshsig", self.B.key_id, d, sig_b)
        with self.assertRaises(E.IntegrityError):
            T.TrustVerifier(st, tool_verify, NS_TRANSFER).verify("sshsig", self.X.key_id, d,
                                                                  self.X.sign_ns(NS_TRANSFER, d))
        st2 = self.apply(st, EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))
        with self.assertRaises(E.IntegrityError) as cm:  # old signature by a now-revoked key
            T.TrustVerifier(st2, tool_verify, NS_TRANSFER).verify("sshsig", self.B.key_id, d, sig_b)
        self.assertIn("revoked", cm.exception.message)

    def test_store_persists_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "trust"
            d.mkdir(mode=0o700)
            store = T.TrustStore(d, tool_verify, allowed_types=TEST_TYPES)
            self.assertIsNone(store.state())
            st = store.append(self.genesis())
            store.append(EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))
            for name in ("trust.log", "trust.anchor"):
                self.assertEqual(stat.S_IMODE(os.lstat(d / name).st_mode), 0o600)
            fresh = T.TrustStore(d, tool_verify, allowed_types=TEST_TYPES)
            self.assertEqual(fresh.state().seq, 1)
            data = (d / "trust.log").read_bytes()
            (d / "trust.log").write_bytes(data.replace(b'"reason":"lost"', b'"reason":"LOST"'))
            with self.assertRaises(E.IntegrityError):
                T.TrustStore(d, tool_verify, allowed_types=TEST_TYPES).state()
            (d / "trust.log").write_bytes(data)
            (d / "trust.anchor").write_bytes(b'{"anchor":"' + b"0" * 64 + b'"}')
            with self.assertRaises(E.IntegrityError) as cm:
                T.TrustStore(d, tool_verify, allowed_types=TEST_TYPES).state()
            self.assertEqual(cm.exception.code, "TRUST_ANCHOR_MISMATCH")


class OwnerAssertionTests(KeysCase):
    """Broker-level owner assertions with real signatures (no socket)."""

    def setUp(self):
        from test_runtime import launcher
        self.tmp = tempfile.TemporaryDirectory()
        self.services = build_services(launcher(), Path(self.tmp.name) / "state", sig_check=tool_verify,
                                       allowed_key_types=TEST_TYPES)
        self.services.trust.append(EN.genesis([(self.A, "A", None), (self.B, "B", None)]))
        self.broker = self.services.broker
        self.principal = authz.Principal("owner", 1000, frozenset(ALL_CAPS), frozenset({"peer_uid"}))
        self.session = Session(1000, 1000, 1)
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, op, params=None, session=None, principal=None):
        self.n += 1
        return self.broker.handle(principal or self.principal, {"v": 1, "type": "request", "id": "r%d" % self.n,
                                                                "op": op, "params": params or {}},
                                  session or self.session)

    def assertion(self, signer, op, params, *, namespace=NS_OWNER, session=None, uid=1000, tweak=None):
        session = session or self.session
        ch = self.call("auth.challenge", session=session)["result"]
        rd = authz.request_digest(op, params)
        digest = assertion_digest(nonce=ch["nonce"], broker_id=ch["broker_id"], uid=uid, op=op, request_digest=rd,
                                  key_id=signer.key_id)
        body = {"nonce": ch["nonce"], "key_id": signer.key_id, "op": op, "request_digest": rd,
                "signature": signer.sign_ns(namespace, digest).decode()}
        if tweak:
            body.update(tweak)
        return self.call("auth.assert", body, session=session)

    def test_status_needs_owner_until_asserted(self):
        # trust.log has no factor; vault.read (via transfer.release) needs one; use a cheap owner-gated op
        self.assertEqual(self.call("device.surface_test", {"kname": "sdz", "fingerprint": "0" * 64})["error"]["code"],
                         "PERMISSION_DENIED")

    def test_grant_is_one_shot_and_bound_to_params(self):
        params = {"kname": "sdz", "fingerprint": "0" * 64}
        self.assertTrue(self.assertion(self.A, "device.surface_test", params)["ok"])
        first = self.call("device.surface_test", params)
        self.assertNotEqual(first["error"]["code"], "PERMISSION_DENIED")  # authorized; fails later (no device)
        self.assertEqual(self.call("device.surface_test", params)["error"]["code"], "PERMISSION_DENIED")
        self.assertTrue(self.assertion(self.A, "device.surface_test", params)["ok"])
        other = {"kname": "sdy", "fingerprint": "0" * 64}
        self.assertEqual(self.call("device.surface_test", other)["error"]["code"], "PERMISSION_DENIED")

    def test_grant_bound_to_connection_and_op(self):
        params = {"kname": "sdz", "fingerprint": "0" * 64}
        self.assertTrue(self.assertion(self.A, "device.surface_test", params)["ok"])
        other_session = Session(1000, 1000, 2)
        self.assertEqual(self.call("device.surface_test", params, session=other_session)["error"]["code"],
                         "PERMISSION_DENIED")
        self.assertEqual(self.call("transfer.release", {"name_policy": "strict"})["error"]["code"],
                         "PERMISSION_DENIED")

    def test_rejected_assertions(self):
        p = {"kname": "sdz", "fingerprint": "0" * 64}
        cases = {
            "wrong namespace": dict(namespace=NS_TRANSFER),
            "other uid": dict(uid=1001),
            "outsider key": dict(signer=self.X),
            "digest swapped": dict(tweak={"request_digest": "1" * 64}),
            "op swapped": dict(tweak={"op": "transfer.release"}),
        }
        for label, kw in cases.items():
            with self.subTest(label):
                signer = kw.pop("signer", self.A)
                resp = self.assertion(signer, "device.surface_test", p, **kw)
                self.assertFalse(resp["ok"])
                self.assertIn(resp["error"]["code"], ("OWNER_KEY_REJECTED", "PERMISSION_DENIED"))
                self.assertEqual(self.call("device.surface_test", p)["error"]["code"], "PERMISSION_DENIED")

    def test_nonce_single_use_and_expiry(self):
        p = {"kname": "sdz", "fingerprint": "0" * 64}
        ch = self.call("auth.challenge")["result"]
        rd = authz.request_digest("device.surface_test", p)
        digest = assertion_digest(nonce=ch["nonce"], broker_id=ch["broker_id"], uid=1000, op="device.surface_test",
                                  request_digest=rd, key_id=self.A.key_id)
        body = {"nonce": ch["nonce"], "key_id": self.A.key_id, "op": "device.surface_test", "request_digest": rd,
                "signature": self.A.sign_ns(NS_OWNER, digest).decode()}
        self.assertTrue(self.call("auth.assert", body)["ok"])
        self.assertEqual(self.call("auth.assert", body)["error"]["code"], "CHALLENGE_INVALID")
        now = [0.0]
        timed = Session(1000, 1000, 3, clock=lambda: now[0])
        ch = self.call("auth.challenge", session=timed)["result"]
        now[0] = 500.0
        digest = assertion_digest(nonce=ch["nonce"], broker_id=ch["broker_id"], uid=1000, op="device.surface_test",
                                  request_digest=rd, key_id=self.A.key_id)
        body = dict(body, nonce=ch["nonce"], signature=self.A.sign_ns(NS_OWNER, digest).decode())
        self.assertEqual(self.call("auth.assert", body, session=timed)["error"]["code"], "CHALLENGE_INVALID")

    def test_revoked_key_cannot_assert(self):
        st = self.services.trust.require_state()
        self.services.trust.append(EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))
        resp = self.assertion(self.B, "device.surface_test", {"kname": "sdz", "fingerprint": "0" * 64})
        self.assertEqual(resp["error"]["code"], "OWNER_KEY_REJECTED")

    def test_capability_still_required(self):
        limited = authz.Principal("op", 1000, frozenset({"auth.assert"}), frozenset({"peer_uid"}))
        p = {"kname": "sdz", "fingerprint": "0" * 64}
        self.assertTrue(self.assertion(self.A, "device.surface_test", p)["ok"])
        resp = self.call("device.surface_test", p, principal=limited)
        self.assertEqual(resp["error"]["code"], "PERMISSION_DENIED")


class EndToEndTests(KeysCase):
    """Real socket, real fd passing, real sandboxed signature verification."""

    def setUp(self):
        from test_runtime import launcher
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        os.chmod(root, 0o755)
        self.root = root
        self.services = build_services(launcher(), root / "state", allowed_key_types=TEST_TYPES)
        policy = authz.Policy([("owner", os.geteuid(), ALL_CAPS)])
        self.sock = root / "b.sock"
        self.server = BrokerServer(self.services.broker, policy, self.sock, idle_timeout=30.0)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BrokerClient(self.sock, timeout=60)
        self.client.connect()

    def tearDown(self):
        self.client.close()
        self.server.stop()
        self.thread.join(5)
        self.tmp.cleanup()

    def init_trust(self):
        return self.client.call("trust.init", {"envelope": EN.genesis([(self.A, "A", None), (self.B, "B", None)])})

    def make_files(self, files):
        src = self.root / "src"
        src.mkdir(exist_ok=True)
        fds = []
        for name, data in files.items():
            (src / name).write_bytes(data)
            fds.append(os.open(src / name, os.O_RDONLY))
        return fds

    def intake(self, files, signer=None):
        fds = self.make_files(files)
        try:
            return call_as_owner(self.client, signer or self.A, "vault.intake", {"names": list(files)}, fds)
        finally:
            for fd in fds:
                os.close(fd)

    def write_transfer(self, record_ids, signer=None, out=None):
        signer = signer or self.A
        prepared = self.client.call("transfer.prepare", {"record_ids": record_ids, "key_id": signer.key_id})
        signature = signer.sign_ns(NS_TRANSFER, bytes.fromhex(prepared["digest"]))
        out = out or self.root / "transfer.gpkg"
        fd = os.open(out, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            return self.client.call("transfer.write", {"transfer_id": prepared["transfer_id"],
                                                       "signature": signature.decode()}, [fd])
        finally:
            os.close(fd)

    def release(self, package, dest, signer=None, policy="strict"):
        fds = [os.open(package, os.O_RDONLY), os.open(dest, os.O_RDONLY | os.O_DIRECTORY)]
        try:
            return call_as_owner(self.client, signer or self.A, "transfer.release", {"name_policy": policy}, fds)
        finally:
            for fd in fds:
                os.close(fd)

    def test_full_transfer_with_two_keys(self):
        status = self.init_trust()
        self.assertEqual(len(status["active"]), 2)
        files = {"report.txt": b"line\r\nexact bytes\x00\xff", "empty.bin": b""}
        records = self.intake(files)["records"]
        written = self.write_transfer([r["record_id"] for r in records])
        self.assertTrue(written["readback_verified"])
        fd = os.open(self.root / "transfer.gpkg", os.O_RDONLY)
        try:
            report = self.client.call("transfer.verify", {"offset": 0}, [fd])
        finally:
            os.close(fd)
        self.assertEqual(report["key_id"], self.A.key_id)
        dest = self.root / "dest"
        dest.mkdir(mode=0o700)
        receipt = self.release(self.root / "transfer.gpkg", dest, signer=self.B)  # backup key releases
        self.assertEqual(sorted(r["name"] for r in receipt["released"]), sorted(files))
        for name, data in files.items():
            self.assertEqual((dest / name).read_bytes(), data)

    def test_owner_operations_refused_without_touch(self):
        self.init_trust()
        fds = self.make_files({"a": b"x"})
        try:
            with self.assertRaises(E.PermissionDenied):
                self.client.call("vault.intake", {"names": ["a"]}, fds)
        finally:
            for fd in fds:
                os.close(fd)
        prepared = self.client.call("transfer.prepare", {
            "record_ids": [self.intake({"a": b"x"})["records"][0]["record_id"]], "key_id": self.A.key_id})
        out = os.open(self.root / "o.gpkg", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            bogus = self.X.sign_ns(NS_TRANSFER, bytes.fromhex(prepared["digest"]))  # not an owner key
            with self.assertRaises(E.PermissionDenied):
                self.client.call("transfer.write", {"transfer_id": prepared["transfer_id"],
                                                    "signature": bogus.decode()}, [out])
            self.assertEqual(os.fstat(out).st_size, 0)
        finally:
            os.close(out)

    def test_revocation_takes_effect_for_existing_packages(self):
        self.init_trust()
        records = self.intake({"a.txt": b"data"})["records"]
        self.write_transfer([records[0]["record_id"]], signer=self.B)
        status = self.client.call("trust.status")
        envelope = EN.revoke(status["head"], status["seq"], self.B.key_id, self.A, "lost")
        self.client.call("trust.append", {"envelope": envelope})
        dest = self.root / "dest"
        dest.mkdir(mode=0o700)
        with self.assertRaises(E.GuardianError) as cm:
            self.release(self.root / "transfer.gpkg", dest)
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")
        self.assertEqual(os.listdir(dest), [])
        # replacement through the remaining key
        status = self.client.call("trust.status")
        self.client.call("trust.append", {"envelope": EN.enroll(status["head"], status["seq"], self.C, "C", None,
                                                                self.A)})
        self.assertEqual({k["label"] for k in self.client.call("trust.status")["active"]}, {"A", "C"})

    def test_trust_init_only_once_and_needs_valid_genesis(self):
        bad = EN.genesis([(self.A, "A", None)])
        bad["event"]["keys"][0]["label"] = "Changed"
        with self.assertRaises(E.GuardianError):
            self.client.call("trust.init", {"envelope": bad})
        self.init_trust()
        with self.assertRaises(E.GuardianError) as cm:
            self.init_trust()
        self.assertEqual(cm.exception.code, "TRUST_ALREADY_INITIALIZED")

    def test_fd_validation(self):
        self.init_trust()
        dfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(E.ValidationError):  # a directory is not a file to take into custody
                call_as_owner(self.client, self.A, "vault.intake", {"names": ["d"]}, [dfd])
        finally:
            os.close(dfd)
        records = self.intake({"a": b"x"})["records"]
        (self.root / "full.gpkg").write_bytes(b"existing")
        with self.assertRaises(E.ValidationError):  # output must be empty
            prepared = self.client.call("transfer.prepare", {"record_ids": [records[0]["record_id"]],
                                                             "key_id": self.A.key_id})
            fd = os.open(self.root / "full.gpkg", os.O_RDWR)
            try:
                self.client.call("transfer.write", {"transfer_id": prepared["transfer_id"], "signature":
                                 self.A.sign_ns(NS_TRANSFER, bytes.fromhex(prepared["digest"])).decode()}, [fd])
            finally:
                os.close(fd)
        self.assertEqual((self.root / "full.gpkg").read_bytes(), b"existing")

    def test_declared_fd_count_must_match(self):
        a, b = socket.socketpair()
        try:
            from usbguardian.runtime import ipc
            ipc.send_frame_fds(self.client._sock, ipc.make_request("x1", "trust.status", {}, fds=2), [a.fileno()])
            resp = ipc.validate_response(ipc.recv_frame(self.client._sock.fileno(), timeout=10))
            self.assertEqual(resp["error"]["code"], "PROTOCOL_ERROR")
        finally:
            a.close()
            b.close()


class ReleaseOwnershipTests(KeysCase):
    @unittest.skipUnless(os.geteuid() == 0, "chown needs root")
    def test_released_files_belong_to_requester(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            os.chmod(root, 0o755)
            store = CustodyStore(root / "store")
            (root / "f").write_bytes(b"data")
            rec = store.intake(root / "f", "f.txt")
            manifest = build_manifest([rec], instance_id="guardian-main", scheme="sshsig", key_id=self.A.key_id)
            pkg = root / "p.gpkg"
            fd = os.open(pkg, os.O_RDWR | os.O_CREAT, 0o600)
            write_package(fd, store, manifest, self.A.for_namespace(NS_TRANSFER))
            os.close(fd)
            st = T.apply_event(None, EN.genesis([(self.A, "A", None)]), tool_verify, allowed_types=TEST_TYPES)
            verifier = T.TrustVerifier(st, tool_verify, NS_TRANSFER)
            dest = root / "dest"
            dest.mkdir(mode=0o700)
            os.chown(dest, 65534, 65534)
            fd = os.open(pkg, os.O_RDONLY)
            dfd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
            try:
                release_package(fd, verifier, dest_fd=dfd, owner=(65534, 65534))
                with self.assertRaises(E.SecurityViolation):  # destination must belong to the requester
                    release_package(fd, verifier, dest_fd=dfd, owner=(1234, 1234))
            finally:
                os.close(fd)
                os.close(dfd)
            st_file = os.lstat(dest / "f.txt")
            self.assertEqual((st_file.st_uid, st_file.st_gid), (65534, 65534))
            self.assertEqual((dest / "f.txt").read_bytes(), b"data")
            fd = os.open(pkg, os.O_RDONLY)
            try:
                verify_package(fd, verifier)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
