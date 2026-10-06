# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 6 Guardian Forge tests (real ssh-keygen, ed25519 keys under the explicit test-only policy)."""

import datetime
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_dumps  # noqa: E402
from usbguardian.forge import profiles as PR  # noqa: E402
from usbguardian.forge.descriptor import (CODE_PREFIX, DESCRIPTOR_NAME, EXCLUDED_CODE, TRUST_LOG_NAME,  # noqa: E402
                                          build_descriptor, check_descriptor, collect_code)
from usbguardian.forge.install import verify_deployment  # noqa: E402
from usbguardian.forge.service import CODE_ROOT, trust_log_bytes  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.owner import call_as_owner  # noqa: E402
from usbguardian.identity.sshsig import NS_DEPLOY, NS_TRANSFER, tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.server import BrokerServer  # noqa: E402
from usbguardian.vault.custody import CustodyStore  # noqa: E402
from usbguardian.vault.package import build_manifest, write_package  # noqa: E402

ALL_CAPS = sorted(authz.CAPABILITIES)


class ProfileTests(unittest.TestCase):
    def test_spinoffs_never_get_forge_capabilities(self):
        for name, caps in PR.PROFILES.items():
            self.assertFalse(caps & PR.FORGE_ONLY, name)
            self.assertIn("auth.assert", caps, name)
        self.assertEqual(PR.profile_capabilities("diagnostic"),
                         sorted({"runtime.status", "auth.assert", "trust.read", "runtime.diagnostics",
                                 "device.inspect", "vault.verify", "lease.read", "lease.manage", "airlock.read"}))

    def test_unavailable_platforms_refused(self):
        PR.check_platform("debian-mx")
        PR.check_platform("rescue-usb")
        for p in ("termux", "windows"):
            with self.assertRaises(E.ValidationError) as cm:
                PR.check_platform(p)
            self.assertEqual(cm.exception.code, "PLATFORM_UNAVAILABLE")
        with self.assertRaises(E.ValidationError):
            PR.check_platform("macos")

    def test_code_collection(self):
        files = collect_code(CODE_ROOT)
        rels = [r for r, _ in files]
        self.assertIn("guardian.py", rels)
        self.assertIn("usbguardian/forge/install.py", rels)
        for excluded in EXCLUDED_CODE:
            self.assertNotIn(excluded, rels)
        self.assertEqual(rels, sorted(rels))
        self.assertTrue(all(r.endswith(".py") for r in rels))

    def test_descriptor_rules(self):
        base = dict(deployment_id="0" * 32, instance_id="laptop", platform="debian-mx", profile="storage",
                    issued="2026-10-06T00:00:00Z", trust={"anchor": "a" * 64, "head": "b" * 64, "seq": 0},
                    issuer_instance="guardian-main", key_id="sha256-" + "c" * 64,
                    code=[{"path": "guardian.py", "sha256": "d" * 64, "length": 1}])
        desc = build_descriptor(**base)
        with self.assertRaises(E.SecurityViolation):
            check_descriptor(dict(desc, capabilities=desc["capabilities"] + ["forge.build"]))
        with self.assertRaises(E.ValidationError):
            check_descriptor(dict(desc, capabilities=["runtime.status"]))  # does not match the profile
        with self.assertRaises(E.ValidationError):
            check_descriptor(dict(desc, code=[{"path": "../x.py", "sha256": "d" * 64, "length": 1}]))


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
class ForgeTests(unittest.TestCase):
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
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o755)
        self.services = build_services(launcher(), self.root / "state", allowed_key_types=TEST_TYPES)
        policy = authz.Policy([("owner", os.geteuid(), ALL_CAPS)])
        self.server = BrokerServer(self.services.broker, policy, self.root / "b.sock", idle_timeout=60.0)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.client = BrokerClient(self.root / "b.sock", timeout=120)
        self.client.connect()
        self.client.call("trust.init", {"envelope": EN.genesis([(self.A, "A", None), (self.B, "B", None)])})

    def tearDown(self):
        self.client.close()
        self.server.stop()
        self.thread.join(5)
        self.tmp.cleanup()

    def forge(self, instance_id="laptop", platform="debian-mx", profile="storage", signer=None,
              namespace=NS_DEPLOY, out=None):
        signer = signer or self.A
        prepared = self.client.call("forge.prepare", {"instance_id": instance_id, "platform": platform,
                                                      "profile": profile, "key_id": signer.key_id})
        out = out or self.root / ("%s.gpkg" % instance_id)
        fd = os.open(out, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            sig = signer.sign_ns(namespace, bytes.fromhex(prepared["digest"]))
            result = self.client.call("forge.write", {"deployment_id": prepared["deployment_id"],
                                                      "signature": sig.decode()}, [fd])
        finally:
            os.close(fd)
        return out, result

    def verify(self, pkg, envelopes=None, anchor=None, **kw):
        envelopes = envelopes if envelopes is not None else self.services.trust.envelopes()
        anchor = anchor or self.services.trust.require_state().anchor
        fd = os.open(pkg, os.O_RDONLY)
        try:
            return verify_deployment(fd, envelopes, anchor, tool_verify, allowed_types=TEST_TYPES, **kw)
        finally:
            os.close(fd)

    def test_build_verify_extract(self):
        pkg, result = self.forge()
        self.assertTrue(result["readback_verified"])
        entries = self.client.call("forge.list")["deployments"]
        self.assertEqual([(e["instance_id"], e["status"]) for e in entries], [("laptop", "active")])
        extract = self.root / "extract"
        extract.mkdir(mode=0o755)
        out = self.verify(pkg, extract_to=extract, expected_platform="debian-mx")
        desc = out["descriptor"]
        self.assertEqual(desc["capabilities"], sorted(PR.PROFILES["storage"]))
        self.assertEqual(desc["trust"]["anchor"], self.services.trust.require_state().anchor)
        for rel, path in collect_code(CODE_ROOT):
            self.assertEqual((extract / rel).read_bytes(), path.read_bytes(), rel)
        self.assertFalse((extract / "usbguardian/runtime/testing_handlers.py").exists())

    def test_backup_key_can_build(self):
        pkg, _ = self.forge(instance_id="rescue", platform="rescue-usb", profile="recovery", signer=self.B)
        self.assertEqual(self.verify(pkg)["descriptor"]["issuer"]["key_id"], self.B.key_id)

    def test_transfer_namespace_signature_cannot_deploy(self):
        with self.assertRaises(E.PermissionDenied):
            self.forge(namespace=NS_TRANSFER)
        with self.assertRaises(E.ValidationError):  # outsider key refused before anything is built
            self.forge(instance_id="other", signer=self.X)
        self.assertEqual(self.client.call("forge.list")["deployments"], [])

    def test_deployment_is_not_a_transfer_and_vice_versa(self):
        pkg, _ = self.forge()
        fd = os.open(pkg, os.O_RDONLY)
        try:
            with self.assertRaises(E.GuardianError) as cm:
                self.client.call("transfer.verify", {"offset": 0}, [fd])
        finally:
            os.close(fd)
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")
        # a transfer package (transfer namespace) is refused by the installer
        (self.root / "f").write_bytes(b"x")
        fd = os.open(self.root / "f", os.O_RDONLY)
        try:
            rec = call_as_owner(self.client, self.A, "vault.intake", {"names": ["deployment.json"]}, [fd])["records"]
        finally:
            os.close(fd)
        prepared = self.client.call("transfer.prepare", {"record_ids": [rec[0]["record_id"]], "key_id": self.A.key_id})
        out = os.open(self.root / "t.gpkg", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            self.client.call("transfer.write", {"transfer_id": prepared["transfer_id"], "signature":
                             self.A.sign_ns(NS_TRANSFER, bytes.fromhex(prepared["digest"])).decode()}, [out])
        finally:
            os.close(out)
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(self.root / "t.gpkg")
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")

    def test_pinned_anchor_and_forks(self):
        pkg, _ = self.forge()
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(pkg, anchor="f" * 64)
        self.assertEqual(cm.exception.code, "TRUST_ANCHOR_MISMATCH")
        envelopes = self.services.trust.envelopes()
        st = self.services.trust.require_state()
        # a later, consistent trust log on the Rescue USB is fine
        later = envelopes + [EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost")]
        self.verify(pkg, envelopes=later)
        # build a deployment after an event, then present a diverging branch
        self.services.trust.append(EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost"))
        pkg2, _ = self.forge(instance_id="desk")
        fork = envelopes + [EN.revoke(st.head, st.seq, self.B.key_id, self.B, "retired")]
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(pkg2, envelopes=fork)
        self.assertEqual(cm.exception.code, "TRUST_FORK")

    def test_revoked_issuer_rejected(self):
        pkg, _ = self.forge(signer=self.B)
        st = self.services.trust.require_state()
        later = self.services.trust.envelopes() + [EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost")]
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(pkg, envelopes=later)
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")

    def test_instance_ids_unique_and_retire(self):
        self.forge()
        with self.assertRaises(E.GuardianError) as cm:  # custom codes arrive as GuardianError + code
            self.client.call("forge.prepare", {"instance_id": "laptop", "platform": "debian-mx",
                                               "profile": "storage", "key_id": self.A.key_id})
        self.assertEqual(cm.exception.code, "INSTANCE_EXISTS")
        first = self.client.call("forge.list")["deployments"][0]["deployment_id"]
        prepared = self.client.call("forge.prepare", {"instance_id": "laptop", "platform": "debian-mx",
                                                      "profile": "storage", "key_id": self.A.key_id,
                                                      "redeploy": True})
        fd = os.open(self.root / "update.gpkg", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            self.client.call("forge.write", {"deployment_id": prepared["deployment_id"], "signature":
                             self.A.sign_ns(NS_DEPLOY, bytes.fromhex(prepared["digest"])).decode()}, [fd])
        finally:
            os.close(fd)
        entry = self.client.call("forge.list")["deployments"][0]
        self.assertEqual((entry["deployment_id"], entry["previous"]), (prepared["deployment_id"], [first]))
        with self.assertRaises(E.GuardianError):  # redeploy keeps the platform
            self.client.call("forge.prepare", {"instance_id": "laptop", "platform": "rescue-usb",
                                               "profile": "storage", "key_id": self.A.key_id, "redeploy": True})
        with self.assertRaises(E.GuardianError):
            self.client.call("forge.prepare", {"instance_id": "guardian-main", "platform": "debian-mx",
                                               "profile": "storage", "key_id": self.A.key_id})
        with self.assertRaises(E.PermissionDenied):
            self.client.call("forge.retire", {"instance_id": "laptop"})  # needs a touch
        retired = call_as_owner(self.client, self.A, "forge.retire", {"instance_id": "laptop"})
        self.assertEqual(retired["status"], "retired")
        with self.assertRaises(E.ValidationError):
            call_as_owner(self.client, self.A, "forge.retire", {"instance_id": "laptop"})

    def test_unavailable_platform(self):
        with self.assertRaises(E.GuardianError) as cm:
            self.client.call("forge.prepare", {"instance_id": "phone", "platform": "termux", "profile": "storage",
                                               "key_id": self.A.key_id})
        self.assertEqual(cm.exception.code, "PLATFORM_UNAVAILABLE")

    def test_wrong_platform_and_expiry(self):
        pkg, _ = self.forge()
        with self.assertRaises(E.ValidationError) as cm:
            self.verify(pkg, expected_platform="rescue-usb")
        self.assertEqual(cm.exception.code, "WRONG_PLATFORM")
        expired = self._manual_deployment(expires="2026-01-01T00:00:00Z")
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(expired, now=datetime.datetime(2026, 10, 6, tzinfo=datetime.timezone.utc))
        self.assertEqual(cm.exception.code, "DEPLOYMENT_EXPIRED")

    def test_deploy_signed_package_with_wrong_layout_refused(self):
        bad = self._manual_deployment(layout="flat")
        with self.assertRaises(E.SecurityViolation) as cm:
            self.verify(bad)
        self.assertEqual(cm.exception.code, "NOT_A_DEPLOYMENT")

    def _manual_deployment(self, expires=None, layout="normal"):
        """Owner-signed deployment built by hand, for cases the service never produces."""
        store = CustodyStore(self.root / "manual-store")
        st = self.services.trust.require_state()
        envelopes = self.services.trust.envelopes()
        code_recs, code = [], []
        for rel, path in collect_code(CODE_ROOT)[:3]:
            rec = store.intake(path, CODE_PREFIX + rel)
            code_recs.append(rec)
            code.append({"path": rel, "sha256": rec["sha256"], "length": rec["length"]})
        desc = build_descriptor(deployment_id="1" * 32, instance_id="manual", platform="debian-mx",
                                profile="diagnostic", issued="2025-12-01T00:00:00Z",
                                trust={"anchor": st.anchor, "head": st.head, "seq": st.seq},
                                issuer_instance="guardian-main", key_id=self.A.key_id, code=code, expires=expires)
        records = [store.intake_bytes(canonical_dumps(desc), DESCRIPTOR_NAME),
                   store.intake_bytes(trust_log_bytes(envelopes), TRUST_LOG_NAME)] + code_recs
        if layout == "flat":
            records = [store.intake_bytes(b"payload", "anything.txt")]
        manifest = build_manifest(records, instance_id="guardian-main", scheme="sshsig", key_id=self.A.key_id,
                                  transfer_id="1" * 32)
        out = self.root / ("manual-%s.gpkg" % layout)
        fd = os.open(out, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            write_package(fd, store, manifest, self.A.for_namespace(NS_DEPLOY))
        finally:
            os.close(fd)
        return out


if __name__ == "__main__":
    unittest.main()
