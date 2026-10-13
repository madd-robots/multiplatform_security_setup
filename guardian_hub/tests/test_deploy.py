# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 7 Debian/MX installer tests.  Everything is installed under temporary roots."""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_dumps, canonical_loads  # noqa: E402
from usbguardian.deploy.debian import InstallLayout, install_debian, read_anchor  # noqa: E402
from usbguardian.forge.profiles import PROFILES  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.sshsig import NS_DEPLOY, tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.client import BrokerClient  # noqa: E402
from usbguardian.runtime.session import Session  # noqa: E402
from usbguardian.runtime.workers import verify_code_tree  # noqa: E402

ALL_CAPS = frozenset(authz.CAPABILITIES)
WORKER = "nobody"


def _req(op, params, fds=0, n=[0]):
    n[0] += 1
    request = {"v": 1, "type": "request", "id": "r%d" % n[0], "op": op, "params": params}
    if fds:
        request["fds"] = fds
    return request


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
@unittest.skipUnless(os.geteuid() == 0, "the installer requires root")
class DebianInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_runtime import launcher
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        os.chmod(root, 0o755)
        cls.A, cls.B = (_keygen(root, n) for n in ("a", "b"))
        cls.services = build_services(launcher(), root / "main", allowed_key_types=TEST_TYPES)
        cls.services.trust.append(EN.genesis([(cls.A, "A", None), (cls.B, "B", None)]))
        cls.media = root / "media"  # what the owner carries on the Rescue USB
        cls.media.mkdir()
        shutil.copy(root / "main" / "trust" / "trust.log", cls.media / "trust.log")
        shutil.copy(root / "main" / "trust" / "trust.anchor", cls.media / "trust.anchor")
        cls.pkg1 = cls._forge(root, "desk", "debian-mx", "storage")
        cls.pkg2 = cls._forge(root, "laptop", "debian-mx", "diagnostic")
        cls.pkg_rescue = cls._forge(root, "rescue", "rescue-usb", "recovery")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    @classmethod
    def _forge(cls, root, instance_id, platform, profile):
        principal = authz.Principal("owner", 0, ALL_CAPS, frozenset({"peer_uid"}))
        session = Session(0, 0, 1)
        broker = cls.services.broker
        prep = broker.handle(principal, _req("forge.prepare", {"instance_id": instance_id, "platform": platform,
                                                               "profile": profile, "key_id": cls.A.key_id}), session)
        assert prep["ok"], prep
        out = root / ("%s.gpkg" % instance_id)
        session.fds = [os.open(out, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)]
        sig = cls.A.sign_ns(NS_DEPLOY, bytes.fromhex(prep["result"]["digest"])).decode()
        resp = broker.handle(principal, _req("forge.write", {"deployment_id": prep["result"]["deployment_id"],
                                                             "signature": sig}, fds=1), session)
        session.close_fds()
        assert resp["ok"], resp
        return out

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        r = Path(self.tmp.name)
        os.chmod(r, 0o755)
        self.layout = InstallLayout(prefix=r / "opt", state_dir=r / "state", etc_dir=r / "etc",
                                    initd_dir=r / "initd", run_dir=r / "run", log_file=r / "broker.log")

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, pkg=None, **kw):
        kw.setdefault("owner_uid", 0)
        kw.setdefault("worker_user", WORKER)
        return install_debian(pkg or self.pkg1, kw.pop("trust_log", self.media / "trust.log"),
                              kw.pop("anchor_file", self.media / "trust.anchor"), sig_check=tool_verify,
                              layout=self.layout, allowed_types=TEST_TYPES, **kw)

    def releases(self):
        return sorted(os.listdir(self.layout.releases)) if self.layout.releases.exists() else []

    def test_install_layout(self):
        report = self.install()
        current = self.layout.current
        self.assertTrue(os.path.islink(current))
        target = Path(os.path.realpath(current))
        self.assertEqual(target, Path(report["release"]))
        verify_code_tree(target / "usbguardian")  # root-owned, nothing writable by others
        for dirpath, dirnames, filenames in os.walk(target):
            for name in filenames:
                st = os.lstat(os.path.join(dirpath, name))
                self.assertEqual((st.st_uid, stat.S_IMODE(st.st_mode)), (0, 0o644), name)
        self.assertFalse((target / "usbguardian/runtime/testing_handlers.py").exists())
        for name in ("trust/trust.log", "trust/trust.anchor", "deployment.json"):
            self.assertEqual(stat.S_IMODE(os.lstat(self.layout.state_dir / name).st_mode), 0o600, name)
        self.assertEqual(read_anchor(self.layout.state_dir / "trust" / "trust.anchor"),
                         read_anchor(self.media / "trust.anchor"))
        policy = canonical_loads((self.layout.etc_dir / "policy.json").read_bytes())
        self.assertEqual(policy["principals"][0]["capabilities"], sorted(PROFILES["storage"]))
        script = self.layout.initd_dir / "usbguardian"
        self.assertEqual(stat.S_IMODE(os.lstat(script).st_mode), 0o755)
        subprocess.run(["sh", "-n", str(script)], check=True)
        text = script.read_text()
        for needle in (str(self.layout.current / "guardian.py"), "--worker-user nobody", "--instance-id desk"):
            self.assertIn(needle, text)
        self.assertIn("block", (self.layout.etc_dir / "usbguard-rules.suggested").read_text())
        self.assertFalse(report["service_enabled"])

    def test_installed_code_runs_a_broker(self):
        self.install()
        guardian = self.layout.current / "guardian.py"
        out = subprocess.run([sys.executable, "-I", "-B", str(guardian), "key-info", self.A.handle_path + ".pub"],
                             capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(out.stdout)["key_id"], self.A.key_id)
        os.makedirs(self.layout.run_dir, mode=0o755, exist_ok=True)
        sock = self.layout.run_dir / "b.sock"
        proc = subprocess.Popen([sys.executable, "-I", "-B", str(guardian), "broker",
                                 "--policy", str(self.layout.etc_dir / "policy.json"), "--socket", str(sock),
                                 "--state-dir", str(self.layout.state_dir), "--worker-user", WORKER,
                                 "--instance-id", "desk"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if sock.exists() or proc.poll() is not None:
                    break
                time.sleep(0.1)
            self.assertTrue(sock.exists(), proc.stderr.read(4000) if proc.poll() is not None else "no socket")
            with BrokerClient(sock, timeout=30) as client:
                self.assertEqual(client.call("runtime.status")["principal"], "owner")
                # The production broker accepts only hardware keys, so the test keys are refused.
                with self.assertRaises(E.GuardianError) as cm:
                    client.call("trust.status")
                self.assertEqual(cm.exception.code, "TRUST_INVALID")
        finally:
            proc.terminate()
            proc.wait(10)
            proc.stderr.close()

    def test_tampered_package_leaves_no_trace(self):
        bad = Path(self.tmp.name) / "bad.gpkg"
        data = bytearray(self.pkg1.read_bytes())
        data[len(data) // 2] ^= 1
        bad.write_bytes(bytes(data))
        with self.assertRaises(E.GuardianError):
            self.install(bad)
        self.assertEqual(self.releases(), [])
        self.assertFalse(os.path.lexists(self.layout.current))
        self.assertFalse(self.layout.state_dir.exists())

    def test_wrong_anchor_and_platform(self):
        other = Path(self.tmp.name) / "anchor"
        other.write_bytes(canonical_dumps({"anchor": "f" * 64}))
        with self.assertRaises(E.IntegrityError):
            self.install(anchor_file=other)
        with self.assertRaises(E.ValidationError) as cm:
            self.install(self.pkg_rescue)  # rescue-usb deployment on the debian-mx installer
        self.assertEqual(cm.exception.code, "WRONG_PLATFORM")
        self.install(self.pkg_rescue, platform="rescue-usb")
        self.assertEqual(len(self.releases()), 1)

    def test_reinstall_refused_and_switch(self):
        first = self.install()
        with self.assertRaises(E.ValidationError) as cm:
            self.install()
        self.assertEqual(cm.exception.code, "ALREADY_INSTALLED")
        second = self.install(self.pkg2, replace_policy=True)
        self.assertEqual(os.path.realpath(self.layout.current), second["release"])
        self.assertTrue(os.path.isdir(first["release"]))  # previous release kept for rollback
        self.assertEqual([n for n in self.releases() if n.startswith(".")], [])

    def test_existing_policy_preserved(self):
        self.layout.etc_dir.mkdir(mode=0o755)
        (self.layout.etc_dir / "policy.json").write_bytes(b'{"principals":[],"version":1}')
        report = self.install()
        self.assertFalse(report["policy_written"])
        self.assertEqual((self.layout.etc_dir / "policy.json").read_bytes(), b'{"principals":[],"version":1}')

    def test_trust_state_merge(self):
        self.install()
        st = self.services.trust.require_state()
        envelopes = self.services.trust.envelopes()
        longer = envelopes + [EN.revoke(st.head, st.seq, self.B.key_id, self.A, "lost")]
        log = self.layout.state_dir / "trust" / "trust.log"
        log.write_bytes(b"".join(canonical_dumps(e) + b"\n" for e in longer))
        self.install(self.pkg2)  # shorter provided log: the longer installed one is kept
        self.assertEqual(len(log.read_bytes().splitlines()), 2)
        fork = envelopes + [EN.revoke(st.head, st.seq, self.B.key_id, self.B, "retired")]
        log.write_bytes(b"".join(canonical_dumps(e) + b"\n" for e in fork))
        media_log = Path(self.tmp.name) / "trust.log"
        media_log.write_bytes(b"".join(canonical_dumps(e) + b"\n" for e in longer))
        with self.assertRaises(E.IntegrityError) as cm:
            self.install(self.pkg_rescue, platform="rescue-usb", trust_log=media_log)
        self.assertEqual(cm.exception.code, "TRUST_FORK")
        self.assertEqual(len(self.releases()), 2)

    def test_dry_run_leaves_nothing(self):
        report = self.install(dry_run=True)
        self.assertTrue(report["dry_run"])
        self.assertEqual(self.releases(), [])
        self.assertFalse(self.layout.state_dir.exists())
        self.assertFalse(self.layout.etc_dir.exists())

    def test_worker_user_checks(self):
        with self.assertRaises(E.ConfigError):
            self.install(worker_user="no-such-user-guardian")
        with self.assertRaises(E.ConfigError):
            self.install(worker_user="root")
        self.assertEqual(self.releases(), [])


if __name__ == "__main__":
    unittest.main()
