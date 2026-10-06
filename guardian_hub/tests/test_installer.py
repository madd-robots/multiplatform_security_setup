# SPDX-License-Identifier: GPL-3.0-or-later
"""Installer v2 tests: SysVinit preflight, dependency inventory, offline bundle, plan/apply/validate/uninstall.

The host (PID 1, /etc, rc directories, dpkg answers) is a fixture under a
temporary root, and every external command goes through a recording fake
runner, so nothing on the machine running the tests is changed.
"""

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from test_identity import SSH_KEYGEN, TEST_TYPES, _keygen  # noqa: E402

from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.deploy import inventory as INV  # noqa: E402
from usbguardian.deploy.bundle import build_bundle, check_target, verify_bundle  # noqa: E402
from usbguardian.deploy.debian import InstallLayout, read_anchor  # noqa: E402
from usbguardian.deploy.installer import apply_install, plan_install, uninstall, validate_install  # noqa: E402
from usbguardian.deploy.preflight import MISMATCH, sysvinit_preflight  # noqa: E402
from usbguardian.forge.service import CODE_ROOT  # noqa: E402
from usbguardian.identity import enrollment as EN  # noqa: E402
from usbguardian.identity.sshsig import NS_DEPLOY, tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.session import Session  # noqa: E402

ALL_CAPS = frozenset(authz.CAPABILITIES)
INIT_PKGS = ("sysvinit-core", "sysv-rc", "initscripts", "init-system-helpers")


class FakeHost:
    """A SysVinit machine under a temporary root, plus a runner that answers like dpkg, apt and friends."""

    def __init__(self, root: Path, comm="init"):
        self.fs = root / "fs"
        self.proc = root / "proc"
        (self.proc / "1").mkdir(parents=True)
        (self.proc / "1" / "comm").write_text(comm + "\n")
        (self.proc / "1" / "cmdline").write_bytes(b"/sbin/init\x00")
        for d in ("etc/init.d", "sbin", "usr/sbin") + tuple("etc/rc%s.d" % r for r in "0123456S"):
            (self.fs / d).mkdir(parents=True, exist_ok=True)
            os.chmod(self.fs / d, 0o755)
        for tool in ("sbin/init", "usr/sbin/update-rc.d", "usr/sbin/invoke-rc.d", "sbin/start-stop-daemon"):
            (self.fs / tool).write_bytes(b"\x7fELF")
            os.chmod(self.fs / tool, 0o755)
        (self.fs / "etc/os-release").write_text('ID=debian\nVERSION_ID="12"\nPRETTY_NAME="MX 23"\n')
        (self.fs / "etc/mx-version").write_text("MX-23.6_x64 Libretto September 15  2024\n")
        (self.fs / "etc/debian_version").write_text("12.9\n")
        self.installed = {p: "1.0" for p in INIT_PKGS + ("python3", "openssh-client", "dpkg", "apt", "mount",
                                                         "adduser")}
        self.verify_output = ""
        self.runlevel = (0, "N 5\n", "")
        self.init_owner = "sysvinit-core"
        self.calls = []

    def run(self, argv):
        self.calls.append(list(argv))
        a = list(argv)
        if a[:2] == ["dpkg-query", "-S"]:
            return 0, "%s: %s\n" % (self.init_owner, a[2]), ""
        if a[:3] == ["dpkg-query", "-W", "-f=${Version}"]:
            return 0, "3.06-4", ""
        if a[:2] == ["dpkg-query", "-W"]:
            pkg = a[-1]
            if pkg not in self.installed:
                return 1, "", "no packages found matching %s" % pkg
            if a[2] == "-f=${db:Status-Abbrev}":
                return 0, "ii ", ""
            return 0, "ii \t%s\tamd64" % self.installed[pkg], ""
        if a == ["runlevel"]:
            return self.runlevel
        if a == ["dpkg", "--audit"]:
            return 0, "", ""
        if a[:2] == ["dpkg", "--verify"]:
            return (1 if self.verify_output else 0), self.verify_output, ""
        if a == ["dpkg", "--print-architecture"]:
            return 0, "amd64\n", ""
        if a[:2] == ["apt-get", "install"]:
            for path in a[5:]:
                self.installed[Path(path).name.split("_")[0]] = "9.9"
            return 0, "", ""
        if a[:2] == ["update-rc.d", "usbguardian"]:
            for r, kind in (("2", "S"), ("3", "S"), ("4", "S"), ("5", "S"), ("0", "K"), ("1", "K"), ("6", "K")):
                link = self.fs / ("etc/rc%s.d" % r) / ("%s01usbguardian" % kind)
                if a[2] == "defaults" and not os.path.lexists(link):
                    os.symlink("../init.d/usbguardian", link)
                elif a[2] == "remove" and os.path.lexists(link):
                    os.unlink(link)
            return 0, "", ""
        if a[:2] == ["dpkg-deb", "--field"]:
            name = Path(a[2]).name.split("_")
            return 0, "Package: %s\nVersion: %s\nArchitecture: %s\n" % (name[0], name[1], name[2][:-4]), ""
        return 127, "", "unexpected command %s" % a


@unittest.skipUnless(os.geteuid() == 0, "fixture ownership checks need root")
class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.host = FakeHost(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def preflight(self):
        return sysvinit_preflight(proc_root=self.host.proc, fs_root=self.host.fs, run=self.host.run)

    def status(self, report, check):
        return [c for c in report["checks"] if c["check"] == check][0]

    def test_healthy_sysvinit(self):
        report = self.preflight()
        self.assertEqual(report["result"], "PASS", report["checks"])
        self.assertIn("not proof", report["note"])

    def test_systemd_or_other_init_is_a_mismatch(self):
        (self.host.proc / "1" / "comm").write_text("systemd\n")
        report = self.preflight()
        self.assertEqual(report["result"], "BLOCKED")
        self.assertIn(MISMATCH, self.status(report, "pid1")["detail"])
        (self.host.proc / "1" / "comm").write_text("init\n")
        (self.host.fs / "run/systemd/system").mkdir(parents=True)
        self.assertEqual(self.preflight()["result"], "BLOCKED")
        shutil.rmtree(self.host.fs / "run")
        (self.host.proc / "1" / "comm").write_text("runit\n")
        self.assertEqual(self.preflight()["result"], "BLOCKED")
        (self.host.proc / "1" / "comm").write_text("init\n")
        self.host.init_owner = "systemd-sysv"
        self.assertEqual(self.preflight()["result"], "BLOCKED")

    def test_unknown_never_passes(self):
        self.host.runlevel = (127, "", "missing")
        self.assertEqual(self.preflight()["result"], "UNKNOWN")
        self.host.runlevel = (0, "unknown\n", "")
        self.assertEqual(self.preflight()["result"], "UNKNOWN")

    def test_dpkg_verification(self):
        self.host.verify_output = "??5?????? c /etc/inittab\n"
        self.assertEqual(self.preflight()["result"], "PASS")  # changed configuration is expected, recorded
        self.host.verify_output = "??5??????   /usr/share/doc/sysv-rc/README\n"
        self.assertEqual(self.preflight()["result"], "PASS WITH FINDINGS")
        self.host.verify_output = "??5??????   /sbin/init\n"
        report = self.preflight()
        self.assertEqual(report["result"], "BLOCKED")
        critical = self.status(report, "dpkg_verify_critical")
        self.assertEqual(critical["evidence"]["path"], "/sbin/init")
        self.assertEqual(critical["method"], "dpkg --verify")

    def test_writable_init_infrastructure_blocks(self):
        os.chmod(self.host.fs / "etc/init.d", 0o777)
        self.assertEqual(self.status(self.preflight(), "init_d")["status"], "blocking")
        os.chmod(self.host.fs / "etc/init.d", 0o755)
        os.chmod(self.host.fs / "usr/sbin/update-rc.d", 0o777)
        self.assertEqual(self.preflight()["result"], "BLOCKED")
        os.chmod(self.host.fs / "usr/sbin/update-rc.d", 0o755)
        shutil.rmtree(self.host.fs / "etc/rc3.d")
        self.assertEqual(self.preflight()["result"], "BLOCKED")


class InventoryTests(unittest.TestCase):
    def test_inventory_covers_every_tool_the_code_uses(self):
        used = INV.referenced_tools(CODE_ROOT)
        self.assertTrue({"ssh-keygen", "clamscan", "mount", "update-rc.d", "apt-get", "dpkg-query"} <= used, used)
        self.assertEqual(used - set(INV.TOOLS), set(), "tools used by the code but missing from the inventory")
        classes = {r["class"] for r in INV.inventory()}
        self.assertTrue(classes <= {INV.REQUIRED_RUNTIME, INV.REQUIRED_INSTALLER, INV.OPTIONAL_FEATURE,
                                    INV.HARDWARE_FEATURE, INV.DEVELOPMENT_TEST})
        self.assertEqual({r["package"]: r["class"] for r in INV.inventory()}["openssh-client"], INV.REQUIRED_RUNTIME)


def _req(op, params, fds=0, n=[0]):
    n[0] += 1
    request = {"v": 1, "type": "request", "id": "r%d" % n[0], "op": op, "params": params}
    if fds:
        request["fds"] = fds
    return request


@unittest.skipIf(SSH_KEYGEN is None, "ssh-keygen (openssh-client) is not installed")
@unittest.skipUnless(os.geteuid() == 0, "the installer requires root")
class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_runtime import launcher
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        os.chmod(root, 0o755)
        cls.A, cls.X = (_keygen(root, n) for n in ("a", "x"))
        cls.services = build_services(launcher(), root / "main", allowed_key_types=TEST_TYPES)
        cls.services.trust.append(EN.genesis([(cls.A, "A", None)]))
        cls.media = root / "media"
        cls.media.mkdir()
        shutil.copy(root / "main" / "trust" / "trust.log", cls.media / "trust.log")
        shutil.copy(root / "main" / "trust" / "trust.anchor", cls.media / "trust.anchor")
        cls.debs = root / "debs"
        cls.debs.mkdir()
        for name in ("clamav_1.0.7+dfsg-1_amd64.deb", "libclamav11_1.0.7+dfsg-1_amd64.deb",
                     "clamav-freshclam_1.0.7+dfsg-1_amd64.deb", "openssh-client_9.2p1-2_amd64.deb"):
            (cls.debs / name).write_bytes(b"!<arch>\n" + name.encode())
        cls.root = root
        cls.pkg_desk = cls._forge("desk")
        cls.pkg_lap = cls._forge("lap")
        cls.pkg_desk2 = cls._forge("desk", redeploy=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    @classmethod
    def _forge(cls, instance_id, redeploy=False):
        principal = authz.Principal("owner", 0, ALL_CAPS, frozenset({"peer_uid"}))
        session = Session(0, 0, 1)
        broker = cls.services.broker
        params = {"instance_id": instance_id, "platform": "debian-mx", "profile": "storage", "key_id": cls.A.key_id}
        if redeploy:
            params["redeploy"] = True
        prep = broker.handle(principal, _req("forge.prepare", params), session)
        assert prep["ok"], prep
        out = cls.root / ("%s-%s.gpkg" % (instance_id, prep["result"]["deployment_id"][:6]))
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
        self.r = r
        self.host = FakeHost(r)
        self.layout = InstallLayout(prefix=r / "opt", state_dir=r / "state", etc_dir=r / "etc",
                                    initd_dir=self.host.fs / "etc/init.d", run_dir=r / "run",
                                    log_file=r / "broker.log")
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def bundle(self, pkg=None, signer=None, target=None, debs=True):
        self.n += 1
        out = self.r / ("bundle%d" % self.n)
        build_bundle(out, deployment=pkg or self.pkg_desk, trust_log=self.media / "trust.log",
                     anchor_file=self.media / "trust.anchor", debs_dir=self.debs if debs else None,
                     target=target or {"distribution": "mx", "release": "23", "debian": "12", "architecture": "amd64"},
                     signer=signer or self.A, sig_check=tool_verify, created="2026-10-06T00:00:00Z",
                     allowed_types=TEST_TYPES, run=self.host.run)
        return out

    def common(self, **kw):
        return dict(dict(layout=self.layout, owner_uid=0, worker_user="nobody", enable_service=True,
                         sig_check=tool_verify, allowed_types=TEST_TYPES, fs_root=self.host.fs,
                         proc_root=self.host.proc, sysfs_root=self.r / "sys", run=self.host.run), **kw)

    def plan(self, bundle, **kw):
        return plan_install(bundle, **self.common(**kw))

    def apply(self, bundle, confirm=None, **kw):
        plan = self.plan(bundle, **kw)
        return apply_install(bundle, confirm=confirm or plan["plan_id"], python=sys.executable, **self.common(**kw))

    def test_bundle_verification(self):
        b = self.bundle()
        manifest = verify_bundle(b, tool_verify, allowed_types=TEST_TYPES)
        self.assertEqual(sorted(p["name"] for p in manifest["packages"]),
                         ["clamav", "clamav-freshclam", "libclamav11", "openssh-client"])
        self.assertFalse(any("key" in f["path"] and "pub" not in f["path"] for f in manifest["files"]))
        self.assertNotIn(self.A.handle_path, (b / "manifest.json").read_text())  # no private key or handle

        def fails(mutate, code="BUNDLE_INTEGRITY_FAILURE"):
            c = self.bundle()
            mutate(c)
            with self.assertRaises(E.GuardianError) as cm:
                verify_bundle(c, tool_verify, allowed_types=TEST_TYPES)
            self.assertEqual(cm.exception.code, code)
        fails(lambda c: (c / "packages" / "clamav_1.0.7+dfsg-1_amd64.deb").write_bytes(b"evil"))
        fails(lambda c: (c / "packages" / "extra_1_amd64.deb").write_bytes(b"x"))  # closed bundle
        fails(lambda c: os.unlink(c / "packages" / "libclamav11_1.0.7+dfsg-1_amd64.deb"))
        fails(lambda c: os.symlink("/etc/passwd", c / "packages" / "link.deb"))
        fails(lambda c: (c / "manifest.json").write_bytes((c / "manifest.json").read_bytes().replace(b'"23"', b'"25"')))
        outsider = self.r / "outsider"
        build_bundle(outsider, deployment=self.pkg_desk, trust_log=self.media / "trust.log",
                     anchor_file=self.media / "trust.anchor", debs_dir=None,
                     target={"distribution": "mx", "release": "23", "debian": "12", "architecture": "amd64"},
                     signer=_Outsider(self.X, self.A.key_id), sig_check=tool_verify, created="2026-10-06T00:00:00Z",
                     allowed_types=TEST_TYPES, run=self.host.run)
        with self.assertRaises(E.GuardianError) as cm:
            verify_bundle(outsider, tool_verify, allowed_types=TEST_TYPES)
        self.assertEqual(cm.exception.code, "BUNDLE_INTEGRITY_FAILURE")
        with self.assertRaises(E.IntegrityError) as cm:
            verify_bundle(b, tool_verify, allowed_types=TEST_TYPES, expected_anchor="0" * 64)
        self.assertEqual(cm.exception.code, "TRUST_ANCHOR_MISMATCH")
        with self.assertRaises(E.ValidationError) as cm:
            check_target(manifest, {"distribution": "mx", "release": "25", "debian": "13", "architecture": "amd64"})
        self.assertEqual(cm.exception.code, "BUNDLE_TARGET_MISMATCH")

    def test_plan_apply_verify_repair_update_uninstall(self):
        b = self.bundle()
        plan = self.plan(b)
        self.assertEqual((plan["status"], plan["mode"]), ("READY", "INSTALL"), plan["blocked_reasons"])
        for key in ("packages_to_remove", "broad_os_upgrades", "bootloader_changes", "init_system_conversion",
                    "systemd_installation", "packages_to_upgrade"):
            self.assertEqual(plan[key], "NONE")
        self.assertEqual([p["name"] for p in plan["packages_to_install"]],
                         ["clamav", "clamav-freshclam", "libclamav11"])  # openssh-client already installed
        with self.assertRaises(E.GuardianError) as cm:
            self.apply(b, confirm="0" * 24)
        self.assertEqual(cm.exception.code, "PLAN_CHANGED")
        report = self.apply(b)
        self.assertEqual(report["validation"]["result"], "PASS", report["validation"]["checks"])
        apt = [c for c in self.host.calls if c[:1] == ["apt-get"]]
        self.assertEqual(len(apt), 1)
        self.assertEqual(apt[0][:5], ["apt-get", "install", "-y", "--no-install-recommends", "--no-upgrade"])
        forbidden = {"upgrade", "dist-upgrade", "full-upgrade", "--allow-unauthenticated", "remove", "purge"}
        for call in self.host.calls:
            self.assertFalse(forbidden & set(call), call)
            self.assertNotIn("systemctl", call)
        self.assertEqual(len([c for c in self.host.calls if c[:2] == ["update-rc.d", "usbguardian"]]), 1)
        self.assertTrue((self.layout.state_dir / "install.json").exists())
        self.assertIn("installer.apply", [r["entry"]["event"] for r in
                                          __import__("usbguardian.audit.ledger", fromlist=["x"]).AuditLedger(
                                              self.layout.state_dir / "audit").entries(0, 100)])
        # idempotent: second run is VERIFY, installs nothing and registers nothing again
        again = self.plan(b)
        self.assertEqual((again["mode"], again["packages_to_install"], again["service_actions"]), ("VERIFY", [], []))
        calls = len(self.host.calls)
        self.apply(b)
        self.assertFalse([c for c in self.host.calls[calls:] if c[:1] in (["apt-get"], ["update-rc.d"])])
        # Guardian's own damage is repaired from the bundle; the damaged copy is kept as evidence
        release = Path(os.path.realpath(self.layout.current))
        target = release / "usbguardian" / "app.py"
        os.chmod(target, 0o644)
        target.write_bytes(target.read_bytes() + b"\n# tampered\n")
        self.assertEqual(validate_install(self.layout, fs_root=self.host.fs, proc_root=self.host.proc,
                                          run=self.host.run)["result"], "FAILED")
        repair = self.plan(b)
        self.assertEqual(repair["mode"], "REPAIR")
        self.assertIn("modified: usbguardian/app.py", repair["damaged_guardian_files"])
        self.assertEqual(self.apply(b)["validation"]["result"], "PASS")
        self.assertTrue([n for n in os.listdir(self.layout.releases) if n.startswith(".damaged-")])
        # a different instance's bundle never overwrites this machine's identity
        other = self.plan(self.bundle(self.pkg_lap, debs=False))
        self.assertEqual((other["status"], other["mode"]), ("BLOCKED", "BLOCKED"))
        # a newer deployment of the same instance is an UPDATE
        upd = self.bundle(self.pkg_desk2, debs=False)
        self.assertEqual(self.plan(upd)["mode"], "UPDATE")
        self.assertEqual(self.apply(upd)["validation"]["result"], "PASS")
        # uninstall removes code and service, keeps state, keys and configuration
        removed = uninstall(self.layout, fs_root=self.host.fs, run=self.host.run, proc_root=self.host.proc)
        self.assertFalse(self.layout.prefix.exists())
        self.assertFalse((self.layout.initd_dir / "usbguardian").exists())
        self.assertTrue((self.layout.state_dir / "trust" / "trust.log").exists())
        self.assertIn(str(self.layout.state_dir), removed["kept"])
        self.assertFalse([n for d in os.listdir(self.host.fs / "etc") if d.startswith("rc")
                          for n in os.listdir(self.host.fs / "etc" / d)])

    def test_mismatched_host_is_blocked(self):
        b = self.bundle(debs=False)
        (self.host.proc / "1" / "comm").write_text("systemd\n")
        plan = self.plan(b)
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertIn("SysVinit preflight BLOCKED", plan["blocked_reasons"])
        with self.assertRaises(E.GuardianError) as cm:
            self.apply(b)
        self.assertEqual(cm.exception.code, "INSTALLATION_BLOCKED")
        self.assertFalse(self.layout.prefix.exists())
        (self.host.fs / "etc/mx-version").write_text("MX-25.1_x64\n")
        (self.host.proc / "1" / "comm").write_text("init\n")
        with self.assertRaises(E.ValidationError) as cm:
            self.plan(b)
        self.assertEqual(cm.exception.code, "BUNDLE_TARGET_MISMATCH")


class _Outsider:
    """Signs with a key that is not enrolled while claiming an enrolled key id."""

    def __init__(self, signer, claimed):
        self.signer, self.key_id = signer, claimed

    def sign_ns(self, ns, digest):
        return self.signer.sign_ns(ns, digest)


if __name__ == "__main__":
    unittest.main()
