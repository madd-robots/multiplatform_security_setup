# SPDX-License-Identifier: GPL-3.0-or-later
"""Bundle build and installer tests.

Builds the release tarball into a temporary directory, extracts it, and runs
install.sh against temporary prefixes.  Nothing outside the temporary
directory is changed.  Skipped inside an installed bundle (tools/ is not
shipped) or where /bin/sh or sha256sum is unavailable.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILDER = ROOT / "tools" / "make_bundle.py"
SH = "/bin/sh"
ENABLED = BUILDER.is_file() and os.path.exists(SH) and shutil.which("sha256sum", path="/usr/bin:/bin")


def load_builder():
    spec = importlib.util.spec_from_file_location("make_bundle", str(BUILDER))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(ENABLED, "bundle builder or shell tools not available")
class BundleInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="airlock-install-test-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.archive, self.archive_sha, self.digest = self.builder.build(self.tmp / "dist", quiet=True)
        self.extract = self.tmp / "extract"
        self.extract.mkdir()
        with tarfile.open(str(self.archive), "r:gz") as tar:
            for member in tar.getmembers():
                self.assertTrue(member.isfile() or member.isdir(), member.name)
                self.assertFalse(member.name.startswith("/") or ".." in member.name.split("/"), member.name)
                self.assertEqual((member.uid, member.gid), (0, 0))
            if hasattr(tarfile, "data_filter"):
                tar.extractall(str(self.extract), filter="data")
            else:
                tar.extractall(str(self.extract))
        self.bundle = self.extract / ("mx_usb_airlock-%s" % self.builder.read_version())
        self.prefix = self.tmp / "opt" / "mx_usb_airlock"
        self.bindir = self.tmp / "bin"
        self.launcher = self.bindir / "mx-usb-airlock"

    def install(self, *extra):
        argv = [SH, str(self.bundle / "install.sh"), "--yes", "--skip-tests",
                "--prefix", str(self.prefix), "--bin-dir", str(self.bindir)] + list(extra)
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL)

    def test_build_is_reproducible(self):
        again = self.builder.build(self.tmp / "dist2", quiet=True)
        self.assertEqual(again[1], self.archive_sha)
        self.assertEqual((self.bundle / "install.sh").stat().st_mode & 0o777, 0o755)

    def test_install_upgrade_and_uninstall(self):
        res = self.install("--expect-digest", self.digest.upper())
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("BUNDLE DIGEST MATCHES", res.stdout)
        self.assertTrue((self.prefix / "airlock.py").is_file())
        self.assertTrue((self.prefix / ".installed-by-mx_usb_airlock").is_file())
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.prefix / "airlock.py").stat().st_mode & 0o777, 0o644)
        out = subprocess.run([str(self.launcher), "--version"], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0)
        self.assertIn(self.builder.read_version(), out.stdout)
        self.assertIn(" -I -B ", self.launcher.read_text())
        # re-install (upgrade path) replaces the managed installation
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual([p.name for p in self.prefix.parent.iterdir()], ["mx_usb_airlock"])
        res = subprocess.run([SH, str(self.bundle / "install.sh"), "--uninstall", "--yes",
                              "--prefix", str(self.prefix), "--bin-dir", str(self.bindir)],
                             capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(self.launcher.exists())

    def test_tampered_bundle_is_refused(self):
        target = self.bundle / "airlock.py"
        target.write_text(target.read_text() + "\n# modified\n")
        res = self.install()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("integrity check FAILED", res.stderr)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(self.launcher.exists())

    def test_wrong_expected_digest_is_refused(self):
        res = self.install("--expect-digest", "0" * 64)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("does NOT match", res.stderr)
        self.assertFalse(self.prefix.exists())

    def test_extra_or_missing_files_refused(self):
        (self.bundle / "tests" / "test_airlock.py").unlink()
        res = self.install()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing", res.stderr)

    def test_refuses_unmanaged_targets_and_unsafe_paths(self):
        self.prefix.mkdir(parents=True)
        (self.prefix / "precious.txt").write_text("keep")
        res = self.install()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("was not installed by this script", res.stderr)
        self.assertTrue((self.prefix / "precious.txt").exists())
        shutil.rmtree(str(self.prefix))
        self.bindir.mkdir()
        self.launcher.write_text("#!/bin/sh\necho someone else\n")
        res = self.install()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("not managed by this installer", res.stderr)
        for bad in (str(self.tmp / "opt" / "other"), "relative/mx_usb_airlock", str(self.tmp) + "/a b/mx_usb_airlock",
                    str(self.tmp) + "/../mx_usb_airlock"):
            res = subprocess.run([SH, str(self.bundle / "install.sh"), "--yes", "--skip-tests", "--prefix", bad,
                                  "--bin-dir", str(self.bindir)], capture_output=True, text=True, timeout=60,
                                 stdin=subprocess.DEVNULL)
            self.assertNotEqual(res.returncode, 0, bad)
        res = subprocess.run([SH, str(self.bundle / "install.sh"), "--uninstall", "--yes", "--prefix",
                              str(self.tmp / "opt" / "mx_usb_airlock")], capture_output=True, text=True, timeout=60,
                             stdin=subprocess.DEVNULL)
        self.assertNotEqual(res.returncode, 0)

    def test_check_only_changes_nothing(self):
        res = subprocess.run([SH, str(self.bundle / "install.sh"), "--check-only", "--prefix", str(self.prefix),
                              "--bin-dir", str(self.bindir)], capture_output=True, text=True, timeout=300,
                             stdin=subprocess.DEVNULL)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Test suite: Ran", res.stdout)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(self.bindir.exists())

    def test_noninteractive_without_yes_is_cancelled(self):
        res = subprocess.run([SH, str(self.bundle / "install.sh"), "--skip-tests", "--prefix", str(self.prefix),
                              "--bin-dir", str(self.bindir)], capture_output=True, text=True, timeout=60,
                             stdin=subprocess.DEVNULL)
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertFalse(self.prefix.exists())


if __name__ == "__main__":
    unittest.main()
