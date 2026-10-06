# SPDX-License-Identifier: GPL-3.0-or-later
"""Free-space checks (ROADMAP D8): refuse up front, stop cleanly when space runs out mid-way.

Low space is simulated with an injected statvfs, so no test fills a real disk.
"""

import hashlib
import hmac
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.space import (MIB, InsufficientSpace, SpaceGuard, SpacePolicy, require_space,  # noqa: E402
                                      space_report)
from usbguardian.vault import package as P  # noqa: E402
from usbguardian.vault.custody import CustodyStore  # noqa: E402
from usbguardian.vault.release import release_package  # noqa: E402

KEY = b"test-only-hmac-key"


class Vfs:
    def __init__(self, avail_bytes, total_bytes=100 * 1024 * MIB, inodes=10 ** 6, total_inodes=10 ** 6):
        self.f_frsize = 4096
        self.f_bavail = avail_bytes // 4096
        self.f_blocks = total_bytes // 4096
        self.f_favail = inodes
        self.f_files = total_inodes


class FakeDisk:
    """statvfs stand-in: plenty of space until ``fill_after`` calls, then (almost) none."""

    def __init__(self, fill_after=None, avail=50 * 1024 * MIB):
        self.calls = 0
        self.fill_after = fill_after
        self.avail = avail

    def __call__(self, target):
        self.calls += 1
        if self.fill_after is not None and self.calls > self.fill_after:
            return Vfs(1 * MIB)
        return Vfs(self.avail)


def policy(disk, **kw):
    return SpacePolicy(statvfs=disk, check_interval=64 * 1024, **kw)


class Signer:
    scheme = "test-hmac-sha256"
    key_id = "owner-a"

    def __init__(self):
        self.calls = 0

    def sign(self, digest):
        self.calls += 1
        return hmac.new(KEY, digest, hashlib.sha256).digest()


class Verifier:
    def verify(self, scheme, key_id, digest, signature):
        if not hmac.compare_digest(hmac.new(KEY, digest, hashlib.sha256).digest(), signature):
            raise E.IntegrityError("bad signature")


class PolicyTests(unittest.TestCase):
    def test_reserve_and_need(self):
        p = SpacePolicy(statvfs=lambda t: Vfs(1024 * MIB, total_bytes=10 * 1024 * MIB))
        self.assertEqual(space_report("/x", p)["reserve_bytes"], 128 * MIB)  # 1% = ~102 MiB < floor
        require_space("/x", 800 * MIB, policy=p)
        with self.assertRaises(InsufficientSpace) as cm:
            require_space("/x", 900 * MIB, policy=p)
        self.assertEqual(cm.exception.code, "INSUFFICIENT_SPACE")
        self.assertIsInstance(cm.exception, E.ResourceLimitExceeded)

    def test_fraction_and_cap(self):
        big = SpacePolicy(statvfs=lambda t: Vfs(10 ** 12, total_bytes=50 * 1024 ** 3))
        self.assertEqual(space_report("/x", big)["reserve_bytes"], 50 * 1024 ** 3 // 100)
        huge = SpacePolicy(statvfs=lambda t: Vfs(10 ** 13, total_bytes=10 ** 13))
        self.assertEqual(space_report("/x", huge)["reserve_bytes"], 4 * 1024 ** 3)

    def test_inodes(self):
        p = SpacePolicy(statvfs=lambda t: Vfs(10 ** 11, inodes=1100))
        require_space("/x", 0, files=50, policy=p)
        with self.assertRaises(InsufficientSpace):
            require_space("/x", 0, files=100, policy=p)
        fat = SpacePolicy(statvfs=lambda t: Vfs(10 ** 11, inodes=0, total_inodes=0))  # FAT reports no inodes
        require_space("/x", 0, files=100, policy=fat)

    def test_guard_rechecks_during_write(self):
        disk = FakeDisk(fill_after=2)
        guard = SpaceGuard("/x", total=10 * MIB, what="test", policy=policy(disk))
        guard.start()
        guard.advance(10 * 1024)  # below the interval: no new check
        self.assertEqual(disk.calls, 1)
        guard.advance(64 * 1024)  # second check: still fine
        with self.assertRaises(InsufficientSpace):
            guard.advance(64 * 1024)  # third check: disk filled meanwhile

    def test_real_filesystem_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = space_report(tmp)
            self.assertGreater(report["total_bytes"], 0)
            fd = os.open(tmp, os.O_RDONLY)
            try:
                self.assertEqual(space_report(fd)["total_bytes"], report["total_bytes"])
            finally:
                os.close(fd)

    def test_invalid_policies(self):
        for kw in (dict(reserve_bytes=-1), dict(reserve_fraction_ppm=2_000_000), dict(check_interval=10)):
            with self.assertRaises(ValueError):
                SpacePolicy(**kw)


class VaultSpaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.src = self.root / "big.bin"
        self.src.write_bytes(os.urandom(512 * 1024))

    def tearDown(self):
        self.tmp.cleanup()

    def store_state(self, store):
        objects = [p for p in (store.root / "objects").rglob("*") if p.is_file()]
        return objects, os.listdir(store.root / "records"), os.listdir(store.root / "tmp")

    def test_intake_refused_up_front(self):
        store = CustodyStore(self.root / "store", space_policy=policy(lambda t: Vfs(100 * MIB)))
        with self.assertRaises(InsufficientSpace):
            store.intake(self.src, "big.bin")
        self.assertEqual(self.store_state(store), ([], [], []))

    def test_intake_stops_when_disk_fills_mid_copy(self):
        disk = FakeDisk(fill_after=1)  # the upfront check passes, the first re-check fails
        store = CustodyStore(self.root / "store", space_policy=policy(disk))
        with self.assertRaises(InsufficientSpace):
            store.intake(self.src, "big.bin")
        self.assertEqual(self.store_state(store), ([], [], []))
        self.assertGreater(disk.calls, 1)

    def test_intake_of_stream_checked_while_copying(self):
        disk = FakeDisk(fill_after=1)
        store = CustodyStore(self.root / "store", space_policy=policy(disk))
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:  # writer child: stream more than the check interval
            os.close(r)
            try:
                for _ in range(8):
                    os.write(w, b"x" * 65536)
            except OSError:
                pass
            os._exit(0)
        os.close(w)
        try:
            with self.assertRaises(InsufficientSpace):
                store.intake(r, "stream")
        finally:
            os.close(r)
            os.waitpid(pid, 0)
        self.assertEqual(self.store_state(store), ([], [], []))

    def _package(self, disk_for_write):
        store = CustodyStore(self.root / "store")
        rec = store.intake(self.src, "big.bin")
        manifest = P.build_manifest([rec], instance_id="guardian-main", scheme=Signer.scheme, key_id=Signer.key_id)
        signer = Signer()
        out = self.root / "p.gpkg"
        fd = os.open(out, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            P.write_package(fd, store, manifest, signer, space_policy=policy(disk_for_write))
        finally:
            os.close(fd)
        return out, signer

    def test_package_write_refused_before_signing(self):
        store = CustodyStore(self.root / "store")
        rec = store.intake(self.src, "big.bin")
        manifest = P.build_manifest([rec], instance_id="guardian-main", scheme=Signer.scheme, key_id=Signer.key_id)
        signer = Signer()
        fd = os.open(self.root / "p.gpkg", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with self.assertRaises(InsufficientSpace):
                P.write_package(fd, store, manifest, signer, space_policy=policy(lambda t: Vfs(50 * MIB)))
        finally:
            os.close(fd)
        self.assertEqual(signer.calls, 0)  # no touch spent on a write that cannot fit
        self.assertEqual((self.root / "p.gpkg").read_bytes(), b"")

    def test_package_write_stopped_mid_way_never_verifies(self):
        with self.assertRaises(InsufficientSpace):
            self._package(FakeDisk(fill_after=1))
        fd = os.open(self.root / "p.gpkg", os.O_RDONLY)
        try:
            with self.assertRaises(E.IntegrityError):
                P.verify_package(fd, Verifier())
        finally:
            os.close(fd)

    def test_release_refused_and_stopped_cleanly(self):
        pkg, _ = self._package(FakeDisk())
        dest = self.root / "dest"
        dest.mkdir(mode=0o700)
        for label, disk in (("up front", lambda t: Vfs(10 * MIB)), ("mid-way", FakeDisk(fill_after=1))):
            with self.subTest(label):
                fd = os.open(pkg, os.O_RDONLY)
                try:
                    with self.assertRaises(InsufficientSpace):
                        release_package(fd, Verifier(), dest, space_policy=policy(disk))
                finally:
                    os.close(fd)
                self.assertEqual(os.listdir(dest), [])  # nothing released, staging removed
        fd = os.open(pkg, os.O_RDONLY)
        try:
            receipt = release_package(fd, Verifier(), dest, space_policy=policy(FakeDisk()))
        finally:
            os.close(fd)
        self.assertEqual((dest / receipt["released"][0]["name"]).read_bytes(), self.src.read_bytes())


if __name__ == "__main__":
    unittest.main()
