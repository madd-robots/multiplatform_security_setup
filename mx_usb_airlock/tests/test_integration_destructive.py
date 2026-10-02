# SPDX-License-Identifier: GPL-3.0-or-later
"""DESTRUCTIVE integration test against one real, dedicated USB test drive.

Skipped unless BOTH variables are set exactly:

    AIRLOCK_TEST_DEVICE=/dev/disk/by-id/usb-<vendor>_<model>_<serial>-0:0
    AIRLOCK_TEST_DESTRUCTIVE=ERASE-THIS-TEST-DEVICE

and the process runs as root on Linux.  The device is ERASED.  It must be the
only removable storage attached, and it must not be system or live media
(the same checks the application applies).  See TESTING.md.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import airlock as A  # noqa: E402

DEVICE = os.environ.get("AIRLOCK_TEST_DEVICE", "")
ENABLED = (os.environ.get("AIRLOCK_TEST_DESTRUCTIVE") == "ERASE-THIS-TEST-DEVICE" and DEVICE.startswith("/dev/disk/by-id/")
           and sys.platform.startswith("linux") and os.geteuid() == 0)


@unittest.skipUnless(ENABLED, "destructive test disabled (see module docstring)")
class DestructiveDeviceTest(unittest.TestCase):
    def setUp(self):
        self.backend = A.LinuxBackend(A.CommandRunner())
        disks = self.backend.list_disks()
        protected = self.backend.protected_disks()
        name = os.path.basename(DEVICE)
        matches = [d for d in disks if name in d.by_id]
        self.assertEqual(len(matches), 1, "test device not found exactly once")
        self.disk = matches[0]
        self.assertNotIn(self.disk.kname, protected, "refusing: device is protected (%s)" % protected.get(self.disk.kname))
        removable = A.removable_disks(disks, protected)
        self.assertEqual([d.kname for d in removable], [self.disk.kname], "the test device must be the only removable storage")
        self.assertEqual(self.disk.tran, "usb")
        self.mnt = Path(tempfile.mkdtemp(prefix="airlock-it-"))
        self.addCleanup(lambda: os.rmdir(str(self.mnt)) if not os.listdir(str(self.mnt)) else None)

    def _part(self):
        for d in self.backend.list_disks():
            if d.maj_min == self.disk.maj_min and d.serial == self.disk.serial:
                return d, d.partitions[0]
        self.fail("device disappeared")

    def test_prepare_write_verify_then_readonly_ingest(self):
        for part in self.disk.partitions:
            self.backend.unmount_partition(part)
        self.backend.prepare_fat32(self.disk, "AIRLOCKIT")
        disk, part = self._part()
        self.assertEqual(part.fstype, "vfat")
        uid, gid = os.getuid(), os.getgid()

        kt, opts = A.mount_options("vfat", "rw", uid, gid)
        root = self.backend.mount(part, kt, self.mnt, opts)
        try:
            self.backend.verify_mount(part, root, expect_ro=False)
            writer = A.DestinationWriter(root, "RECOVERY_TRANSFER", "20260101T000000Z-00000000")
            writer.open()
            try:
                writer.write_file("test.ps1", b"Write-Host 'integration'\r\n")
            finally:
                writer.close()
            os.sync()
        finally:
            self.backend.unmount_partition(part, self.mnt)
        self.backend.flush_buffers(part)

        kt, opts = A.mount_options("vfat", "ro", uid, gid)
        root = self.backend.mount(part, kt, self.mnt, opts)
        try:
            self.backend.verify_mount(part, root, expect_ro=True)
            hashes, anomalies = A.inventory_tree(root, "RECOVERY_TRANSFER", 1024 * 1024)
            self.assertEqual(anomalies, [])
            self.assertEqual(hashes["FILES/test.ps1"], A.sha256_hex(b"Write-Host 'integration'\r\n"))
        finally:
            self.backend.unmount_partition(part, self.mnt)

        # Ingest path: block-layer read-only, then a read-write mount must fail.
        ok, _details = self.backend.set_readonly(disk)
        self.assertTrue(ok)
        kt, opts = A.mount_options("vfat", "ro", uid, gid)
        root = self.backend.mount(part, kt, self.mnt, opts)
        try:
            scan = A.scan_source_tree(root, A.load_config(None), self.backend.expected_root_dev(part))
            self.assertIn("RECOVERY_TRANSFER/FILES/test.ps1", [r["relative_path"] for r in scan.accepted])
        finally:
            self.backend.unmount_partition(part, self.mnt)
        kt, opts = A.mount_options("vfat", "rw", uid, gid)
        with self.assertRaises(A.BlockingError):
            self.backend.mount(part, kt, self.mnt, opts)
            self.backend.unmount_partition(part, self.mnt)
        print("\nNOTE: the test device is still read-only at the block layer; unplug and replug it.")


if __name__ == "__main__":
    unittest.main()
