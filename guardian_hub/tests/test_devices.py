# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 3 device engine tests.

Devices are simulated with a fake sysfs tree in a temporary directory and
the surface test runs on temporary files or in-memory fakes. No test opens
or writes a real block device.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.common import errors as E  # noqa: E402
from usbguardian.devices import assess as A  # noqa: E402
from usbguardian.devices.handlers import build_report, summarize  # noqa: E402
from usbguardian.devices.identity import fingerprint, identity_changes, identity_document  # noqa: E402
from usbguardian.devices.operations import SurfaceTestRunner, device_operations  # noqa: E402
from usbguardian.devices.scanner import SysfsScanner, parse_mountinfo, read_attr  # noqa: E402
from usbguardian.devices.surface import FdBlockIO, open_block_device, pattern, surface_test  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402
from usbguardian.runtime.broker import Broker  # noqa: E402

MIB = 1024 * 1024
STORAGE = ("08", "06", "50", "usb-storage")


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else (str(value) + "\n").encode())


def _link(link, target):
    link.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(os.path.relpath(target, link.parent), link)


class FakeSys:
    def __init__(self, root):
        self.root = Path(root)
        self.mountinfo = self.root / "mountinfo"
        (self.root / "block").mkdir(parents=True)
        self.mountinfo.write_bytes(b"")

    def scanner(self):
        return SysfsScanner(str(self.root), str(self.mountinfo))

    def _block(self, parent, kname, devnum, sectors, ro=0, removable=1, lbs=512, parts=(), holders=()):
        blk = parent / "block" / kname
        for name, value in (("dev", devnum), ("size", sectors), ("ro", ro), ("removable", removable),
                            ("queue/logical_block_size", lbs), ("queue/physical_block_size", lbs),
                            ("queue/rotational", 0)):
            _write(blk / name, value)
        (blk / "holders").mkdir()
        for h in holders:
            (blk / "holders" / h).mkdir()
        major, minor = devnum.split(":")
        for n, start, size in parts:
            p = blk / ("%s%d" % (kname, n))
            for name, value in (("partition", n), ("start", start), ("size", size), ("ro", 0),
                                ("dev", "%s:%d" % (major, int(minor) + n))):
                _write(p / name, value)
            (p / "holders").mkdir()
        _link(self.root / "block" / kname, blk)
        return blk

    def add_usb(self, kname="sdb", port="2-1", devnum="8:16", sectors=8192, interfaces=(STORAGE,),
                vendor="0781", product_id="5583", serial="4C530001", manufacturer="SanDisk", product="Ultra",
                num_configs=1, device_class="00", scsi=("SanDisk ", "Ultra   ", "1.00"), **block):
        usb = self.root / "devices/pci0000:00/0000:00:14.0/usb2" / port
        for name, value in (("idVendor", vendor), ("idProduct", product_id), ("bcdDevice", "0100"),
                            ("speed", "480"), ("version", " 2.10"), ("bDeviceClass", device_class),
                            ("bNumConfigurations", num_configs), ("bConfigurationValue", 1), ("authorized", 1)):
            _write(usb / name, value)
        for name, value in (("manufacturer", manufacturer), ("product", product), ("serial", serial)):
            if value is not None:
                _write(usb / name, value)
        storage_iface = None
        for idx, (cls, sub, proto, driver) in enumerate(interfaces):
            iface = usb / ("%s:1.%d" % (port, idx))
            for name, value in (("bInterfaceClass", cls), ("bInterfaceSubClass", sub),
                                ("bInterfaceProtocol", proto), ("authorized", 1)):
                _write(iface / name, value)
            drv = self.root / "bus/usb/drivers" / driver
            drv.mkdir(parents=True, exist_ok=True)
            _link(iface / "driver", drv)
            if storage_iface is None and cls == "08":
                storage_iface = iface
        scsi_dir = (storage_iface or usb / ("%s:1.0" % port)) / "host6/target6:0:0/6:0:0:0"
        for name, value in zip(("vendor", "model", "rev"), scsi):
            _write(scsi_dir / name, value)
        blk = self._block(scsi_dir, kname, devnum, sectors, **block)
        _link(blk / "device", scsi_dir)
        return blk

    def add_mmc(self, kname="mmcblk0", devnum="179:0", sectors=8192, cid="035344534330384780f2a1b4c0012345"):
        card = self.root / "devices/platform/mmc0/mmc_host/mmc0/mmc0:aaaa"
        for name, value in (("cid", cid), ("name", "SC08G"), ("manfid", "0x000003"), ("oemid", "0x5344"),
                            ("serial", "0xf2a1b4c0"), ("date", "01/2023"), ("type", "SD")):
            _write(card / name, value)
        blk = self._block(card, kname, devnum, sectors)
        _link(blk / "device", card)
        return blk

    def add_nvme(self, kname="nvme0n1"):
        ctrl = self.root / "devices/pci0000:00/0000:00:1d.0/nvme/nvme0"
        _write(ctrl / "model", "Internal SSD")
        blk = self._block(ctrl, kname, "259:0", 2 ** 30, removable=0)
        return blk

    def add_loop(self, kname="loop0"):
        return self._block(self.root / "devices/virtual", kname, "7:0", 100, removable=0)

    def mounts(self, *lines):
        self.mountinfo.write_bytes("".join(l + "\n" for l in lines).encode())


def codes(findings, severity=None):
    return {f["code"] for f in findings if severity is None or f["severity"] == severity}


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fs = FakeSys(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_classifies_transports(self):
        self.fs.add_usb()
        self.fs.add_mmc()
        self.fs.add_nvme()
        self.fs.add_loop()
        devs = {d["kname"]: d for d in self.fs.scanner().scan()}
        self.assertEqual(sorted(devs), ["mmcblk0", "nvme0n1", "sdb"])
        self.assertEqual(devs["sdb"]["transport"], "usb")
        self.assertEqual(devs["mmcblk0"]["transport"], "mmc")
        self.assertEqual(devs["nvme0n1"]["transport"], "nvme")
        sdb = devs["sdb"]
        self.assertEqual(sdb["size_bytes"], 8192 * 512)
        self.assertEqual(sdb["dev"], "8:16")
        self.assertEqual(sdb["usb"]["vendor_id"], "0781")
        self.assertEqual(sdb["usb"]["port"], "2-1")
        self.assertEqual(sdb["usb"]["interfaces"][0]["driver"], "usb-storage")
        self.assertEqual(sdb["scsi"]["vendor"], "SanDisk ")  # kept exactly as reported
        self.assertEqual(devs["mmcblk0"]["mmc"]["type"], "SD")

    def test_partitions_holders_and_mounts(self):
        self.fs.add_usb(parts=[(1, 2048, 4096)])
        self.fs.mounts("36 25 8:17 / /media/user/STICK rw,nosuid - vfat /dev/sdb1 rw",
                       "37 25 0:50 / /mnt/dm rw - ext4 /dev/sdc1 rw")
        dev = self.fs.scanner().inspect("sdb")
        self.assertEqual(dev["partitions"][0]["kname"], "sdb1")
        self.assertEqual(dev["partitions"][0]["dev"], "8:17")
        self.assertEqual([m["mountpoint"] for m in dev["mounts"]], ["/media/user/STICK"])

    def test_symlink_escaping_sysfs_root_ignored(self):
        os.symlink("/etc", self.fs.root / "block" / "sdz")
        self.assertEqual(self.fs.scanner().scan(), [])

    def test_inspect_validation(self):
        self.fs.add_loop()
        sc = self.fs.scanner()
        for bad in ("../sda", "SDA", "", "loop0", 5):
            with self.assertRaises(E.ValidationError):
                sc.inspect(bad)
        with self.assertRaises(E.NotFound):
            sc.inspect("sdq")

    def test_attribute_reads_are_bounded_and_typed(self):
        d = self.fs.root / "attrs"
        _write(d / "big", b"x" * 5000)
        _write(d / "bad", b"\xff\xfe")
        os.mkfifo(d / "fifo")
        os.symlink(d / "big", d / "link")
        self.assertIsNone(read_attr(str(d), "big"))
        self.assertEqual(read_attr(str(d), "bad"), "invalid-utf8:fffe")
        self.assertIsNone(read_attr(str(d), "fifo"))
        self.assertIsNone(read_attr(str(d), "link"))
        self.assertIsNone(read_attr(str(d), "missing"))

    def test_mountinfo_parsing(self):
        mounts = parse_mountinfo(b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                                 b"40 22 8:17 / /media/a\\040b rw - vfat /dev/sdb1 rw\n"
                                 b"garbage line\n\n41 22 x:y / /x rw - tmpfs none rw\n")
        self.assertEqual(mounts[0], {"device": "8:1", "mountpoint": "/", "source": "/dev/sda1"})
        self.assertEqual(mounts[1]["mountpoint"], "/media/a b")
        self.assertEqual(mounts[2]["device"], "")
        self.assertEqual(len(mounts), 3)

    def test_kernel_facts(self):
        self.fs.add_usb(holders=["dm-0"])
        facts = self.fs.scanner().kernel_facts("sdb")
        self.assertEqual(facts, {"dev": "8:16", "size_bytes": 8192 * 512, "transport": "usb", "holders": True})
        with self.assertRaises(E.NotFound):
            self.fs.scanner().kernel_facts("sdx")
        self.fs.add_usb(kname="sdc", port="2-2", devnum="8:32", parts=[(1, 2048, 1000)])
        self.assertFalse(self.fs.scanner().kernel_facts("sdc")["holders"])
        os.mkdir(self.fs.root / "block" / "sdc" / "sdc1" / "holders" / "dm-3")
        self.assertTrue(self.fs.scanner().kernel_facts("sdc")["holders"])
        self.assertIn("HAS_HOLDERS", codes(build_report(self.fs.scanner().inspect("sdc"))["findings"]))


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fs = FakeSys(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, kname="sdb"):
        return build_report(self.fs.scanner().inspect(kname))

    def test_clean_stick_is_candidate(self):
        self.fs.add_usb()
        r = self.report()
        self.assertTrue(r["candidate"], r["findings"])
        self.assertEqual(codes(r["findings"], A.SEV_BLOCKING), set())
        self.assertEqual(len(r["fingerprint"]), 64)
        self.assertEqual(summarize(r)["usb_id"], "0781:5583")

    def test_uas_and_sd_card_accepted(self):
        self.fs.add_usb(interfaces=[("08", "06", "62", "uas")])
        self.fs.add_mmc()
        self.assertTrue(self.report("sdb")["candidate"])
        self.assertTrue(self.report("mmcblk0")["candidate"])

    def test_badusb_extra_interfaces_blocked(self):
        cases = {
            "hid": [STORAGE, ("03", "01", "01", "usbhid")],
            "network": [STORAGE, ("02", "06", "00", "cdc_ether")],
            "vendor": [("ff", "ff", "ff", "none"), STORAGE],
        }
        for label, ifaces in cases.items():
            with self.subTest(label):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                fs = FakeSys(tmp.name)
                fs.add_usb(interfaces=ifaces)
                r = build_report(fs.scanner().inspect("sdb"))
                self.assertIn("USB_EXTRA_INTERFACE", codes(r["findings"], A.SEV_BLOCKING))
                self.assertFalse(r["candidate"])

    def test_other_usb_rules(self):
        cases = [
            (dict(interfaces=[("08", "01", "00", "usb-storage")]), "USB_STORAGE_VARIANT", A.SEV_BLOCKING),
            (dict(interfaces=[STORAGE, STORAGE]), "USB_MULTIPLE_STORAGE_INTERFACES", A.SEV_BLOCKING),
            (dict(num_configs=2), "USB_CONFIGURATIONS", A.SEV_BLOCKING),
            (dict(device_class="ef"), "USB_DEVICE_CLASS", A.SEV_BLOCKING),
            (dict(interfaces=[]), "USB_NO_INTERFACES", A.SEV_BLOCKING),
            (dict(serial=None), "USB_NO_SERIAL", A.SEV_REVIEW),
            (dict(product="Ultra\x1b[2J"), "USB_STRING_ANOMALY", A.SEV_REVIEW),
            (dict(product=b"\xff\xfe\n"), "USB_STRING_ANOMALY", A.SEV_REVIEW),
            (dict(sectors=0), "NO_MEDIA", A.SEV_BLOCKING),
            (dict(ro=1), "WRITE_PROTECTED", A.SEV_INFO),
            (dict(lbs=520), "UNUSUAL_BLOCK_SIZE", A.SEV_REVIEW),
            (dict(holders=["dm-0"]), "HAS_HOLDERS", A.SEV_BLOCKING),
            (dict(parts=[(1, 8000, 1000)]), "PARTITION_TABLE_INCONSISTENT", A.SEV_REVIEW),
        ]
        for kwargs, code, severity in cases:
            with self.subTest(code):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                fs = FakeSys(tmp.name)
                fs.add_usb(**kwargs)
                self.assertIn(code, codes(build_report(fs.scanner().inspect("sdb"))["findings"], severity))

    def test_mounted_and_system_disks_blocked(self):
        self.fs.add_usb(parts=[(1, 2048, 4096)])
        self.fs.mounts("22 1 8:17 / / rw - ext4 /dev/sdb1 rw")
        found = codes(self.report()["findings"], A.SEV_BLOCKING)
        self.assertIn("SYSTEM_DISK", found)
        self.assertIn("MOUNTED", found)
        self.fs.mounts("22 1 8:17 / /run/live/medium ro - iso9660 /dev/sdb1 ro")
        self.assertIn("SYSTEM_DISK", codes(self.report()["findings"]))

    def test_internal_disk_blocked(self):
        self.fs.add_nvme()
        r = self.report("nvme0n1")
        self.assertIn("INTERNAL_DEVICE", codes(r["findings"], A.SEV_BLOCKING))


class IdentityTests(unittest.TestCase):
    def fp(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeSys(tmp)
            fs.add_usb(**kwargs)
            return fingerprint(fs.scanner().inspect("sdb"))

    def test_volatile_state_does_not_change_identity(self):
        base = self.fp()
        self.assertEqual(base, self.fp(port="3-4", devnum="8:32", parts=[(1, 2048, 1000)], ro=1))

    def test_presented_identity_changes_are_detected(self):
        base = self.fp()
        for change in (dict(serial="OTHER"), dict(product_id="5584"), dict(sectors=16384),
                       dict(interfaces=[STORAGE, ("03", "01", "01", "usbhid")]), dict(scsi=("X", "Y", "Z")),
                       dict(lbs=4096)):
            with self.subTest(change):
                self.assertNotEqual(base, self.fp(**change))

    def test_identity_changes_reports_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeSys(tmp)
            fs.add_usb()
            fs.add_usb(kname="sdc", port="2-2", devnum="8:32", serial="DIFFERENT", sectors=4096)
            a = identity_document(fs.scanner().inspect("sdb"))
            b = identity_document(fs.scanner().inspect("sdc"))
        self.assertEqual(identity_changes(a, b), ["size_bytes", "usb.serial"])
        self.assertEqual(identity_changes(a, a), [])


class MemIO:
    """In-memory device used to simulate counterfeit and failing media."""

    direct = False

    def __init__(self, real_size, mode="ok", at=None):
        self.data = bytearray(real_size)
        self.real = real_size
        self.mode = mode
        self.at = at

    def write(self, offset, data):
        data = bytes(data)
        if self.mode == "write_error" and offset >= self.at:
            raise OSError(5, "I/O error")
        if self.mode == "wrap":
            offset %= self.real
        elif self.mode == "drop" and offset >= self.real:
            return
        self.data[offset:offset + len(data)] = data

    def read_into(self, offset, buf):
        if self.mode == "read_error" and offset == self.at:
            raise OSError(5, "I/O error")
        if self.mode == "wrap":
            offset %= self.real
        if self.mode == "drop" and offset >= self.real:
            buf[:] = bytes(len(buf))
            return len(buf)
        chunk = bytearray(self.data[offset:offset + len(buf)])
        if self.mode == "bitflip" and offset <= self.at < offset + len(buf):
            chunk[self.at - offset] ^= 0x01
        buf[:len(chunk)] = chunk
        return len(chunk)

    def flush(self):
        pass


class SurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "device.img"

    def tearDown(self):
        self.tmp.cleanup()

    def run_file(self, size, key=None):
        self.path.write_bytes(b"\x00" * size)
        fd = os.open(self.path, os.O_RDWR)
        try:
            return surface_test(FdBlockIO(fd, size, direct=False), size, chunk_size=MIB, key=key)
        finally:
            os.close(fd)

    def test_file_backed_pass_overwrites_everything(self):
        size = 8 * MIB + 4096  # partial final chunk
        r = self.run_file(size, key=b"k" * 32)
        self.assertTrue(r["passed"], r)
        self.assertEqual(r["verified_bytes"], size)
        self.assertEqual(r["bytes_written"], size)
        self.assertEqual(r["chunks"], 9)
        data = self.path.read_bytes()
        self.assertEqual(data[:MIB], pattern(b"k" * 32, 0, MIB))
        self.assertEqual(data[8 * MIB:], pattern(b"k" * 32, 8, 4096))
        self.assertNotIn(b"\x00" * 4096, data)

    def test_fresh_key_each_run(self):
        self.run_file(MIB)
        first = self.path.read_bytes()
        self.run_file(MIB)
        self.assertNotEqual(first, self.path.read_bytes())

    def test_counterfeit_wrapping_capacity_detected(self):
        r = surface_test(MemIO(4 * MIB, "wrap"), 8 * MIB, chunk_size=MIB)
        self.assertFalse(r["passed"])
        self.assertEqual(r["bad_chunks"], 4)
        self.assertEqual(r["first_bad_offset"], 0)
        self.assertEqual(r["verified_bytes"], 0)

    def test_counterfeit_dropping_writes_detected(self):
        r = surface_test(MemIO(4 * MIB, "drop"), 8 * MIB, chunk_size=MIB)
        self.assertFalse(r["passed"])
        self.assertEqual(r["verified_bytes"], 4 * MIB)
        self.assertEqual(r["bad_ranges"], [[4 * MIB, 8 * MIB]])

    def test_single_bit_flip_detected(self):
        r = surface_test(MemIO(8 * MIB, "bitflip", at=5 * MIB + 7), 8 * MIB, chunk_size=MIB)
        self.assertFalse(r["passed"])
        self.assertEqual(r["bad_chunks"], 1)
        self.assertEqual(r["bad_ranges"], [[5 * MIB, 6 * MIB]])

    def test_write_and_read_errors(self):
        r = surface_test(MemIO(8 * MIB, "write_error", at=3 * MIB), 8 * MIB, chunk_size=MIB)
        self.assertFalse(r["passed"])
        self.assertEqual(r["write_error_offset"], 3 * MIB)
        r = surface_test(MemIO(8 * MIB, "read_error", at=2 * MIB), 8 * MIB, chunk_size=MIB)
        self.assertFalse(r["passed"])
        self.assertEqual(r["unreadable_chunks"], 1)

    def test_cancel_and_progress(self):
        seen = []
        r = surface_test(MemIO(4 * MIB), 4 * MIB, chunk_size=MIB, progress=lambda *a: seen.append(a))
        self.assertTrue(r["passed"])
        self.assertEqual(seen[-1], ("verify", 4 * MIB, 4 * MIB))
        r = surface_test(MemIO(4 * MIB), 4 * MIB, chunk_size=MIB, should_stop=lambda: True)
        self.assertTrue(r["cancelled"])
        self.assertFalse(r["passed"])

    def test_parameter_validation(self):
        for kwargs in (dict(size=1000), dict(size=0), dict(size=MIB, chunk_size=1000),
                       dict(size=MIB, key=b"short")):
            with self.assertRaises(E.ValidationError):
                surface_test(MemIO(MIB), **kwargs)

    def test_open_block_device_refuses_non_devices(self):
        self.path.write_bytes(b"\x00" * 4096)
        with self.assertRaises(E.SecurityViolation):
            open_block_device(str(self.path), "8:16")
        with self.assertRaises(E.SecurityViolation):
            open_block_device(str(self.path) + ".missing", "8:16")


class SurfaceOperationTests(unittest.TestCase):
    SIZE = 4 * MIB

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.fs = FakeSys(root / "sys")
        self.fs.add_usb(sectors=self.SIZE // 512)
        self.devdir = root / "dev"
        self.devdir.mkdir()
        self.image = self.devdir / "sdb"
        self.image.write_bytes(b"\x00" * self.SIZE)
        self.reports = []

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, kname):
        report = build_report(self.fs.scanner().inspect(kname))
        for hook in self.reports:
            report = hook(report)
        return report

    def runner(self, inspect=None):
        def open_file(path, expected_dev):
            self.opened = (path, expected_dev)
            return os.open(path, os.O_RDWR)
        return SurfaceTestRunner(inspect or self.inspect, open_device=open_file,
                                 io_factory=lambda fd, size, direct: FdBlockIO(fd, size, direct=False),
                                 dev_root=str(self.devdir), sysfs_root=str(self.fs.root))

    def owner(self):
        return authz.Principal("owner", 0, frozenset({"device.modify"}), frozenset({"peer_uid", "owner_key"}))

    def fp(self):
        return self.inspect("sdb")["fingerprint"]

    def untouched(self):
        return self.image.read_bytes() == b"\x00" * self.SIZE

    def test_runs_when_identity_matches(self):
        out = self.runner()(self.owner(), {"kname": "sdb", "fingerprint": self.fp()})
        self.assertTrue(out["result"]["passed"])
        self.assertEqual(self.opened, (str(self.devdir / "sdb"), "8:16"))
        self.assertFalse(self.untouched())

    def test_refusals_leave_device_untouched(self):
        fp = self.fp()
        cases = [
            ("wrong fingerprint", None, "0" * 64, "DEVICE_IDENTITY_CHANGED"),
            ("blocking finding", lambda r: dict(r, findings=r["findings"] + [
                {"code": "MOUNTED", "severity": "BLOCKING", "detail": "x"}]), fp, "DEVICE_NOT_ELIGIBLE"),
            ("read only", lambda r: dict(r, device=dict(r["device"], read_only=True)), fp, "DEVICE_READ_ONLY"),
            ("worker lies about dev", lambda r: dict(r, device=dict(r["device"], dev="8:0")), fp,
             "DEVICE_IDENTITY_CHANGED"),
            ("worker lies about size", lambda r: dict(r, device=dict(r["device"], size_bytes=self.SIZE * 2)), fp,
             "DEVICE_IDENTITY_CHANGED"),
        ]
        for label, hook, given_fp, code in cases:
            with self.subTest(label):
                self.reports = [hook] if hook else []
                with self.assertRaises(E.GuardianError) as cm:
                    self.runner()(self.owner(), {"kname": "sdb", "fingerprint": given_fp})
                self.assertEqual(cm.exception.code, code)
                self.assertTrue(self.untouched())

    def test_malformed_worker_report_refused(self):
        with self.assertRaises(E.ValidationError):
            self.runner(lambda k: {"device": {}, "fingerprint": "x"})(
                self.owner(), {"kname": "sdb", "fingerprint": self.fp()})
        self.assertTrue(self.untouched())

    def test_kernel_topology_overrides_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            internal = FakeSys(tmp)
            internal.add_nvme(kname="sdb")  # kernel says the name belongs to an internal disk
            runner = self.runner()
            runner.sysfs_root = str(internal.root)
            with self.assertRaises(E.SecurityViolation) as cm:
                runner(self.owner(), {"kname": "sdb", "fingerprint": self.fp()})
        self.assertEqual(cm.exception.code, "DEVICE_NOT_ELIGIBLE")
        self.assertTrue(self.untouched())

    def test_identity_change_during_test_fails(self):
        fp = self.fp()
        calls = []

        def inspect(kname):
            calls.append(kname)
            report = self.inspect(kname)
            return report if len(calls) == 1 else dict(report, fingerprint="f" * 64)
        with self.assertRaises(E.IntegrityError):
            self.runner(inspect)(self.owner(), {"kname": "sdb", "fingerprint": fp})

    def test_broker_requires_owner_key(self):
        broker = Broker(device_operations(launcher=None, surface_runner=self.runner()), launcher=None)
        req = {"v": 1, "type": "request", "id": "r1", "op": "device.surface_test",
               "params": {"kname": "sdb", "fingerprint": self.fp()}}
        no_key = authz.Principal("op", 1000, frozenset({"device.modify"}), frozenset({"peer_uid"}))
        resp = broker.handle(no_key, req)
        self.assertEqual(resp["error"]["code"], "PERMISSION_DENIED")
        self.assertTrue(self.untouched())
        resp = broker.handle(self.owner(), req)
        self.assertTrue(resp["ok"], resp)
        self.assertTrue(resp["result"]["result"]["passed"])


class DeviceWorkerTests(unittest.TestCase):
    """The read-only handlers run inside the real sandboxed worker."""

    def setUp(self):
        from test_runtime import launcher
        self.launcher = launcher()
        from usbguardian.devices.operations import DEVICE_PROFILE
        self.profile = DEVICE_PROFILE

    def test_scan_in_worker(self):
        result = self.launcher.run(self.profile, "devices.scan", {})
        self.assertIsInstance(result["devices"], list)
        for d in result["devices"]:
            self.assertEqual(len(d["fingerprint"]), 64)

    def test_inspect_unknown_device(self):
        with self.assertRaises(E.NotFound):
            self.launcher.run(self.profile, "devices.inspect", {"kname": "zzq9"})
        with self.assertRaises(E.ValidationError):
            self.launcher.run(self.profile, "devices.inspect", {"kname": "../sda"})


if __name__ == "__main__":
    unittest.main()
