# SPDX-License-Identifier: GPL-3.0-or-later
"""Simulation-mode tests for the MX USB transfer airlock.

No test here touches a real block device.  Devices are simulated and their
"filesystems" are temporary directories.  Run with:

    python3 -I -B -m unittest discover -s tests -v
"""

import copy
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import airlock as A  # noqa: E402

PS1_BENIGN = b"# Hardening script\r\nSet-StrictMode -Version Latest\r\nWrite-Host 'Applying settings'\r\n"


def pe_bytes():
    data = bytearray(b"MZ" + b"\x00" * 200)
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    return bytes(data)


class Responder:
    """Answers console prompts by substring; raises EOFError (= cancel) when unscripted."""

    def __init__(self, rules):
        self.rules = [list(r) for r in rules]
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        for index, rule in enumerate(self.rules):
            key, answer = rule[0], rule[1]
            if key in prompt:
                if len(rule) > 2 and rule[2] == "once":
                    self.rules.pop(index)
                return answer(prompt) if callable(answer) else answer
        raise EOFError("no scripted answer for prompt: %r" % prompt)


class Harness:
    def __init__(self, tc):
        self.tc = tc
        self.tmp = Path(tempfile.mkdtemp(prefix="airlock-test-"))
        tc.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.src = self.tmp / "src"
        self.dst = self.tmp / "dst"
        self.live_root = self.tmp / "live"
        self.outside = self.tmp / "outside"
        for d in (self.src, self.dst, self.live_root, self.outside):
            d.mkdir()
        self.state = self.tmp / "state"
        self.backend = A.SimulatedBackend()
        self.live = A.sim_disk("sda", 8, "LIVE0001", model="LiveStick")
        self.backend.add_device(self.live, {"sda1": self.live_root}, protected="LIVE BOOT DEVICE (test)")
        self.source = A.sim_disk("sdb", 9, "DIRTY0001", model="DirtyStick")
        self.dest = A.sim_disk("sdc", 10, "CLEAN0001", model="CleanStick")
        self.out = io.StringIO()
        self.responder = None
        self.config_path = None

    # -- device actions
    def insert_source(self, automount=None):
        self.backend.add_device(copy.deepcopy(self.source), {"sdb1": self.src}, automount=automount)

    def insert_dest(self, disk=None):
        disk = disk or self.dest
        self.backend.add_device(copy.deepcopy(disk), {disk.partitions[0].kname: self.dst})

    def remove(self, kname):
        self.backend.remove_device(kname)

    # -- files
    def put(self, rel, data):
        path = self.src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def config(self, **values):
        self.config_path = self.tmp / "config.json"
        self.config_path.write_text(json.dumps(values))

    # -- running commands
    def run(self, argv, rules=()):
        self.responder = Responder(rules)
        console = A.Console(input_fn=self.responder, out=self.out, interactive=True, color=False)
        args = ["--state-dir", str(self.state)]
        if self.config_path:
            args += ["--config", str(self.config_path)]
        return A.main(args + list(argv), console=console, backend=self.backend)

    def session(self):
        return A.StateStore(self.state).load_session()

    def output(self):
        return self.out.getvalue()

    def removal_answer(self, prompt):
        self.remove("sdb")
        return "REMOVED"

    def dest_insert_answer(self, prompt):
        if "sdc" not in self.backend.devices:
            self.insert_dest()
        return ""

    def ingest_rules(self, extra=()):
        return list(extra) + [("Type YES", "YES"), ("then type REMOVED", self.removal_answer)]

    def release_rules(self, extra=()):
        return list(extra) + [("Insert the CLEAN destination USB", self.dest_insert_answer),
                              ("Type WRITE", "WRITE 0001")]

    def ingest(self, extra_args=(), extra_rules=()):
        self.insert_source()
        return self.run(["ingest"] + list(extra_args), self.ingest_rules(extra_rules))

    def approve_all(self):
        return self.run(["review"], [("Approve file", "a"), ("Type APPROVE", "APPROVE")])

    def release(self, extra_rules=()):
        return self.run(["release"], self.release_rules(extra_rules))

    def dest_files(self):
        return sorted(str(p.relative_to(self.dst)) for p in self.dst.rglob("*") if p.is_file() or p.is_symlink())

    def mount_calls(self):
        return [c for c in self.backend.calls if c[0] == "mount"]


# ---------------------------------------------------------------------------
# Unit tests: names, paths, content, config, parsing
# ---------------------------------------------------------------------------

class FilenameTests(unittest.TestCase):
    def test_good_names_accepted(self):
        for name in ("WIN11_STANDALONE_LOCKDOWN_V3.ps1", "notes.v2.md", "hashes.sha256", "a-b_c.json"):
            self.assertEqual(A.check_name_component(name), [], name)

    def test_malicious_names_rejected(self):
        cases = {
            "evil\nname.ps1": "NEWLINE_IN_NAME",
            "evil\rname.ps1": "CARRIAGE_RETURN_IN_NAME",
            "bell\x07.txt": "CONTROL_CHARACTER_IN_NAME",
            "CON.txt": "WINDOWS_RESERVED_NAME",
            "con .txt": "WINDOWS_RESERVED_NAME",
            "LPT1.ps1": "WINDOWS_RESERVED_NAME",
            "trailing.txt ": "TRAILING_SPACE_OR_DOT",
            "trailing.txt.": "TRAILING_SPACE_OR_DOT",
            "a<b.txt": "WINDOWS_INVALID_CHARACTER",
            "a:b.txt": "WINDOWS_INVALID_CHARACTER",
            "a\\b.txt": "EMBEDDED_BACKSLASH",
            "a/b.txt": "EMBEDDED_SLASH",
            "..": "PATH_TRAVERSAL",
            ("x" * 200) + ".txt": "NAME_TOO_LONG",
        }
        for name, code in cases.items():
            self.assertIn(code, A.check_name_component(name), repr(name))

    def test_malicious_unicode_names_rejected(self):
        self.assertIn("BIDI_CONTROL_IN_NAME", A.check_name_component("invoice\u202egnp.ps1"))
        self.assertIn("ZERO_WIDTH_CHARACTER_IN_NAME", A.check_name_component("scr\u200bipt.ps1"))
        # Cyrillic small a (U+0430) as a lookalike of Latin a
        self.assertIn("NON_ASCII_NAME", A.check_name_component("\u0430dmin.ps1"))
        self.assertIn("NOT_NFC_NORMALIZED", A.check_name_component("cafe\u0301.txt", allow_non_ascii=True))
        self.assertIn("INVALID_NAME_ENCODING", A.check_name_component("bad\udcff.txt"))

    def test_extension_policy(self):
        self.assertEqual(A.check_extension("x.ps1", A.DEFAULT_ALLOWED_EXTENSIONS), [])
        self.assertIn("DENIED_FILE_TYPE", A.check_extension("x.exe", A.DEFAULT_ALLOWED_EXTENSIONS))
        self.assertIn("DENIED_FILE_TYPE", A.check_extension("x.psm1", A.DEFAULT_ALLOWED_EXTENSIONS))
        self.assertIn("TYPE_NOT_ALLOWLISTED", A.check_extension("x.xyz", A.DEFAULT_ALLOWED_EXTENSIONS))
        self.assertIn("NO_EXTENSION", A.check_extension("README", A.DEFAULT_ALLOWED_EXTENSIONS))
        self.assertIn("DECEPTIVE_DOUBLE_EXTENSION", A.check_extension("invoice.exe.txt", A.DEFAULT_ALLOWED_EXTENSIONS))
        self.assertEqual(A.check_extension("notes.v2.txt", A.DEFAULT_ALLOWED_EXTENSIONS), [])

    def test_relative_path_traversal_and_absolute(self):
        for bad in ("../x.txt", "a/../b.txt", "a/./b.txt", "", "a//b.txt"):
            with self.assertRaises(A.BlockingError):
                A.validate_relative_path(bad)
        for bad in ("/etc/passwd", "\\windows\\x", "C:/x.txt"):
            with self.assertRaises(A.BlockingError) as cm:
                A.validate_relative_path(bad)
            self.assertEqual(cm.exception.code, "ABSOLUTE_PATH")
        self.assertEqual(A.validate_relative_path("sub/x.ps1"), ["sub", "x.ps1"])

    def test_display_text_escapes_terminal_controls(self):
        shown = A.display_text("a\x1b[31mred\u202e\n")
        self.assertNotIn("\x1b", shown)
        self.assertNotIn("\u202e", shown)
        self.assertNotIn("\n", shown)
        self.assertIn("\\x1b", shown)
        self.assertIn("\\u202e", shown)


class ContentTests(unittest.TestCase):
    def test_fake_txt_containing_pe_rejected(self):
        rejects, _flags, _enc = A.inspect_content("readme.txt", pe_bytes())
        self.assertIn("BINARY_SIGNATURE:PE_EXECUTABLE", rejects)

    def test_other_binary_signatures_rejected(self):
        for data, label in ((b"\x7fELF\x02\x01\x01" + b"\x00" * 20, "ELF_EXECUTABLE"),
                            (b"PK\x03\x04" + b"\x00" * 30, "ZIP_ARCHIVE_OR_OFFICE_DOCUMENT"),
                            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 30, "OLE_COMPOUND_DOCUMENT_OR_MSI"),
                            (b"%PDF-1.7\n", "PDF_DOCUMENT")):
            rejects, _f, _e = A.inspect_content("x.ps1", data)
            self.assertIn("BINARY_SIGNATURE:" + label, rejects)

    def test_nul_heavy_powershell_rejected(self):
        rejects, _f, _e = A.inspect_content("x.ps1", b"Write-Host hi\n" + b"\x00" * 500 + b"\x90" * 100)
        self.assertEqual(rejects, ["NUL_BYTES_PRESENT"])

    def test_binary_control_content_rejected(self):
        rejects, _f, _e = A.inspect_content("x.txt", bytes(range(1, 32)) * 20)
        self.assertEqual(rejects, ["BINARY_CONTENT"])

    def test_utf16_powershell_accepted_and_scanned(self):
        data = b"\xff\xfe" + "Invoke-Expression $x\r\n".encode("utf-16-le")
        rejects, flags, enc = A.inspect_content("x.ps1", data)
        self.assertEqual(rejects, [])
        self.assertEqual(enc, "utf-16-le")
        self.assertIn("INVOKE_EXPRESSION", {f["code"] for f in flags})

    def test_cp1252_accepted_with_flag(self):
        rejects, flags, enc = A.inspect_content("x.txt", b"caf\xe9 \x93quoted\x94\n")
        self.assertEqual(rejects, [])
        self.assertEqual(enc, "cp1252")
        self.assertIn("LEGACY_8BIT_ENCODING", {f["code"] for f in flags})

    def test_powershell_review_flags(self):
        tick = chr(0x60)
        script = "\n".join([
            "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            "$b = [Convert]::FromBase64String($s)",
            "Invoke-Expression $c",
            "I" + tick + "EX $d",
            "(New-Object Net.WebClient).DownloadString('http://example.invalid/x')",
            "Invoke-WebRequest -Uri http://example.invalid -OutFile x",
            "Start-BitsTransfer -Source a -Destination b",
            "[System.Reflection.Assembly]::Load($bytes)",
            "Add-Type -TypeDefinition $src",
            "rundll32 x.dll,Entry",
            "regsvr32 /s x.dll",
            "mshta http://example.invalid",
            "certutil -urlcache -split -f http://example.invalid/a a",
            "Register-ScheduledTask -TaskName t",
            "New-Service -Name s -BinaryPathName x",
            "Set-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name x",
            "Set-WmiInstance -Class __EventFilter",
            "Enable-PSRemoting -Force",
            "winrm quickconfig",
            "Add-MpPreference -ExclusionPath C:\\temp",
            "Set-MpPreference -DisableRealtimeMonitoring $true",
            "Set-NetFirewallProfile -Profile Domain -Enabled False",
            "Set-ExecutionPolicy Bypass -Scope Process",
            "powershell -WindowStyle Hidden -File x.ps1",
            "curl http://example.invalid",
        ])
        codes = {f["code"] for f in A.scan_powershell(script)}
        expected = {"ENCODED_COMMAND", "FROMBASE64STRING", "INVOKE_EXPRESSION", "IEX_ALIAS",
                    "ESCAPE_CHARACTER_OBFUSCATION", "DOWNLOADSTRING", "WEBCLIENT", "INVOKE_WEBREQUEST",
                    "BITS_TRANSFER", "REFLECTION_LOADING", "ADD_TYPE", "RUNDLL32", "REGSVR32", "MSHTA",
                    "CERTUTIL_DOWNLOAD_OR_DECODE", "SCHEDULED_TASK", "SERVICE_CREATION", "RUN_KEY_PERSISTENCE",
                    "WMI_PERSISTENCE", "POWERSHELL_REMOTING", "WINRM_CHANGE", "DEFENDER_EXCLUSION",
                    "DEFENDER_DISABLE", "FIREWALL_DISABLE", "EXECUTION_POLICY_WEAKENING",
                    "HIDDEN_POWERSHELL_LAUNCH", "CURL_WGET"}
        self.assertTrue(expected <= codes, sorted(expected - codes))
        self.assertTrue(all(f["severity"] == A.SEV_REVIEW for f in A.scan_powershell(script)))

    def test_benign_powershell_has_no_pattern_flags(self):
        rejects, flags, _ = A.inspect_content("x.ps1", PS1_BENIGN)
        self.assertEqual(rejects, [])
        self.assertEqual([f for f in flags if f["severity"] != A.SEV_INFO], [])

    def test_text_heuristics(self):
        text = "ok\nx = 'a\u202eb'\n" + "Q" * 1200 + "\n" + ("aB3+/" * 60) + "\n"
        codes = {f["code"] for f in A.text_heuristics(text)}
        self.assertIn("SUSPICIOUS_UNICODE_BIDI_CONTROL", codes)
        self.assertIn("EXTREMELY_LONG_LINE", codes)
        self.assertIn("BASE64_BLOB", codes)
        rnd = "".join(chr(33 + (i * 7919) % 90) for i in range(200))
        tok = re.sub(r"[^A-Za-z0-9+/=_-]", "", rnd) * 2
        self.assertIn("HIGH_ENTROPY_DATA", {f["code"] for f in A.text_heuristics(tok)})

    def test_csv_and_json_flags(self):
        _r, flags, _ = A.inspect_content("x.csv", b"name,value\nx,=HYPERLINK(\"http://x\")\ny,-5\n")
        self.assertIn("CSV_FORMULA_PREFIX", {f["code"] for f in flags})
        _r, flags, _ = A.inspect_content("x.json", b"{not json")
        self.assertIn("INVALID_JSON", {f["code"] for f in flags})

    def test_zero_byte(self):
        rejects, flags, enc = A.inspect_content("x.ps1", b"")
        self.assertEqual(rejects, [])
        self.assertEqual(flags[0]["code"], "ZERO_BYTE_FILE")


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(self.tmp), True)

    def write(self, data):
        path = self.tmp / "c.json"
        path.write_text(json.dumps(data))
        return str(path)

    def test_denied_extension_cannot_be_allowlisted(self):
        with self.assertRaises(A.ConfigError):
            A.load_config(self.write({"allowed_extensions": ["ps1", "exe"]}))

    def test_unknown_key_and_bad_types_rejected(self):
        with self.assertRaises(A.ConfigError):
            A.load_config(self.write({"run_this": "x"}))
        with self.assertRaises(A.ConfigError):
            A.load_config(self.write({"max_file_bytes": "big"}))
        with self.assertRaises(A.ConfigError):
            A.load_config(self.write({"destination_dir_name": "../up"}))

    def test_valid_config_and_example(self):
        cfg = A.load_config(self.write({"allowed_extensions": [".PS1", "log"], "max_files": 10}))
        self.assertEqual(cfg["allowed_extensions"], ["log", "ps1"])
        example = HERE.parent / "config.example.json"
        self.assertEqual(A.load_config(str(example))["allowed_extensions"], sorted(A.DEFAULT_ALLOWED_EXTENSIONS))


class HashParsingTests(unittest.TestCase):
    def test_formats(self):
        h1, h2, h3 = "a" * 64, "b" * 64, "c" * 64
        parsed = A.parse_hash_text("# comment\n%s  x.ps1\n%s *sub/y.txt\nSHA256 (z.md) = %s\n%s\n" % (h1, h2, h3, h1.upper()))
        self.assertEqual(parsed.errors, [])
        self.assertEqual(parsed.named, {"x.ps1": h1, "sub/y.txt": h2, "z.md": h3})
        self.assertEqual(parsed.bare, {h1})
        js = A.parse_hash_json(json.dumps({"sha256": {"x.ps1": h1}, "hashes": [h2]}))
        self.assertEqual(js.errors, [])

    def test_unsafe_or_conflicting_entries_rejected(self):
        self.assertTrue(A.parse_hash_text("%s  ../etc/passwd\n" % ("a" * 64)).errors)
        self.assertTrue(A.parse_hash_text("%s  x\n%s  x\n" % ("a" * 64, "b" * 64)).errors)
        self.assertTrue(A.parse_hash_text("not a hash line\n").errors)


class ParsingTests(unittest.TestCase):
    def test_lsblk_parsing(self):
        sample = {"blockdevices": [
            {"name": "zram0", "kname": "zram0", "maj:min": "253:0", "type": "disk", "size": 0},
            {"name": "sdb", "kname": "sdb", "maj:min": "8:16", "type": "disk", "tran": "usb", "rm": True,
             "hotplug": "1", "ro": False, "size": 16000000000, "model": "Cruzer  ", "vendor": "SanDisk",
             "serial": "4C53", "children": [
                 {"name": "sdb1", "kname": "sdb1", "maj:min": "8:17", "type": "part", "size": 15999000000,
                  "fstype": "vfat", "uuid": "ABCD-1234", "label": "EVIL\x1bLABEL"}]},
            {"name": "sdc", "kname": "sdc", "maj:min": "8:32", "type": "disk", "tran": "usb", "rm": "1",
             "size": 4000000000, "fstype": "vfat", "uuid": "1111-2222"},
            {"name": "bad/name", "kname": "../x", "maj:min": "8:48", "type": "disk", "size": 10},
        ]}
        disks = A.parse_lsblk_json(json.dumps(sample))
        self.assertEqual([d.kname for d in disks], ["sdb", "sdc"])
        self.assertEqual(disks[0].model, "Cruzer")
        self.assertTrue(disks[0].hotplug and disks[0].removable)
        self.assertEqual(disks[0].partitions[0].fstype, "vfat")
        self.assertTrue(disks[1].whole_disk_fs)
        self.assertEqual(disks[1].partitions[0].kname, "sdc")

    def test_mountinfo_parsing(self):
        line = b"36 25 8:17 / /media/demo/MY\\040STICK rw,nosuid,nodev shared:1 - vfat /dev/sdb1 rw,fmask=0022\n"
        entries = A.parse_mountinfo(line)
        self.assertEqual(entries[0].target, "/media/demo/MY STICK")
        self.assertEqual(entries[0].maj_min, "8:17")
        self.assertIn("rw", entries[0].options)
        self.assertEqual(entries[0].fstype, "vfat")

    def test_mount_options(self):
        _t, opts = A.mount_options("vfat", "ro", 1000, 1000)
        for o in ("ro", "nodev", "nosuid", "noexec", "uid=1000", "fmask=0377"):
            self.assertIn(o, opts.split(","))
        kt, opts = A.mount_options("ext4", "ro", 1000, 1000)
        self.assertIn("noload", opts.split(","))
        _t, opts = A.mount_options("exfat", "rw", 1000, 1000)
        self.assertIn("rw", opts.split(","))
        with self.assertRaises(A.BlockingError):
            A.mount_options("ntfs", "rw", 0, 0)
        with self.assertRaises(A.BlockingError):
            A.mount_options("btrfs", "ro", 0, 0)

    def test_fingerprint_matching(self):
        src = A.sim_disk("sdb", 9, "S1", model="M", vendor="V", size=100)
        fp = src.identity()
        self.assertTrue(A.matches_fingerprint(fp, A.sim_disk("sdx", 20, "S1", model="Other", size=5)))
        self.assertFalse(A.matches_fingerprint(fp, A.sim_disk("sdx", 20, "S2", model="M", vendor="V", size=100)))
        noserial = A.sim_disk("sdx", 20, "", model="M", vendor="V", size=100, uuid="0000-0000")
        self.assertTrue(A.matches_fingerprint(fp, noserial))
        same_uuid = A.sim_disk("sdy", 21, "S9", model="Q", uuid=src.partitions[0].uuid)
        self.assertTrue(A.matches_fingerprint(fp, same_uuid))


class CommandRunnerTests(unittest.TestCase):
    def test_find_tool_rejects_odd_names(self):
        with self.assertRaises(ValueError):
            A.find_tool("../bin/sh")
        with self.assertRaises(ValueError):
            A.find_tool("a b")

    @unittest.skipUnless(A.find_tool("echo"), "echo not available")
    def test_arguments_are_never_interpreted_by_a_shell(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(tmp), True)
        marker = tmp / "pwned"
        payload = "; touch %s $(touch %s) | touch %s" % (marker, marker, marker)
        res = A.CommandRunner().run("echo", [payload])
        self.assertEqual(res.stdout.strip(), payload)
        self.assertFalse(marker.exists())

    def test_missing_tool(self):
        with self.assertRaises(A.ToolMissing):
            A.CommandRunner().run("definitely-not-a-real-tool-xyz", [])


# ---------------------------------------------------------------------------
# Workflow tests (simulated devices)
# ---------------------------------------------------------------------------

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)

    def test_normal_ps1_transfer(self):
        h = self.h
        h.put("WIN11_STANDALONE_LOCKDOWN_V3.ps1", PS1_BENIGN)
        h.put("docs/notes.md", b"# notes\n")
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual(s["phase"], A.PHASE_SOURCE_REMOVED)
        self.assertEqual(len(s["files"]), 2)
        self.assertTrue(all(f["hash_status"] == A.HASH_NOT_PREAUTHORIZED for f in s["files"]))
        # source was mounted read-only with hardening options and the block device set read-only
        kname, fstype, opts = h.mount_calls()[0][1]
        self.assertEqual(kname, "sdb1")
        self.assertTrue({"ro", "nodev", "nosuid", "noexec"} <= set(opts.split(",")))
        self.assertIn("sdb", h.backend.readonly)
        self.assertEqual(h.approve_all(), 0, h.output())
        self.assertEqual(h.release(), 0, h.output())
        s = h.session()
        self.assertEqual(s["phase"], A.PHASE_RELEASED)
        self.assertEqual(s["verification"]["result"], "PASS")
        out_file = h.dst / "RECOVERY_TRANSFER" / "FILES" / "WIN11_STANDALONE_LOCKDOWN_V3.ps1"
        self.assertEqual(out_file.read_bytes(), PS1_BENIGN)
        self.assertFalse(out_file.stat().st_mode & 0o111)
        self.assertEqual(h.dest_files(), sorted([
            "RECOVERY_TRANSFER/FILES/WIN11_STANDALONE_LOCKDOWN_V3.ps1", "RECOVERY_TRANSFER/FILES/docs/notes.md",
            "RECOVERY_TRANSFER/MANIFEST/SHA256SUMS.txt", "RECOVERY_TRANSFER/MANIFEST/manifest.json",
            "RECOVERY_TRANSFER/REPORTS/transfer-report.json", "RECOVERY_TRANSFER/REPORTS/transfer-report.txt"]))
        manifest = json.loads((h.dst / "RECOVERY_TRANSFER/MANIFEST/manifest.json").read_text())
        self.assertEqual({f["hash_status"] for f in manifest["files"]}, {A.HASH_NOT_PREAUTHORIZED})
        report = (h.dst / "RECOVERY_TRANSFER/REPORTS/transfer-report.txt").read_text()
        self.assertNotRegex(report, r"(?i)\bsafe\b")
        self.assertIn("NO TRUSTED SOURCE HASH AVAILABLE", report)
        self.assertNotRegex(h.output(), r"(?i)\bsafe\b")
        # destination writes used rw + hardening options; verification used a fresh ro mount
        dest_mounts = [c[1] for c in h.mount_calls() if c[1][0] == "sdc1"]
        self.assertEqual([("rw" in m[2].split(",")) for m in dest_mounts], [True, False])
        for m in dest_mounts:
            self.assertTrue({"nodev", "nosuid", "noexec"} <= set(m[2].split(",")))
        self.assertEqual(h.run(["verify-clean"], [("Insert ONLY the CLEAN USB", ""), ("Type YES", "YES")]), 0, h.output())
        self.assertEqual(h.run(["report"]), 0)
        self.assertTrue(list((h.state / "reports").glob("*.json")))

    def test_trusted_hash_match(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        trusted = h.tmp / "trusted_hashes.txt"
        trusted.write_text("%s  script.ps1\n" % A.sha256_hex(PS1_BENIGN))
        self.assertEqual(h.ingest(["--trusted-hashes", str(trusted)]), 0, h.output())
        rec = h.session()["files"][0]
        self.assertEqual(rec["hash_status"], A.HASH_MATCH)
        # trusted-match approval needs no APPROVE phrase
        self.assertEqual(h.run(["review"], [("Approve file", "a")]), 0, h.output())
        self.assertEqual(h.release(), 0, h.output())
        self.assertIn("INTEGRITY VERIFIED AGAINST TRUSTED HASH", h.output())

    def test_trusted_hash_mismatch_blocks_release(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        h.put("other.txt", b"fine\n")
        trusted = h.tmp / "trusted.json"
        trusted.write_text(json.dumps({"sha256": {"script.ps1": "0" * 64}}))
        self.assertEqual(h.ingest(["--trusted-hashes", str(trusted)]), 0, h.output())
        s = h.session()
        rec = [f for f in s["files"] if f["relative_path"] == "script.ps1"][0]
        self.assertEqual(rec["hash_status"], A.HASH_MISMATCH)
        self.assertIn("TRUSTED_HASH_MISMATCH", {b["code"] for b in s["blocking"]})
        h.approve_all()
        self.assertFalse(rec["approved"])
        self.assertEqual(h.release(), 1)
        self.assertIn("TRUSTED_HASH_MISMATCH", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_operator_entered_hash_mismatch_is_sticky(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        rules = [("Approve file", "h", "once"), ("Paste the independently trusted", "1" * 64), ("Approve file", "q")]
        self.assertEqual(h.run(["review"], rules), 0, h.output())
        self.assertEqual(h.session()["files"][0]["hash_status"], A.HASH_MISMATCH)
        trusted = h.tmp / "t.txt"
        trusted.write_text("%s  script.ps1\n" % A.sha256_hex(PS1_BENIGN))
        h.run(["review", "--trusted-hashes", str(trusted), "--list"])
        self.assertEqual(h.session()["files"][0]["hash_status"], A.HASH_MISMATCH)
        self.assertEqual(h.release(), 1)

    def test_trusted_hash_file_on_dirty_usb_refused(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        h.put("trusted.txt", ("%s  script.ps1\n" % A.sha256_hex(PS1_BENIGN)).encode())
        self.assertEqual(h.ingest(["--trusted-hashes", str(h.src / "trusted.txt")]), 1)
        self.assertIn("TRUSTED_HASH_ON_REMOVABLE", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_BLOCKED)

    def test_source_supplied_hash_list_is_untrusted(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        h.put("SHA256SUMS.txt", ("%s  script.ps1\n" % A.sha256_hex(PS1_BENIGN)).encode())
        self.assertEqual(h.ingest(), 0, h.output())
        rec = [f for f in h.session()["files"] if f["relative_path"] == "script.ps1"][0]
        self.assertEqual(rec["hash_status"], A.HASH_NOT_PREAUTHORIZED)
        self.assertIn("SOURCE_SUPPLIED_HASH_MATCH", {f["code"] for f in rec["review_flags"]})

    def test_source_supplied_hash_list_mismatch_flagged(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        h.put("hashes.sha256", ("%s  script.ps1\n" % ("f" * 64)).encode())
        self.assertEqual(h.ingest(), 0, h.output())
        rec = [f for f in h.session()["files"] if f["relative_path"] == "script.ps1"][0]
        self.assertIn("SOURCE_SUPPLIED_HASH_MISMATCH", {f["code"] for f in rec["review_flags"]})

    def test_malicious_and_unicode_filenames_left_behind(self):
        h = self.h
        names = ["evil\nname.ps1", "CON.txt", "invoice\u202egnp.ps1", "scr\u200bipt.ps1", "trail.txt ",
                 "\u0430dmin.ps1", "a:b.txt"]
        for n in names:
            h.put(n, PS1_BENIGN)
        h.put("good.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual([f["relative_path"] for f in s["files"]], ["good.ps1"])
        self.assertEqual(sorted(r["original_name"] for r in s["rejected"]), sorted(names))
        out = h.output()
        self.assertNotIn("\u202e", out)
        self.assertNotIn("\u200b", out)
        self.assertNotIn("evil\nname", out)

    def test_symlink_source_not_followed(self):
        h = self.h
        secret = h.outside / "secret.txt"
        secret.write_bytes(b"TOP SECRET CONTENT\n")
        os.symlink(str(secret), str(h.src / "link.txt"))
        os.symlink(str(h.outside), str(h.src / "linkdir"))
        h.put("good.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual([f["relative_path"] for f in s["files"]], ["good.ps1"])
        reasons = {r["original_name"]: r["reasons"] for r in s["rejected"]}
        self.assertEqual(reasons["link.txt"], ["SYMLINK_NOT_FOLLOWED"])
        self.assertEqual(reasons["linkdir"], ["SYMLINK_NOT_FOLLOWED"])
        qdir = A.StateStore(h.state).quarantine_dir(s["run_id"])
        for q in qdir.iterdir():
            self.assertNotIn(b"TOP SECRET", q.read_bytes())

    def test_symlink_destination_not_followed(self):
        h = self.h
        h.put("good.ps1", PS1_BENIGN)
        os.symlink(str(h.outside), str(h.dst / "RECOVERY_TRANSFER"))
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        self.assertEqual(h.release(), 0, h.output())
        self.assertEqual(list(h.outside.iterdir()), [])
        tdir = h.session()["release"]["transfer_dir"]
        self.assertTrue(tdir.startswith("RECOVERY_TRANSFER_"))
        self.assertTrue((h.dst / tdir / "FILES" / "good.ps1").is_file())

    def test_destination_writer_path_safety(self):
        h = self.h
        link_root = h.tmp / "rootlink"
        os.symlink(str(h.dst), str(link_root))
        with self.assertRaises(A.BlockingError) as cm:
            A.DestinationWriter(link_root, "RECOVERY_TRANSFER", "20260101T000000Z-00000000").open()
        self.assertEqual(cm.exception.code, "DESTINATION_INVALID")
        writer = A.DestinationWriter(h.dst, "RECOVERY_TRANSFER", "20260101T000000Z-00000000")
        writer.open()
        try:
            for bad, code in (("../escape.txt", "PATH_TRAVERSAL"), ("/etc/x.txt", "ABSOLUTE_PATH"),
                              ("a/../../x.txt", "PATH_TRAVERSAL")):
                with self.assertRaises(A.BlockingError) as cm:
                    writer.write_file(bad, b"x")
                self.assertEqual(cm.exception.code, code)
            writer.write_file("ok.txt", b"x")
            with self.assertRaises(A.BlockingError):
                writer.write_file("ok.txt", b"y")
        finally:
            writer.close()
        self.assertFalse((h.tmp / "escape.txt").exists())

    def test_fake_txt_and_nul_ps1_rejected(self):
        h = self.h
        h.put("readme.txt", pe_bytes())
        h.put("payload.ps1", b"\x00\x01" * 400)
        h.put("good.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        reasons = {r["original_name"]: r["reasons"] for r in s["rejected"]}
        self.assertIn("BINARY_SIGNATURE:PE_EXECUTABLE", reasons["readme.txt"])
        self.assertEqual(reasons["payload.ps1"], ["NUL_BYTES_PRESENT"])
        self.assertEqual([f["relative_path"] for f in s["files"]], ["good.ps1"])

    def test_both_devices_present_at_ingest(self):
        h = self.h
        h.put("good.ps1", PS1_BENIGN)
        h.insert_source()
        h.insert_dest()
        self.assertEqual(h.run(["ingest"], h.ingest_rules()), 1)
        self.assertIn("MULTIPLE_REMOVABLE_DEVICES", h.output())
        self.assertEqual(h.mount_calls(), [])
        self.assertEqual(h.session()["phase"], A.PHASE_BLOCKED)

    def test_both_devices_present_at_release(self):
        h = self.h
        h.put("good.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()

        def both(prompt):
            h.insert_dest()
            h.insert_source()
            return ""
        self.assertEqual(h.run(["release"], [("Insert the CLEAN destination USB", both), ("Type WRITE", "WRITE 0001")]), 1)
        self.assertIn("MULTIPLE_REMOVABLE_DEVICES", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_source_still_present_blocks_release_mode(self):
        h = self.h
        h.put("good.ps1", PS1_BENIGN)
        h.insert_source()
        rules = [("Type YES", "YES"), ("then type REMOVED", "REMOVED", "once"),
                 ("then type REMOVED", "q")]
        self.assertEqual(h.run(["ingest"], rules), 2)
        self.assertIn("DIRTY USB STILL DETECTED", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_INGESTED)
        # review (and therefore approval) must not proceed while the source is attached
        self.assertEqual(h.run(["review"], [("then type REMOVED", "REMOVED", "once"), ("then type REMOVED", "q")]), 2)
        self.assertIn("DIRTY USB STILL DETECTED", h.output())
        self.assertFalse(any(f["approved"] for f in h.session()["files"]))
        self.assertEqual(h.run(["release"], [("then type REMOVED", "q")]), 1)
        self.assertEqual(h.dest_files(), [])
        self.assertEqual(h.session()["phase"], A.PHASE_INGESTED)

    def test_destination_matching_source_identity_refused(self):
        h = self.h
        h.put("good.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        twin = A.sim_disk("sdd", 11, "DIRTY0001", model="Different")

        def insert_twin(prompt):
            h.backend.add_device(twin, {"sdd1": h.dst})
            return ""
        self.assertEqual(h.run(["release"], [("Insert the CLEAN destination USB", insert_twin), ("Type WRITE", "WRITE 0001")]), 1)
        self.assertIn("DESTINATION_IS_SOURCE", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_source_identity_change_mid_run(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.put("b.ps1", PS1_BENIGN + b"#")

        def mutate(be, event):
            if event == "scan_entry" and "sdb" in be.devices:
                be.devices["sdb"]["disk"].serial = "SWAPPED"
        h.backend.auto = mutate
        self.assertEqual(h.ingest(), 1)
        self.assertIn("IDENTITY_CHANGED", h.output())
        s = h.session()
        self.assertEqual(s["phase"], A.PHASE_BLOCKED)
        self.assertIn(("unmount", "sdb1"), h.backend.calls)
        self.assertFalse(A.StateStore(h.state).quarantine_dir(s["run_id"]).exists())

    def test_destination_identity_change_mid_run(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()

        def mutate(be, event):
            if event == "before_destination_write":
                be.devices["sdc"]["disk"].serial = "OTHER0001"
        h.backend.auto = mutate
        self.assertEqual(h.release(), 1)
        self.assertIn("IDENTITY_CHANGED", h.output())
        self.assertIn("UNVERIFIED directory", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_SOURCE_REMOVED)
        self.assertEqual([p for p in h.dest_files() if "/FILES/" in p], [])

    def test_destination_hash_mismatch(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()

        def corrupt(be, event):
            if event == "after_destination_write":
                target = h.dst / "RECOVERY_TRANSFER" / "FILES" / "a.ps1"
                target.write_bytes(b"tampered")
        h.backend.auto = corrupt
        self.assertEqual(h.release(), 1)
        self.assertIn("DESTINATION_VERIFICATION_MISMATCH", h.output())
        self.assertIn("HASH MISMATCH FILES/a.ps1", h.output())
        self.assertNotEqual(h.session()["phase"], A.PHASE_RELEASED)

    def test_destination_unexpected_extra_file_detected(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()

        def add_file(be, event):
            if event == "after_destination_write":
                (h.dst / "RECOVERY_TRANSFER" / "FILES" / "autorun.inf").write_bytes(b"[autorun]\n")
        h.backend.auto = add_file
        self.assertEqual(h.release(), 1)
        self.assertIn("UNEXPECTED FILE", h.output())

    def test_unexpected_unmount_during_scan(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)

        def yank_mount(be, event):
            if event == "scan_entry":
                be.mounted.pop("sdb1", None)
        h.backend.auto = yank_mount
        self.assertEqual(h.ingest(), 1)
        self.assertIn("FILESYSTEM_DISAPPEARED", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_BLOCKED)

    def test_device_removed_during_scan(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)

        def yank_device(be, event):
            if event == "scan_entry":
                be.remove_device("sdb")
        h.backend.auto = yank_device
        self.assertEqual(h.ingest(), 1)
        self.assertRegex(h.output(), "FILESYSTEM_DISAPPEARED|DEVICE_DISAPPEARED")

    def test_source_automounted_read_write(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source(automount="rw")
        self.assertEqual(h.run(["ingest"], h.ingest_rules([("Type CONTINUE", "CONTINUE")])), 0, h.output())
        out = h.output()
        self.assertIn("MOUNTED READ-WRITE", out)
        self.assertIn("automount should ideally be disabled", out)
        codes = {w["code"] for w in h.session()["warnings"]}
        self.assertIn("SOURCE_WAS_MOUNTED_RW", codes)
        unmount_index = h.backend.calls.index(("unmount", "sdb1"))
        mount_index = h.backend.calls.index(h.mount_calls()[0])
        self.assertLess(unmount_index, mount_index)
        self.assertTrue(h.session()["source"]["automount_events"][0]["read_write"])

    def test_source_automounted_read_write_operator_stops(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source(automount="rw")
        self.assertEqual(h.run(["ingest"], h.ingest_rules([("Type CONTINUE", "stop")])), 2)
        self.assertEqual(h.mount_calls(), [])
        self.assertEqual(h.session()["phase"], A.PHASE_CANCELLED)

    def test_missing_clamav_is_not_fatal(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        self.assertIn("CLAMAV_UNAVAILABLE", {w["code"] for w in h.session()["warnings"]})
        self.assertIn("ClamAV is not installed", h.output())

    def test_clamav_detection_blocks_file(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.put("b.txt", b"hello\n")

        def scan(paths):
            return {"available": True, "version": "1.0", "database_version": "1", "database_date": "x",
                    "exit_code": 1, "results": {p: ("Eicar-Test-Signature FOUND" if p.endswith("f000001.dat") else "OK")
                                                for p in paths}}
        h.backend.clamav_result = scan
        self.assertEqual(h.ingest(), 0, h.output())
        h.approve_all()
        files = {f["relative_path"]: f for f in h.session()["files"]}
        self.assertFalse(files["a.ps1"]["approved"])
        self.assertTrue(files["b.txt"]["approved"])
        self.assertIn("not proof", h.output())

    def test_duplicate_filename_collision(self):
        h = self.h
        h.put("Script.ps1", PS1_BENIGN)
        h.put("script.ps1", PS1_BENIGN)
        h.put("A/x.txt", b"1\n")
        h.put("a/x.txt", b"2\n")
        h.put("unique.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual([f["relative_path"] for f in s["files"]], ["unique.ps1"])
        collided = sorted(r["original_name"] for r in s["rejected"] if "NAME_COLLISION" in r["reasons"])
        self.assertEqual(collided, ["Script.ps1", "script.ps1", "x.txt", "x.txt"])

    def test_zero_byte_file_quarantined_with_flag(self):
        h = self.h
        h.put("empty.ps1", b"")
        self.assertEqual(h.ingest(), 0, h.output())
        rec = h.session()["files"][0]
        self.assertEqual(rec["size"], 0)
        self.assertIn("ZERO_BYTE_FILE", {f["code"] for f in rec["review_flags"]})

    def test_large_unexpected_file_rejected(self):
        h = self.h
        h.config(max_file_bytes=1024)
        h.put("big.txt", b"A\n" * 2048)
        h.put("small.txt", b"ok\n")
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual([f["relative_path"] for f in s["files"]], ["small.txt"])
        self.assertEqual({r["original_name"]: r["reasons"] for r in s["rejected"]}["big.txt"], ["TOO_LARGE"])

    def test_unsupported_types_and_metadata_left_behind(self):
        h = self.h
        for name in ("tool.exe", "doc.docx", "data.xyz", "mod.psm1", ".hidden.txt", "autorun.inf", "archive.zip"):
            h.put(name, b"x")
        h.put("System Volume Information/IndexerVolumeGuid", b"x")
        h.put("$RECYCLE.BIN/x.txt", b"x")
        h.put(".Trash-1000/files/x.txt", b"x")
        h.put("good.md", b"# ok\n")
        self.assertEqual(h.ingest(), 0, h.output())
        s = h.session()
        self.assertEqual([f["relative_path"] for f in s["files"]], ["good.md"])
        reasons = {r["original_name"]: r["reasons"] for r in s["rejected"]}
        self.assertIn("DENIED_FILE_TYPE", reasons["tool.exe"])
        self.assertIn("DENIED_FILE_TYPE", reasons["doc.docx"])
        self.assertIn("TYPE_NOT_ALLOWLISTED", reasons["data.xyz"])
        self.assertIn("DENIED_FILE_TYPE", reasons["mod.psm1"])
        self.assertIn("HIDDEN_FILE", reasons[".hidden.txt"])
        self.assertIn("SYSTEM_METADATA_FILE", reasons["autorun.inf"])
        self.assertEqual(reasons["System Volume Information"], ["HIDDEN_OR_SYSTEM_DIRECTORY_SKIPPED"])
        self.assertEqual(reasons["$RECYCLE.BIN"], ["HIDDEN_OR_SYSTEM_DIRECTORY_SKIPPED"])

    def test_special_file_stops_ingest(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        os.mkfifo(str(h.src / "pipe.txt"))
        self.assertEqual(h.ingest(), 1)
        self.assertIn("UNSUPPORTED_SPECIAL_FILE", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_BLOCKED)

    def test_system_disk_cannot_be_selected(self):
        h = self.h
        system = A.sim_disk("sdz", 30, "SYS0001", model="UsbSystemDisk")
        h.backend.add_device(system, {"sdz1": h.outside}, protected="SYSTEM DISK (mounted at /)")
        disks, protected = A.enumerate_devices(A.Context(None, h.backend, A.load_config(None), A.StateStore(h.state), None))
        self.assertNotIn("sdz", [d.kname for d in A.removable_disks(disks, protected)])
        self.assertNotIn("sda", [d.kname for d in A.removable_disks(disks, protected)])
        # with only protected disks present, ingest never offers them and waits for the dirty USB
        self.assertEqual(h.run(["ingest"], [("Insert ONLY the DIRTY USB", "q")]), 2)
        self.assertEqual(h.mount_calls(), [])
        self.assertEqual(h.run(["prepare-clean-usb"], [("Insert ONLY the USB drive to ERASE", "q")]), 2)
        self.assertTrue((h.outside).exists())

    def test_live_boot_disk_cannot_be_selected_and_does_not_count(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        # live USB stick (sda, USB transport) is present throughout; the dirty USB is still selected alone
        self.assertEqual(h.ingest(), 0, h.output())
        self.assertEqual(h.session()["source"]["identity"]["kname"], "sdb")
        self.assertNotIn(("mount", ("sda1",)), h.backend.calls)
        self.assertTrue(all(c[1][0] != "sda1" for c in h.mount_calls()))

    def test_protected_device_during_revalidation_blocks(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        original = h.backend.protected_disks
        state = {"n": 0}

        def flip():
            state["n"] += 1
            result = original()
            if state["n"] > 1:
                result["sdb"] = "SYSTEM DISK (test)"
            return result
        h.backend.protected_disks = flip
        self.assertEqual(h.run(["ingest"], h.ingest_rules()), 1)
        self.assertIn("PROTECTED_DEVICE", h.output())

    def test_operator_cancellation_at_identity(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        self.assertEqual(h.run(["ingest"], [("Type YES", "no")]), 2)
        s = h.session()
        self.assertEqual(s["phase"], A.PHASE_CANCELLED)
        self.assertEqual(h.mount_calls(), [])
        self.assertFalse(A.StateStore(h.state).quarantine_dir(s["run_id"]).exists())

    def test_operator_cancellation_eof(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        self.assertEqual(h.run(["ingest"], []), 2)
        self.assertEqual(h.mount_calls(), [])

    def test_wrong_write_phrase_writes_nothing(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        rules = [("Insert the CLEAN destination USB", h.dest_insert_answer), ("Type WRITE", "WRITE")]
        self.assertEqual(h.run(["release"], rules), 2)
        self.assertEqual(h.dest_files(), [])
        self.assertFalse(any(c[1][0] == "sdc1" for c in h.mount_calls()))
        self.assertEqual(h.session()["phase"], A.PHASE_SOURCE_REMOVED)

    def test_noninteractive_fails_closed(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        console = A.Console(input_fn=lambda p: "YES", out=h.out, interactive=False, color=False)
        rc = A.main(["--state-dir", str(h.state), "ingest"], console=console, backend=h.backend)
        self.assertEqual(rc, 2)
        self.assertEqual(h.mount_calls(), [])

    def test_session_guards(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.run(["release"]), 1)
        self.assertIn("NO_SESSION", h.output())
        self.assertEqual(h.ingest(), 0)
        self.assertEqual(h.release(), 1)
        self.assertIn("NOTHING_APPROVED", h.output())
        h.insert_source()
        self.assertEqual(h.run(["ingest"], h.ingest_rules()), 1)
        self.assertIn("SESSION_ACTIVE", h.output())
        self.assertEqual(h.run(["ingest", "--new-session"], h.ingest_rules()), 0, h.output())

    def test_quarantine_tamper_detected(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        s = h.session()
        qfile = A.StateStore(h.state).quarantine_dir(s["run_id"]) / s["files"][0]["quarantine_name"]
        qfile.write_bytes(PS1_BENIGN.replace(b"Applying", b"Removing"))
        self.assertEqual(h.release(), 1)
        self.assertIn("QUARANTINE_TAMPERED", h.output())
        self.assertEqual(h.session()["phase"], A.PHASE_BLOCKED)
        self.assertEqual(h.dest_files(), [])

    def test_quarantine_symlink_swap_detected(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        s = h.session()
        qfile = A.StateStore(h.state).quarantine_dir(s["run_id"]) / s["files"][0]["quarantine_name"]
        decoy = h.outside / "decoy"
        decoy.write_bytes(PS1_BENIGN)
        qfile.unlink()
        os.symlink(str(decoy), str(qfile))
        self.assertEqual(h.release(), 1)
        self.assertIn("QUARANTINE_TAMPERED", h.output())

    def test_quarantine_files_are_private_and_opaque(self):
        h = self.h
        h.put("x.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        s = h.session()
        qdir = A.StateStore(h.state).quarantine_dir(s["run_id"])
        self.assertEqual(stat.S_IMODE(qdir.stat().st_mode), 0o700)
        for q in qdir.iterdir():
            self.assertRegex(q.name, r"^f\d{6}\.dat$")
            self.assertEqual(stat.S_IMODE(q.stat().st_mode), 0o600)

    def test_block_readonly_failure_requires_decision(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.backend.readonly_supported = False
        h.insert_source()
        self.assertEqual(h.run(["ingest"], h.ingest_rules([("Type PROCEED", "nope")])), 2)
        self.assertEqual(h.mount_calls(), [])
        h.backend.readonly_supported = False
        self.assertEqual(h.run(["ingest", "--new-session"],
                               h.ingest_rules([("Type PROCEED", "PROCEED")])), 0, h.output())
        self.assertIn("BLOCK_READONLY_UNVERIFIED", {w["code"] for w in h.session()["warnings"]})

    def test_destination_read_only_or_without_serial_refused(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        h.dest.ro = True
        self.assertEqual(h.release(), 1)
        self.assertIn("DESTINATION_READ_ONLY", h.output())
        h.remove("sdc")
        h.dest.ro = False
        h.dest.serial = ""
        self.assertEqual(h.release(), 1)
        self.assertIn("IDENTITY_UNCERTAIN", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_destination_unsupported_filesystem(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        h.dest.partitions[0].fstype = "ntfs"
        self.assertEqual(h.release(), 1)
        self.assertIn("UNSUPPORTED_FILESYSTEM", h.output())

    def test_prepare_clean_usb(self):
        h = self.h
        (h.dst / "old.txt").write_text("old")
        h.dest.partitions[0].fstype = "ntfs"
        rules = [("Insert ONLY the USB drive to ERASE", h.dest_insert_answer), ("Type ERASE", "ERASE 0001")]
        self.assertEqual(h.run(["prepare-clean-usb"], rules), 0, h.output())
        self.assertEqual(list(h.dst.iterdir()), [])
        self.assertEqual(h.backend.devices["sdc"]["disk"].partitions[0].fstype, "vfat")

    def test_prepare_clean_usb_wrong_phrase_erases_nothing(self):
        h = self.h
        (h.dst / "old.txt").write_text("old")
        rules = [("Insert ONLY the USB drive to ERASE", h.dest_insert_answer), ("Type ERASE", "ERASE")]
        self.assertEqual(h.run(["prepare-clean-usb"], rules), 2)
        self.assertTrue((h.dst / "old.txt").exists())

    def test_prepare_refused_while_source_not_removed(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        h.run(["ingest"], [("Type YES", "YES"), ("then type REMOVED", "q")])
        self.assertEqual(h.session()["phase"], A.PHASE_INGESTED)
        h.remove("sdb")
        self.assertEqual(h.run(["prepare-clean-usb"], [("Insert ONLY", h.dest_insert_answer), ("Type ERASE", "ERASE 0001")]), 1)
        self.assertIn("SOURCE_NOT_REMOVED", h.output())

    def test_network_lockdown_and_restore(self):
        h = self.h
        h.backend.net = {"interfaces_up": ["eth0", "wlan0"], "default_route": True, "rfkill": [], "known": True}
        self.assertEqual(h.run(["network-lockdown"]), 0, h.output())
        self.assertEqual(h.backend.net["interfaces_up"], [])
        saved = h.state / "network_lockdown.json"
        self.assertTrue(saved.exists())
        self.assertEqual(json.loads(saved.read_text())["before"]["interfaces_up"], ["eth0", "wlan0"])
        self.assertEqual(h.run(["network-restore"]), 0, h.output())
        self.assertEqual(h.backend.net["interfaces_up"], ["eth0", "wlan0"])
        self.assertFalse(saved.exists())

    def test_ingest_with_offline_lockdown(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        h.backend.net = {"interfaces_up": ["eth0"], "default_route": True, "rfkill": [], "known": True}
        self.assertEqual(h.ingest(["--offline-lockdown"]), 0, h.output())
        self.assertEqual(h.session()["network"]["interfaces_up"], [])
        self.assertIn("OFFLINE", h.output())

    def test_installed_os_warning(self):
        h = self.h
        h.backend.live_detected = False
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        self.assertIn("cannot provide the same trust level", h.output())
        self.assertIn("NOT_LIVE_ENVIRONMENT", {w["code"] for w in h.session()["warnings"]})

    def test_insecure_state_dir_refused(self):
        h = self.h
        bad = h.tmp / "open_state"
        bad.mkdir()
        os.chmod(str(bad), 0o755)
        console = A.Console(input_fn=lambda p: "", out=h.out, interactive=True, color=False)
        self.assertEqual(A.main(["--state-dir", str(bad), "status"], console=console, backend=h.backend), 1)
        self.assertIn("STATE_DIR_INVALID", h.output())
        link = h.tmp / "link_state"
        os.symlink(str(h.outside), str(link))
        self.assertEqual(A.main(["--state-dir", str(link), "status"], console=console, backend=h.backend), 1)

    # -- regression tests for the security review findings
    def test_undetected_live_media_in_use_is_never_offered(self):
        h = self.h
        stray = A.sim_disk("sde", 12, "LIVEX001", model="UndetectedLive")
        h.backend.add_device(stray, {"sde1": h.outside})
        h.backend.mounted["sde1"] = {"target": "/run/somewhere/boot", "ro": True, "options": ["ro"], "automount": False}
        disks, protected = A.enumerate_devices(A.Context(None, h.backend, A.load_config(None), A.StateStore(h.state), None))
        self.assertTrue(protected["sde"].startswith("IN USE"))
        self.assertEqual(h.run(["ingest"], [("Insert ONLY the DIRTY USB", "q")]), 2)
        self.assertEqual(h.mount_calls(), [])

    def test_release_refuses_preinserted_devices(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()
        h.insert_source()
        self.assertEqual(h.release(), 1)
        self.assertIn("SOURCE_STILL_PRESENT", h.output())
        h.remove("sdb")
        h.insert_dest()
        self.assertEqual(h.release(), 1)
        self.assertIn("REMOVABLE_DEVICE_ALREADY_PRESENT", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_concurrent_remount_before_mount_blocks(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        original = h.backend.set_readonly

        def setro_then_automount(disk):
            result = original(disk)
            h.backend.mounted["sdb1"] = {"target": "/media/sim/sdb1", "ro": True, "options": ["ro"], "automount": True}
            return result
        h.backend.set_readonly = setro_then_automount
        self.assertEqual(h.ingest(), 1)
        self.assertIn("CONCURRENT_MOUNT", h.output())
        self.assertEqual(h.mount_calls(), [])

    def test_trusted_hash_file_from_quarantine_refused(self):
        h = self.h
        h.put("script.ps1", PS1_BENIGN)
        h.put("my.sha256", ("%s  script.ps1\n" % A.sha256_hex(PS1_BENIGN)).encode())
        self.assertEqual(h.ingest(), 0)
        s = h.session()
        listing = [f for f in s["files"] if f["relative_path"] == "my.sha256"][0]
        qpath = A.StateStore(h.state).quarantine_dir(s["run_id"]) / listing["quarantine_name"]
        self.assertEqual(h.run(["review", "--trusted-hashes", str(qpath), "--list"]), 1)
        self.assertIn("TRUSTED_HASH_FROM_DIRTY_MEDIA", h.output())
        self.assertEqual(h.session()["files"][0]["hash_status"], A.HASH_NOT_PREAUTHORIZED)

    def test_io_error_during_release_is_recorded_as_blocking(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0)
        h.approve_all()

        def fail(be, event):
            if event == "before_destination_write":
                raise OSError(28, "No space left on device")
        h.backend.auto = fail
        self.assertEqual(h.release(), 1)
        self.assertIn("IO_ERROR", h.output())
        s = h.session()
        self.assertEqual(s["release_attempts"][-1]["result"], "BLOCKED")
        self.assertNotIn("sdc1", h.backend.mounted)

    def test_status_reports_coexistence(self):
        h = self.h
        h.insert_source()
        h.insert_dest()
        self.assertEqual(h.run(["status"]), 0)
        self.assertIn("More than one removable storage device", h.output())


class ConsoleTests(unittest.TestCase):
    def test_broken_pipe_does_not_abort(self):
        class ClosedPipe(io.StringIO):
            def write(self, text):
                raise BrokenPipeError(32, "Broken pipe")
        console = A.Console(input_fn=lambda p: "", out=ClosedPipe(), interactive=False, color=False)
        console.blocking("still running")
        console.line("more output")


class SourceHygieneTests(unittest.TestCase):
    def sources(self):
        files = [HERE.parent / "airlock.py"] + sorted(HERE.glob("*.py"))
        return {p: p.read_text(encoding="utf-8") for p in files}

    def test_no_backticks_shell_true_or_eval(self):
        for path, text in self.sources().items():
            self.assertNotIn(chr(0x60), text, "%s contains a backtick" % path)
            self.assertNotIn("shell" + "=True", text, str(path))
            self.assertIsNone(re.search(r"\b(?:eval|exec)\s*\(", text), str(path))
            self.assertNotIn("import " + "pickle", text, str(path))
            self.assertNotIn("os." + "system", text, str(path))
            self.assertNotIn("bash" + " -c", text, str(path))

    def test_shell_scripts_hygiene(self):
        scripts = [p for p in (HERE.parent / "install.sh", HERE.parent / "run-airlock.sh") if p.exists()]
        builder = HERE.parent / "tools" / "make_bundle.py"
        if builder.exists():
            scripts.append(builder)
        for path in scripts:
            text = path.read_text()
            self.assertNotIn(chr(0x60), text, str(path))
            self.assertIsNone(re.search(r"\beval\b", text), str(path))
            self.assertNotIn("bash" + " -c", text, str(path))
            self.assertIsNone(re.search(r"\b(?:curl|wget|apt-get|apt\s+install\s+-y)\b", text), str(path))
            self.assertNotIn("chmod 777", text, str(path))


@unittest.skipUnless(sys.platform.startswith("linux") and A.find_tool("lsblk"), "requires Linux with lsblk")
class RealBackendReadOnlySmokeTests(unittest.TestCase):
    """Read-only enumeration on the host. Never mounts, writes or changes any device."""

    def test_enumeration_and_protection(self):
        backend = A.LinuxBackend(A.CommandRunner())
        disks = backend.list_disks()
        self.assertIsInstance(disks, list)
        protected = backend.protected_disks()
        self.assertIsInstance(protected, dict)
        env = backend.environment()
        self.assertIn("live_detected", env)
        self.assertIsInstance(A.read_mountinfo(), list)


if __name__ == "__main__":
    unittest.main()
