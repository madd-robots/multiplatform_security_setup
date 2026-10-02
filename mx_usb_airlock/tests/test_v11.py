# SPDX-License-Identifier: GPL-3.0-or-later
"""V1.1 tests: Termux preparation, signed manifest, encrypted transport, whole-destination
verification, read-only fail-closed behaviour and the gate state machine.

Real minisign and age binaries are used with throw-away keys generated in temporary
directories (no production keys).  Devices are simulated (SimulatedBackend), so no
block device is touched.  Skipped when minisign/age are not installed.
"""

import importlib.util
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

import airlock as A  # noqa: E402
from test_airlock import Harness, PS1_BENIGN, pe_bytes  # noqa: E402

TOOLS = all(A.find_tool(t) for t in ("minisign", "age", "age-keygen"))


def load_termux():
    spec = importlib.util.spec_from_file_location("usb_airlock_prepare", str(ROOT / "termux" / "usb_airlock_prepare.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load_termux()
LARGE_TEXT = ("# line of hardening text that is long enough to fill several age chunks\r\n" * 2000).encode("ascii")


class V11Env:
    """A Termux key set, an MX key set pinned to it, and helpers to build and tamper packages."""

    def __init__(self, tc):
        self.tc = tc
        self.h = Harness(tc)
        self.tkeys = self.h.tmp / "termux_keys"
        self.mxkeys = self.h.tmp / "mx_keys"
        self.work = self.h.tmp / "work"
        self.work.mkdir()
        self.termux(["init-keys", "--no-password"])
        tc.assertEqual(self.mx(["init-transport-key"]), 0, self.h.output())
        self.recipient = A.KeyStore(self.mxkeys).recipient()
        self.termux(["set-recipient", self.recipient])
        pub = T.parse_public_key((self.tkeys / T.KEY_PUBLIC).read_bytes())
        self.fingerprint = pub["fingerprint"]
        rc = self.mx(["trust-signing-key", "--public-key", str(self.tkeys / T.KEY_PUBLIC)],
                     [("Type %s" % A.fingerprint_confirmation(self.fingerprint), A.fingerprint_confirmation(self.fingerprint))])
        tc.assertEqual(rc, 0, self.h.output())

    def termux(self, argv, keys=None):
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            rc = T.main(["--keys-dir", str(keys or self.tkeys)] + list(argv))
        self.tc.assertEqual(rc, 0, out.getvalue())
        return out.getvalue()

    def mx(self, argv, rules=()):
        return self.h.run(["--keys-dir", str(self.mxkeys)] + list(argv), rules)

    # -- packages
    def build(self, files=None, name="pkg", keys=None, **kw):
        src = self.work / (name + "_src")
        out = self.work / (name + "_out")
        src.mkdir()
        for rel, data in (files or {"WIN11_STANDALONE_LOCKDOWN_V3.ps1": PS1_BENIGN, "docs/notes.md": b"# notes\n"}).items():
            path = src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return T.prepare(keys or self.tkeys, out, source_dir=str(src), interactive_sign=False, **kw)

    def sign(self, pkg, comment=None, keys=None):
        manifest = (pkg / "manifest.json").read_bytes()
        if comment is None:
            data = json.loads(manifest.decode())
            comment = T.signed_comment(data.get("transfer_id", "x"), A.sha256_hex(manifest))
        (pkg / "manifest.minisig").unlink()
        res = subprocess.run([A.find_tool("minisign"), "-S", "-s", str((keys or self.tkeys) / T.KEY_SECRET),
                              "-m", str(pkg / "manifest.json"), "-x", str(pkg / "manifest.minisig"), "-t", comment],
                             capture_output=True, timeout=60)
        self.tc.assertEqual(res.returncode, 0, res.stderr)

    def rewrite_manifest(self, pkg, mutate, resign=True):
        data = json.loads((pkg / "manifest.json").read_text())
        result = mutate(data)
        raw = result if isinstance(result, bytes) else (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
        (pkg / "manifest.json").write_bytes(raw)
        if resign:
            self.sign(pkg)

    def set_payload(self, pkg, payload, update_manifest=True):
        (pkg / "payload.age").write_bytes(payload)
        if update_manifest:
            def mutate(m):
                m["payload"]["size"] = len(payload)
                m["payload"]["sha256"] = A.sha256_hex(payload)
            self.rewrite_manifest(pkg, mutate)

    def encrypt(self, plaintext):
        res = subprocess.run([A.find_tool("age"), "-r", self.recipient], input=plaintext, capture_output=True, timeout=60)
        self.tc.assertEqual(res.returncode, 0)
        return res.stdout

    def install(self, pkg):
        shutil.copytree(str(pkg), str(self.h.src / A.PACKAGE_DIR), symlinks=True)

    # -- MX workflow
    def ingest(self, extra_rules=()):
        self.h.insert_source()
        return self.mx(["ingest"], list(extra_rules) + self.h.ingest_rules())

    def approve(self):
        return self.mx(["review"], [("Type APPROVE", "APPROVE")])

    def release(self, extra_rules=()):
        return self.mx(["release"], list(extra_rules) + self.h.release_rules())

    def gates(self):
        return A.gates_passed(self.h.session())

    def qdir(self):
        return A.StateStore(self.h.state).quarantine_dir(self.h.session()["run_id"])

    def assert_blocked(self, code, gates_before=None):
        tc, h = self.tc, self.h
        tc.assertIn(code, h.output())
        s = h.session()
        tc.assertEqual(s["phase"], A.PHASE_BLOCKED)
        tc.assertFalse(self.qdir().exists(), "quarantine must be wiped after a refused ingest")
        tc.assertNotIn(A.GATE_STAGING_SEALED, self.gates())
        if gates_before is not None:
            tc.assertEqual(self.gates(), list(gates_before))
        tc.assertEqual(self.release(), 1)  # nothing can move forward
        tc.assertEqual(h.dest_files(), [])


def tar_bytes(members):
    """members: list of (TarInfo-modifier, name, data)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            info.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "/etc/passwd"
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return raw.getvalue()


# ---------------------------------------------------------------------------
# Termux preparation
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class TermuxPreparationTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)

    def test_valid_package_contents_hashes_signature_and_no_secrets(self):
        env = self.env
        files = {"WIN11_STANDALONE_LOCKDOWN_V3.ps1": PS1_BENIGN, "docs/notes.md": b"# notes for the operator\n"}
        pkg = env.build(files)
        self.assertEqual(sorted(p.name for p in pkg.iterdir()),
                         ["README_TRANSFER.txt", "TRANSFER_ID", "manifest.json", "manifest.minisig", "payload.age"])
        manifest = json.loads((pkg / "manifest.json").read_text())
        self.assertEqual(manifest["format_version"], 1)
        self.assertEqual(manifest["file_count"], 2)
        self.assertEqual({f["relative_path"]: f["sha256"] for f in manifest["files"]},
                         {k: A.sha256_hex(v) for k, v in files.items()})
        self.assertEqual(manifest["payload"]["sha256"], A.sha256_hex((pkg / "payload.age").read_bytes()))
        self.assertEqual({f["relative_path"]: f["file_type"] for f in manifest["files"]},
                         {"WIN11_STANDALONE_LOCKDOWN_V3.ps1": "powershell-script", "docs/notes.md": "markdown"})
        T.verify_package(env.tkeys, pkg)
        secret = (env.tkeys / T.KEY_SECRET).read_bytes().splitlines()[1]
        for child in pkg.iterdir():
            data = child.read_bytes()
            self.assertNotIn(secret, data)
            self.assertNotIn(b"AGE-SECRET-KEY", data)
            for body in files.values():
                if child.name != "manifest.json":
                    self.assertNotIn(body, data)
        self.assertTrue((pkg / "payload.age").read_bytes().startswith(b"age-encryption.org/v1\n"))
        # MX validates exactly what Termux produced
        A.validate_signed_manifest((pkg / "manifest.json").read_bytes(), A.load_config(None))

    def test_manifest_and_container_are_deterministic(self):
        contents = {"a.ps1": PS1_BENIGN, "b/c.txt": b"x\n"}
        self.assertEqual(T.build_container(contents), T.build_container(dict(reversed(list(contents.items())))))
        payload = b"age-encryption.org/v1\nfake"
        m1 = T.build_manifest("20260101T000000Z-00000000", "2026-01-01T00:00:00Z", contents, payload)
        m2 = T.build_manifest("20260101T000000Z-00000000", "2026-01-01T00:00:00Z", dict(reversed(list(contents.items()))), payload)
        self.assertEqual(m1, m2)

    def test_input_rejections(self):
        env = self.env
        base = env.work / "inputs"
        base.mkdir()
        (base / "ok.ps1").write_bytes(PS1_BENIGN)
        cases = {}
        os.symlink(str(base / "ok.ps1"), str(base / "link.ps1"))
        cases["symbolic link"] = ["link.ps1"]
        os.mkfifo(str(base / "pipe.ps1"))
        cases["FIFO"] = ["pipe.ps1"]
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(base / "sock.ps1"))
        cases["socket"] = ["sock.ps1"]
        os.link(str(base / "ok.ps1"), str(base / "hard.ps1"))
        cases["hard links"] = ["hard.ps1"]
        try:
            os.mknod(str(base / "dev.ps1"), 0o600 | stat.S_IFCHR, os.makedev(1, 3))
            cases["device node"] = ["dev.ps1"]
        except (PermissionError, OSError):
            pass
        for expected, names in cases.items():
            with self.assertRaises(T.PrepareError) as cm:
                T.prepare(env.tkeys, env.work / ("out_" + names[0]), files=[str(base / n) for n in names],
                          base=str(base), interactive_sign=False)
            self.assertIn(expected, str(cm.exception), names)

    def test_path_and_name_rejections(self):
        env = self.env
        base = env.work / "names"
        (base / "a").mkdir(parents=True)
        (base / "b").mkdir()
        (base / "a" / "x.ps1").write_bytes(PS1_BENIGN)
        (base / "b" / "x.ps1").write_bytes(PS1_BENIGN)
        outside = env.work / "outside.ps1"
        outside.write_bytes(PS1_BENIGN)
        with self.assertRaises(T.PrepareError) as cm:  # duplicate logical path (same basename, no --base)
            T.collect_inputs(None, [str(base / "a" / "x.ps1"), str(base / "b" / "x.ps1")], None, env.tkeys,
                             T.DEFAULT_ALLOWED_EXTENSIONS)
        self.assertRegex(str(cm.exception), "duplicate|different directories")
        with self.assertRaises(T.PrepareError):  # ../ traversal out of --base
            T.collect_inputs(None, [str(base / "a" / ".." / ".." / "outside.ps1")], str(base), env.tkeys,
                             T.DEFAULT_ALLOWED_EXTENSIONS)
        with self.assertRaises(T.PrepareError):  # absolute path outside --base
            T.collect_inputs(None, [str(outside)], str(base), env.tkeys, T.DEFAULT_ALLOWED_EXTENSIONS)
        for bad in ("bad\nname.ps1", "CON.txt", "trail.ps1.", "a<b.ps1", "tool.exe", ".hidden.ps1", "café.ps1",
                    "x‮gnp.ps1"):
            self.assertTrue(T.file_problems(bad, T.DEFAULT_ALLOWED_EXTENSIONS), repr(bad))
        # Termux refuses every name the MX airlock refuses for these samples (consistent policy)
        for name in ("ok.ps1", "with space.ps1", "-leading-dash.ps1", "semi;$(x)&.ps1", "café.ps1", "CON.txt"):
            self.assertEqual(bool(T.name_problems(name)), bool(A.check_name_component(name)), repr(name))
        dup = env.work / "casedup"
        dup.mkdir()
        (dup / "Script.ps1").write_bytes(b"1")
        (dup / "script.ps1").write_bytes(b"2")
        with self.assertRaises(T.PrepareError):
            T.collect_inputs(str(dup), None, None, env.tkeys, T.DEFAULT_ALLOWED_EXTENSIONS)

    def test_size_limits_zero_byte_and_large(self):
        env = self.env
        big = env.work / "big"
        big.mkdir()
        (big / "huge.txt").write_bytes(b"A" * (T.MAX_FILE_BYTES + 1))
        with self.assertRaises(T.PrepareError) as cm:
            T.prepare(env.tkeys, env.work / "out_big", source_dir=str(big), interactive_sign=False)
        self.assertIn("larger than", str(cm.exception))
        pkg = env.build({"empty.ps1": b"", "large.txt": LARGE_TEXT}, name="sizes")
        sizes = {f["relative_path"]: f["size"] for f in json.loads((pkg / "manifest.json").read_text())["files"]}
        self.assertEqual(sizes, {"empty.ps1": 0, "large.txt": len(LARGE_TEXT)})

    def test_key_handling(self):
        env = self.env
        with self.assertRaises(T.PrepareError):  # never overwrites an existing signing key
            T.cmd_init_keys(T.build_parser().parse_args(["--keys-dir", str(env.tkeys), "init-keys", "--no-password"]))
        self.assertEqual(stat.S_IMODE((env.tkeys / T.KEY_SECRET).stat().st_mode), 0o600)
        other = A.KeyStore(env.mxkeys).recipient().replace("age1", "age1", 1)
        self.assertEqual(other, env.recipient)
        with self.assertRaises(T.PrepareError):  # recipient replacement needs --replace
            T.cmd_set_recipient(T.build_parser().parse_args(
                ["--keys-dir", str(env.tkeys), "set-recipient", "age1" + "q" * 58]))
        with self.assertRaises(T.PrepareError):  # keys must never be packaged
            T.prepare(env.tkeys, env.work / "o1", source_dir=str(env.tkeys), interactive_sign=False)
        src = env.work / "s"
        src.mkdir()
        (src / "a.ps1").write_bytes(PS1_BENIGN)
        with self.assertRaises(T.PrepareError):  # output inside the key directory
            T.prepare(env.tkeys, env.tkeys / "out", source_dir=str(src), interactive_sign=False)
        with self.assertRaises(T.PrepareError):  # broad locations are refused
            T.collect_inputs("/", None, None, env.tkeys, T.DEFAULT_ALLOWED_EXTENSIONS)

    def test_special_names_round_trip_without_shell_interpretation(self):
        env = self.env
        names = {"with space.ps1": b"1\n", "-leading-dash.ps1": b"2\n", "semi;$(touch PWNED)&.ps1": b"3\n",
                 "zero.ps1": b""}
        env.install(env.build(names, name="special"))
        self.assertEqual(env.ingest(), 0, env.h.output())
        self.assertEqual(env.approve(), 0)
        self.assertEqual(env.release(), 0, env.h.output())
        for rel, data in names.items():
            self.assertEqual((env.h.dst / "RECOVERY_TRANSFER" / "FILES" / rel).read_bytes(), data)
        self.assertEqual([p for p in Path("/").glob("PWNED")] + list(Path.cwd().glob("PWNED")), [])


# ---------------------------------------------------------------------------
# Key pinning on MX
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class KeyPinningTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)

    def test_pinning_requires_fingerprint_not_key_id(self):
        env = self.env
        attacker = env.h.tmp / "attacker"
        env.termux(["init-keys", "--no-password"], keys=attacker)
        victim = T.parse_public_key((env.tkeys / T.KEY_PUBLIC).read_bytes())
        blob = bytearray(A.base64.b64decode(T.parse_public_key((attacker / T.KEY_PUBLIC).read_bytes())["b64"]))
        blob[2:10] = A.base64.b64decode(victim["b64"])[2:10]  # copy the victim's key ID into the attacker key
        forged = A.base64.b64encode(bytes(blob)).decode()
        parsed = A.parse_minisign_public_key(forged.encode())
        self.assertEqual(parsed["key_id"], victim["key_id"])
        self.assertNotEqual(parsed["fingerprint"], victim["fingerprint"])
        fresh = V11Env.__new__(V11Env)
        fresh.tc, fresh.h, fresh.mxkeys = self, env.h, env.h.tmp / "mx_keys_fresh"
        # operator types the fingerprint shown on Termux (the victim's): the forged key is refused
        rc = fresh.mx(["trust-signing-key", "--public-key-string", forged],
                      [("Type", A.fingerprint_confirmation(victim["fingerprint"]))])
        self.assertEqual(rc, 2)
        self.assertFalse((env.h.tmp / "mx_keys_fresh" / A.KeyStore.SIGNING_PUB).exists())

    def test_replacement_is_explicit_and_old_key_retired(self):
        env = self.env
        other = env.h.tmp / "other"
        env.termux(["init-keys", "--no-password"], keys=other)
        fp = T.parse_public_key((other / T.KEY_PUBLIC).read_bytes())["fingerprint"]
        self.assertEqual(env.mx(["trust-signing-key", "--public-key", str(other / T.KEY_PUBLIC)],
                                [("Type", A.fingerprint_confirmation(fp))]), 1)
        self.assertIn("SIGNING_KEY_ALREADY_PINNED", env.h.output())
        key_id = T.parse_public_key((other / T.KEY_PUBLIC).read_bytes())["key_id"]
        rules = [("Type REPLACE SIGNING KEY", "REPLACE SIGNING KEY %s" % key_id), ("Type", A.fingerprint_confirmation(fp))]
        self.assertEqual(env.mx(["trust-signing-key", "--replace", "--public-key", str(other / T.KEY_PUBLIC)], rules), 0,
                         env.h.output())
        self.assertEqual(A.KeyStore(env.mxkeys).signing_key()["fingerprint"], fp)
        self.assertTrue(list(env.mxkeys.glob("retired-*-trusted_signing_key.pub")))

    def test_transport_identity_private_and_never_overwritten(self):
        env = self.env
        ident = env.mxkeys / A.KeyStore.IDENTITY
        self.assertEqual(stat.S_IMODE(ident.stat().st_mode), 0o600)
        before = ident.read_bytes()
        self.assertEqual(env.mx(["init-transport-key"]), 0)
        self.assertEqual(ident.read_bytes(), before)
        self.assertIn(env.recipient, env.h.output())
        self.assertNotIn("AGE-SECRET-KEY", env.h.output())
        for log in (env.h.state / "logs").glob("*.log"):
            self.assertNotIn("AGE-SECRET-KEY", log.read_text())

    def test_ingest_requires_keys_before_touching_devices(self):
        env = self.env
        env.install(env.build())
        env.h.insert_source()
        rc = env.h.run(["--keys-dir", str(env.h.tmp / "empty_keys"), "ingest"], env.h.ingest_rules())
        self.assertEqual(rc, 1)
        self.assertIn("NO_TRUSTED_SIGNING_KEY", env.h.output())
        self.assertEqual(env.h.mount_calls(), [])

    def test_keys_on_the_transport_usb_refused(self):
        env = self.env
        env.install(env.build())
        shutil.copytree(str(env.mxkeys), str(env.h.src / "keys"))
        os.chmod(str(env.h.src / "keys"), 0o700)
        env.h.insert_source()
        rc = env.h.run(["--keys-dir", str(env.h.src / "keys"), "ingest"], env.h.ingest_rules())
        self.assertEqual(rc, 1)
        self.assertIn("KEYS_ON_REMOVABLE_MEDIA", env.h.output())


# ---------------------------------------------------------------------------
# Authenticated ingest and release
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class AuthenticatedTransferTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)

    def test_end_to_end_valid_transfer(self):
        env, h = self.env, self.env.h
        files = {"WIN11_STANDALONE_LOCKDOWN_V3.ps1": PS1_BENIGN, "docs/notes.md": b"# notes\n", "big.txt": LARGE_TEXT}
        pkg = env.build(files)
        env.install(pkg)
        self.assertEqual(env.ingest(), 0, h.output())
        self.assertEqual(env.gates(), list(A.AUTH_GATES[:7]))
        qdir = env.qdir()
        self.assertEqual(stat.S_IMODE(qdir.stat().st_mode), 0o500)
        # ciphertext is never staged; plaintext only as sealed opaque files
        self.assertEqual(sorted(p.name for p in qdir.iterdir()),
                         ["f000001.dat", "f000002.dat", "f000003.dat", "pkg_manifest.json", "pkg_manifest.minisig"])
        self.assertEqual(env.approve(), 0, h.output())
        self.assertEqual(env.release(), 0, h.output())
        self.assertEqual(env.gates(), list(A.AUTH_GATES))
        s = h.session()
        self.assertEqual(s["phase"], A.PHASE_RELEASED)
        tdir = h.dst / "RECOVERY_TRANSFER"
        for rel, data in files.items():
            self.assertEqual((tdir / "FILES" / rel).read_bytes(), data)
        orig = tdir / "ORIGINAL_SIGNED_MANIFEST"
        self.assertEqual((orig / "manifest.json").read_bytes(), (pkg / "manifest.json").read_bytes())
        self.assertEqual((orig / "manifest.minisig").read_bytes(), (pkg / "manifest.minisig").read_bytes())
        res = subprocess.run([A.find_tool("minisign"), "-V", "-p", str(env.tkeys / T.KEY_PUBLIC), "-m",
                              str(orig / "manifest.json"), "-x", str(orig / "manifest.minisig")], capture_output=True)
        self.assertEqual(res.returncode, 0)
        forward = json.loads((tdir / "MANIFEST" / "manifest.json").read_text())
        self.assertEqual(forward["kind"], "MX_FORWARD_INTEGRITY_MANIFEST")
        self.assertEqual(forward["original_signed_manifest"]["sha256"], A.sha256_hex((pkg / "manifest.json").read_bytes()))
        all_dest = [str(p.relative_to(h.dst)) for p in h.dst.rglob("*")]
        self.assertFalse(any(p.endswith(".age") or "TRANSFER_ID" in p for p in all_dest))
        self.assertEqual(env.mx(["verify-clean"], [("Insert ONLY the CLEAN USB", ""), ("Type YES", "YES")]), 0, h.output())
        self.assertIn("forwarded signed manifest checked with the pinned signing key", h.output())
        log = "".join(p.read_text() for p in (h.state / "logs").glob("*.log"))
        for needle in ('"result": "PASS"', s["authenticated"]["transfer_id"], env.fingerprint, "encrypted_payload_hash",
                       "decryption", "destination_whole_fs_verification"):
            self.assertIn(needle, log)
        self.assertNotIn("AGE-SECRET-KEY", log)
        self.assertNotIn("Set-StrictMode", log)

    def _tamper(self, mutate, code, gates=None):
        env = self.env
        pkg = env.build()
        mutate(pkg)
        env.install(pkg)
        self.assertEqual(env.ingest(), 1)
        env.assert_blocked(code, gates)

    def test_modified_manifest(self):
        def mutate(pkg):
            raw = (pkg / "manifest.json").read_bytes()
            (pkg / "manifest.json").write_bytes(raw.replace(b'"file_count": 2', b'"file_count": 3'))
        self._tamper(mutate, "SIGNATURE_INVALID", [A.GATE_INCOMING_QUARANTINED])

    def test_modified_signature(self):
        def mutate(pkg):
            lines = (pkg / "manifest.minisig").read_text().split("\n")
            sig = bytearray(A.base64.b64decode(lines[1]))
            sig[-1] ^= 1
            lines[1] = A.base64.b64encode(bytes(sig)).decode()
            (pkg / "manifest.minisig").write_text("\n".join(lines))
        self._tamper(mutate, "SIGNATURE_INVALID", [A.GATE_INCOMING_QUARANTINED])

    def test_malformed_signature_file(self):
        self._tamper(lambda pkg: (pkg / "manifest.minisig").write_text("not a signature\n"), "SIGNATURE_MALFORMED")

    def test_wrong_public_key(self):
        env = self.env
        other = env.h.tmp / "other_signer"
        env.termux(["init-keys", "--no-password"], keys=other)
        env.termux(["set-recipient", env.recipient], keys=other)
        env.install(env.build(name="other", keys=other))
        self.assertEqual(env.ingest(), 1)
        env.assert_blocked("WRONG_SIGNING_KEY", [A.GATE_INCOMING_QUARANTINED])

    def test_modified_encrypted_payload(self):
        def mutate(pkg):
            data = bytearray((pkg / "payload.age").read_bytes())
            data[-5] ^= 0xFF
            (pkg / "payload.age").write_bytes(bytes(data))
        self._tamper(mutate, "ENCRYPTED_PAYLOAD_MISMATCH", [A.GATE_INCOMING_QUARANTINED, A.GATE_SIGNED_MANIFEST_VERIFIED])

    def test_manifest_payload_hash_changed_and_resigned(self):
        env = self.env
        self._tamper(lambda pkg: env.rewrite_manifest(pkg, lambda m: m["payload"].update(sha256="0" * 64)),
                     "ENCRYPTED_PAYLOAD_MISMATCH", [A.GATE_INCOMING_QUARANTINED, A.GATE_SIGNED_MANIFEST_VERIFIED])

    def test_signed_comment_must_bind_the_manifest(self):
        env = self.env

        def mutate(pkg):
            env.rewrite_manifest(pkg, lambda m: m["files"][0].update(sha256="1" * 64), resign=False)
            env.sign(pkg, comment=T.signed_comment("20260101T000000Z-deadbeef", "2" * 64))
        self._tamper(mutate, "SIGNATURE_BINDING_MISMATCH")

    def test_payload_swapped_between_transfers(self):
        env = self.env
        other = env.build({"other.ps1": b"Write-Host other\n"}, name="second")

        def mutate(pkg):
            shutil.copyfile(str(other / "payload.age"), str(pkg / "payload.age"))
        self._tamper(mutate, "ENCRYPTED_PAYLOAD_MISMATCH")

    def test_transfer_id_mismatch(self):
        self._tamper(lambda pkg: (pkg / "TRANSFER_ID").write_text("20990101T000000Z-00000000\n"), "TRANSFER_ID_MISMATCH")

    def test_duplicate_manifest_entries(self):
        env = self.env
        self._tamper(lambda pkg: env.rewrite_manifest(pkg, lambda m: m.update(files=m["files"] + m["files"][:1],
                                                                              file_count=3)),
                     "MANIFEST_DUPLICATE_PATH")

    def test_duplicate_json_keys(self):
        env = self.env

        def mutate(pkg):
            raw = (pkg / "manifest.json").read_bytes()
            (pkg / "manifest.json").write_bytes(raw.replace(b'"file_count": 2,', b'"file_count": 2, "file_count": 2,'))
            env.sign(pkg)
        self._tamper(mutate, "MANIFEST_MALFORMED")

    def test_malformed_manifest(self):
        env = self.env

        def mutate(pkg):
            (pkg / "manifest.json").write_bytes(b"{not json")
            env.sign(pkg, comment=T.signed_comment("x" * 8, A.sha256_hex(b"{not json")))
        self._tamper(mutate, "MANIFEST_MALFORMED")

    def test_manifest_path_traversal_and_absolute_paths(self):
        env = self.env
        for index, bad in enumerate(("../escape.ps1", "/etc/evil.ps1", "a/./b.ps1", "nul\x00.ps1")):
            with self.subTest(bad=bad):
                with self.assertRaises(A.BlockingError):
                    pkg = env.build(name="trav%d" % index)
                    env.rewrite_manifest(pkg, lambda m: m["files"][0].update(relative_path=bad), resign=False)
                    A.validate_signed_manifest((pkg / "manifest.json").read_bytes(), A.load_config(None))

    def test_oversized_manifest(self):
        env = self.env
        self._tamper(lambda pkg: env.rewrite_manifest(pkg, lambda m: (json.dumps(m) + " " * (1024 * 1024)).encode()),
                     "PACKAGE_STRUCTURE_INVALID")

    def test_unknown_format_version(self):
        env = self.env
        self._tamper(lambda pkg: env.rewrite_manifest(pkg, lambda m: m.update(format_version=2)),
                     "MANIFEST_UNSUPPORTED_VERSION")

    def test_payload_valid_but_decrypted_files_incorrect(self):
        env = self.env
        self._tamper(lambda pkg: env.rewrite_manifest(pkg, lambda m: m["files"][0].update(sha256="3" * 64)),
                     "DECRYPTED_FILE_MISMATCH",
                     [A.GATE_INCOMING_QUARANTINED, A.GATE_SIGNED_MANIFEST_VERIFIED, A.GATE_ENCRYPTED_PAYLOAD_VERIFIED,
                      A.GATE_PAYLOAD_DECRYPTED])

    def test_signed_file_failing_content_policy_stops_whole_set(self):
        env = self.env
        # Termux refuses NUL-containing files itself; an MZ-header text file passes Termux but not MX.
        pkg = env.build({"readme.txt": b"MZ this text starts like a DOS executable\n", "ok.ps1": PS1_BENIGN}, name="mz")
        env.install(pkg)
        self.assertEqual(env.ingest(), 1)
        env.assert_blocked("SIGNED_FILE_POLICY_VIOLATION")

    def test_package_structure(self):
        env = self.env
        self._tamper(lambda pkg: (pkg / "run_me.sh").write_text("echo hi\n"), "PACKAGE_STRUCTURE_INVALID")

    def test_symlinked_package_member(self):
        env = self.env

        def mutate(pkg):
            target = env.work / "elsewhere.json"
            shutil.move(str(pkg / "manifest.json"), str(target))
            os.symlink(str(target), str(pkg / "manifest.json"))
        self._tamper(mutate, "PACKAGE_STRUCTURE_INVALID")

    def test_no_package_and_no_silent_downgrade(self):
        env, h = self.env, self.env.h
        h.put("loose.ps1", PS1_BENIGN)
        self.assertEqual(env.ingest(), 1)
        self.assertIn("NO_AUTHENTICATED_PACKAGE", h.output())
        self.assertIn("--legacy", h.output())
        env.install(env.build())
        h.remove("sdb")
        h.insert_source()
        self.assertEqual(env.mx(["ingest", "--legacy", "--new-session"], h.ingest_rules()), 1)
        self.assertIn("AUTHENTICATED_PACKAGE_IN_LEGACY_MODE", h.output())
        self.assertEqual(env.mx(["ingest", "--trusted-hashes", str(h.tmp / "x.txt")]), 3)

    def test_release_requires_complete_set_and_reverifies_staging(self):
        env, h = self.env, self.env.h
        env.install(env.build())
        self.assertEqual(env.ingest(), 0, h.output())
        self.assertEqual(env.approve(), 0)
        s = h.session()
        s["files"][0]["approved"] = False
        A.StateStore(h.state).save_session(s)
        self.assertEqual(env.release(), 1)
        self.assertIn("SIGNED_SET_INCOMPLETE", h.output())
        self.assertEqual(env.approve(), 0)

        def tamper(be, event):  # staging modified after review, before export
            if event == "await_destination_insertion":
                q = env.qdir()
                os.chmod(str(q), 0o700)
                os.chmod(str(q / "pkg_manifest.json"), 0o600)
                (q / "pkg_manifest.json").write_bytes(b"{}")
        h.backend.auto = tamper
        self.assertEqual(env.release(), 1)
        self.assertIn("QUARANTINE_TAMPERED", h.output())
        self.assertNotIn(A.GATE_EXPORTED, env.gates())
        self.assertEqual(h.dest_files(), [])

    def test_signing_key_change_between_ingest_and_release(self):
        env, h = self.env, self.env.h
        env.install(env.build())
        self.assertEqual(env.ingest(), 0, h.output())
        self.assertEqual(env.approve(), 0)
        other = h.tmp / "rotated"
        env.termux(["init-keys", "--no-password"], keys=other)
        pub = T.parse_public_key((other / T.KEY_PUBLIC).read_bytes())
        rules = [("Type REPLACE", "REPLACE SIGNING KEY %s" % pub["key_id"]), ("Type", A.fingerprint_confirmation(pub["fingerprint"]))]
        self.assertEqual(env.mx(["trust-signing-key", "--replace", "--public-key", str(other / T.KEY_PUBLIC)], rules), 0)
        self.assertEqual(env.release(), 1)
        self.assertIn("SIGNING_KEY_CHANGED", h.output())
        self.assertEqual(h.dest_files(), [])


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)

    def _expect(self, mutate, code, files=None):
        env = self.env
        pkg = env.build(files)
        mutate(pkg)
        env.install(pkg)
        self.assertEqual(env.ingest(), 1)
        env.assert_blocked(code)
        marker = b"Applying settings"
        for path in env.h.state.rglob("*"):
            if path.is_file():
                self.assertNotIn(marker, path.read_bytes(), "plaintext left behind in %s" % path)

    def test_wrong_identity(self):
        env = self.env
        rules = [("Type REPLACE TRANSPORT KEY", "REPLACE TRANSPORT KEY")]
        self.assertEqual(env.mx(["init-transport-key", "--replace"], rules), 0)
        self._expect(lambda pkg: None, "DECRYPTION_FAILED")

    def test_truncated_ciphertext(self):
        env = self.env
        self._expect(lambda pkg: env.set_payload(pkg, (pkg / "payload.age").read_bytes()[:-40]), "DECRYPTION_FAILED")

    def test_modified_ciphertext(self):
        env = self.env

        def mutate(pkg):
            data = bytearray((pkg / "payload.age").read_bytes())
            data[len(data) // 2] ^= 0x01
            env.set_payload(pkg, bytes(data))
        self._expect(mutate, "DECRYPTION_FAILED")

    def test_partial_decrypt_failure_after_first_chunk(self):
        env = self.env

        def mutate(pkg):
            data = bytearray((pkg / "payload.age").read_bytes())
            data[-3] ^= 0x01  # last STREAM chunk: earlier chunks already decrypted
            env.set_payload(pkg, bytes(data))
        self._expect(mutate, "DECRYPTION_FAILED", {"big.txt": LARGE_TEXT, "a.ps1": PS1_BENIGN})

    def test_empty_ciphertext(self):
        env = self.env
        self._expect(lambda pkg: (pkg / "payload.age").write_bytes(b""), "PACKAGE_STRUCTURE_INVALID")

    def test_unexpected_plaintext_output(self):
        env = self.env
        cases = [
            ("not a tar", b"plain text, not a container" * 40, "PAYLOAD_CONTAINER_INVALID"),
            ("extra member", tar_bytes([("WIN11_STANDALONE_LOCKDOWN_V3.ps1", PS1_BENIGN, tarfile.REGTYPE),
                                        ("docs/notes.md", b"# notes\n", tarfile.REGTYPE),
                                        ("extra.ps1", b"x", tarfile.REGTYPE)]), "PAYLOAD_UNEXPECTED_MEMBER"),
            ("symlink member", tar_bytes([("WIN11_STANDALONE_LOCKDOWN_V3.ps1", b"", tarfile.SYMTYPE)]), "PAYLOAD_UNSAFE_MEMBER"),
            ("hardlink member", tar_bytes([("WIN11_STANDALONE_LOCKDOWN_V3.ps1", b"", tarfile.LNKTYPE)]), "PAYLOAD_UNSAFE_MEMBER"),
            ("directory member", tar_bytes([("docs", b"", tarfile.DIRTYPE)]), "PAYLOAD_UNSAFE_MEMBER"),
            ("fifo member", tar_bytes([("docs/notes.md", b"", tarfile.FIFOTYPE)]), "PAYLOAD_UNSAFE_MEMBER"),
            ("device member", tar_bytes([("docs/notes.md", b"", tarfile.CHRTYPE)]), "PAYLOAD_UNSAFE_MEMBER"),
            ("absolute member", tar_bytes([("/etc/x.ps1", b"x", tarfile.REGTYPE)]), "ABSOLUTE_PATH"),
            ("traversal member", tar_bytes([("../x.ps1", b"x", tarfile.REGTYPE)]), "PATH_TRAVERSAL"),
            ("missing member", tar_bytes([("WIN11_STANDALONE_LOCKDOWN_V3.ps1", PS1_BENIGN, tarfile.REGTYPE)]),
             "DECRYPTED_FILE_MISMATCH"),
        ]
        manifest = json.loads(env.build(name="ref").joinpath("manifest.json").read_text())
        for label, plaintext, code in cases:
            with self.subTest(label=label):
                with self.assertRaises(A.BlockingError) as cm:
                    A.extract_verified_payload(plaintext, manifest)
                self.assertEqual(cm.exception.code, code)
        # and through the full pipeline (re-signed so every earlier gate passes)
        self._expect(lambda pkg: env.set_payload(pkg, env.encrypt(cases[2][1])), "PAYLOAD_UNSAFE_MEMBER")


# ---------------------------------------------------------------------------
# Whole-destination verification
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class WholeDestinationTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)
        self.env.install(self.env.build())
        self.assertEqual(self.env.ingest(), 0, self.env.h.output())
        self.assertEqual(self.env.approve(), 0)

    def test_preexisting_content_stops_before_writing(self):
        env, h = self.env, self.env.h
        planted = {"root.txt": "file", "autorun.inf": "file", "tool.exe": "file", ".hidden": "file",
                   "somedir": "dir", "System Volume Information": "dir"}
        for name, kind in planted.items():
            for other in list(h.dst.iterdir()):
                shutil.rmtree(str(other)) if other.is_dir() else other.unlink()
            (h.dst / name).mkdir() if kind == "dir" else (h.dst / name).write_text("x")
            with self.subTest(name=name):
                h.remove("sdc") if "sdc" in h.backend.devices else None
                self.assertEqual(env.release(), 1)
                self.assertIn("DESTINATION_NOT_CLEAN", h.output())
                self.assertEqual(sorted(p.name for p in h.dst.iterdir()), [name])
                self.assertNotIn(A.GATE_DESTINATION_CLEAN, env.gates())

    def _contaminate(self, action, code):
        env, h = self.env, self.env.h

        def hook(be, event):
            if event == "after_destination_write":
                action(h.dst, h.dst / "RECOVERY_TRANSFER")
        h.backend.auto = hook
        self.assertEqual(env.release(), 1)
        self.assertIn(code, h.output())
        self.assertNotEqual(h.session()["phase"], A.PHASE_RELEASED)
        self.assertNotIn(A.GATE_DESTINATION_WHOLE_FS_VERIFIED, env.gates())
        self.assertNotIn(A.GATE_COMPLETE, env.gates())
        self.assertIn(A.GATE_EXPORTED, env.gates())

    def test_unexpected_file_outside_transfer_dir(self):
        self._contaminate(lambda root, t: (root / "payload.lnk").write_text("x"), "DESTINATION_CONTAMINATION")

    def test_unexpected_file_inside_transfer_dir(self):
        self._contaminate(lambda root, t: (t / "FILES" / "extra.ps1").write_text("x"), "DESTINATION_CONTAMINATION")

    def test_unexpected_hidden_file_and_directory(self):
        self._contaminate(lambda root, t: ((root / ".Trash-1000").mkdir(), (t / ".x.desktop").write_text("x")),
                          "DESTINATION_CONTAMINATION")

    def test_autorun_and_executable(self):
        self._contaminate(lambda root, t: ((root / "autorun.inf").write_text("[autorun]"),
                                           (root / "setup.exe").write_bytes(pe_bytes())), "DESTINATION_CONTAMINATION")

    def test_file_modified_after_export(self):
        self._contaminate(lambda root, t: (t / "FILES" / "WIN11_STANDALONE_LOCKDOWN_V3.ps1").write_text("changed"),
                          "DESTINATION_VERIFICATION_MISMATCH")

    def test_expected_file_removed(self):
        self._contaminate(lambda root, t: (t / "ORIGINAL_SIGNED_MANIFEST" / "manifest.minisig").unlink(),
                          "DESTINATION_VERIFICATION_MISMATCH")

    def test_file_added_after_release_found_by_verify_clean(self):
        env, h = self.env, self.env.h
        self.assertEqual(env.release(), 0, h.output())
        (h.dst / "late_addition.ps1").write_text("x")
        rules = [("Insert ONLY the CLEAN USB", ""), ("Type YES", "YES")]
        self.assertEqual(env.mx(["verify-clean"], rules), 1)
        self.assertIn("DESTINATION_CONTAMINATION: UNEXPECTED FILE late_addition.ps1", h.output())
        (h.dst / "late_addition.ps1").unlink()
        orig = h.dst / "RECOVERY_TRANSFER" / "ORIGINAL_SIGNED_MANIFEST" / "manifest.json"
        orig.write_bytes(orig.read_bytes().replace(b'"file_count": 2', b'"file_count": 9'))
        self.assertEqual(env.mx(["verify-clean"], rules), 1)
        self.assertIn("ORIGINAL SIGNED MANIFEST: SIGNATURE_INVALID", h.output())

    def test_verify_clean_without_session_accounts_only_for_listed_files(self):
        env, h = self.env, self.env.h
        self.assertEqual(env.release(), 0, h.output())
        (h.dst / "RECOVERY_TRANSFER" / "REPORTS" / "extra-note.txt").write_text("x")
        A.StateStore(h.state).archive_session(h.session())  # no local session any more
        rules = [("Insert ONLY the CLEAN USB", ""), ("Type YES", "YES")]
        self.assertEqual(env.mx(["verify-clean"], rules), 1)
        self.assertIn("DESTINATION_CONTAMINATION: UNEXPECTED FILE RECOVERY_TRANSFER/REPORTS/extra-note.txt", h.output())

    def test_metadata_allowlist_is_narrow_and_documented(self):
        self.assertEqual(A.DEST_METADATA_ALLOWLIST, {"vfat": frozenset(), "exfat": frozenset()})
        inv = A.WholeFsInventory(files={"T/FILES/a.ps1": "h", "System Volume Information/WPSettings.dat": None},
                                 dirs={"T", "T/FILES", "System Volume Information"})
        contamination, _ = A.destination_findings(inv, {"T/FILES/a.ps1": "h"}, "vfat")
        self.assertEqual(len(contamination), 2)
        allow = {"vfat": frozenset({"System Volume Information", "System Volume Information/WPSettings.dat"})}
        with unittest.mock.patch.object(A, "DEST_METADATA_ALLOWLIST", allow):
            contamination, _ = A.destination_findings(inv, {"T/FILES/a.ps1": "h"}, "vfat")
        self.assertEqual(contamination, [])  # the mechanism is exact-path only


# ---------------------------------------------------------------------------
# Read-only enforcement (authenticated ingest)
# ---------------------------------------------------------------------------

@unittest.skipUnless(TOOLS, "minisign/age not installed")
class ReadOnlyTests(unittest.TestCase):
    def setUp(self):
        self.env = V11Env(self)
        self.env.install(self.env.build())

    def _expect(self, code):
        env = self.env
        self.assertEqual(env.ingest(), 1)
        self.assertIn(code, env.h.output())
        self.assertNotIn("sdb1", env.h.backend.mounted)
        self.assertNotIn(A.GATE_INCOMING_QUARANTINED, env.gates())
        self.assertFalse(any("PROCEED" in p for p in env.h.responder.prompts))

    def test_block_readonly_set_and_verified(self):
        env = self.env
        self.assertEqual(env.ingest(), 0, env.h.output())
        self.assertIn("sdb", env.h.backend.readonly)
        self.assertIn("BLOCK DEVICE SET READ-ONLY", env.h.output())

    def test_block_readonly_verification_fails(self):
        self.env.h.backend.readonly_supported = False
        self._expect("BLOCK_READONLY_FAILED")

    def test_mount_not_read_only(self):
        self.env.h.backend.mount_ignores_ro = True
        self._expect("MOUNT_OPTIONS_NOT_ENFORCED")

    def test_expected_mount_flag_missing(self):
        for flag in ("noexec", "nodev", "nosuid"):
            with self.subTest(flag=flag):
                env = V11Env(self)
                env.install(env.build())
                env.h.backend.mount_drops_option = flag
                self.assertEqual(env.ingest(), 1)
                self.assertIn("MOUNT_OPTIONS_NOT_ENFORCED", env.h.output())

    def test_device_becomes_writable_during_read(self):
        def hook(be, event):
            if event == "scan_entry":
                be.readonly.discard("sdb")
        self.env.h.backend.auto = hook
        self._expect("BLOCK_READONLY_LOST")

    def test_block_device_disappears(self):
        def hook(be, event):
            if event == "scan_entry":
                be.remove_device("sdb")
        self.env.h.backend.auto = hook
        self.assertEqual(self.env.ingest(), 1)
        self.assertRegex(self.env.h.output(), "FILESYSTEM_DISAPPEARED|DEVICE_DISAPPEARED|BLOCK_READONLY_LOST")

    def test_identity_changes(self):
        def hook(be, event):
            if event == "scan_entry":
                be.devices["sdb"]["disk"].serial = "SWAPPED"
        self.env.h.backend.auto = hook
        self._expect("IDENTITY_CHANGED")

    def test_real_backend_requires_kernel_superblock_ro(self):
        part = A.Partition(kname="sdb1", maj_min="8:17")
        entry = A.MountEntry("/x", "8:17", "vfat", "/dev/sdb1", frozenset({"ro", "nodev", "nosuid", "noexec"}),
                             frozenset({"rw"}))
        backend = A.LinuxBackend(A.CommandRunner())
        with unittest.mock.patch.object(A, "read_mountinfo", lambda: [entry]), \
                unittest.mock.patch.object(A.os.path, "realpath", lambda p: "/x"):
            with self.assertRaises(A.BlockingError) as cm:
                backend.verify_mount(part, Path("/x"), expect_ro=True)
        self.assertIn("superblock", str(cm.exception))


# ---------------------------------------------------------------------------
# Gate state machine and migration
# ---------------------------------------------------------------------------

class GateStateMachineTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness(self)
        self.store = A.StateStore(self.h.state)
        self.store.ensure()
        self.ctx = A.Context(None, self.h.backend, A.load_config(None), self.store, None)

    def test_gates_cannot_be_skipped_or_reordered(self):
        session = {"schema": 2, "run_id": "20260101T000000Z-00000000", "mode": A.MODE_AUTHENTICATED, "gates": []}
        with self.assertRaises(A.BlockingError) as cm:
            A.pass_gate(self.ctx, session, A.GATE_PAYLOAD_DECRYPTED)  # decrypt before signature
        self.assertEqual(cm.exception.code, "ILLEGAL_TRANSITION")
        for gate in A.AUTH_GATES[:9]:
            A.pass_gate(self.ctx, session, gate)
        with self.assertRaises(A.BlockingError):
            A.pass_gate(self.ctx, session, A.GATE_COMPLETE)  # COMPLETE before whole-filesystem verification
        with self.assertRaises(A.BlockingError):
            A.pass_gate(self.ctx, session, A.GATE_PRE_EXPORT_REVERIFIED)  # repeat
        A.reset_release_gates(session)
        self.assertEqual(A.gates_passed(session), list(A.AUTH_GATES[:7]))
        legacy = {"schema": 2, "run_id": session["run_id"], "mode": A.MODE_LEGACY, "gates": []}
        with self.assertRaises(A.BlockingError):
            A.pass_gate(self.ctx, legacy, A.GATE_SIGNED_MANIFEST_VERIFIED)

    def test_release_refuses_without_removal_gate(self):
        h = self.h
        h.put("a.ps1", PS1_BENIGN)
        self.assertEqual(h.ingest(), 0, h.output())
        h.approve_all()
        s = h.session()
        s["gates"] = [g for g in s["gates"] if g["gate"] != A.GATE_INCOMING_REMOVED]
        self.store.save_session(s)
        self.assertEqual(h.release(), 1)
        self.assertIn("ILLEGAL_TRANSITION", h.output())
        self.assertEqual(h.dest_files(), [])

    def test_v1_0_session_migration(self):
        h = self.h
        old = {"schema": 1, "run_id": "20250101T000000Z-0000abcd", "phase": A.PHASE_SOURCE_REMOVED, "files": [],
               "rejected": [], "simulated": True, "warnings": [], "blocking": []}
        self.store.save_session(old)
        self.assertEqual(h.run(["review"]), 1)
        self.assertIn("SESSION_FROM_V1_0", h.output())
        self.assertEqual(h.run(["report"]), 0, h.output())
        h.put("a.ps1", PS1_BENIGN)
        h.insert_source()
        self.assertEqual(h.run(["ingest", "--legacy", "--new-session"], h.ingest_rules()), 0, h.output())
        self.assertTrue((h.state / "archive" / ("%s.json" % old["run_id"])).exists())

    def test_old_config_still_loads(self):
        cfg = self.h.tmp / "v10.json"
        cfg.write_text(json.dumps({"max_files": 50, "require_trusted_hashes": False}))
        self.assertEqual(A.load_config(str(cfg))["max_transfer_payload_bytes"], 64 * 1024 * 1024)


class V11SourceHygieneTests(unittest.TestCase):
    def test_no_bypass_options_and_no_backticks(self):
        files = [ROOT / "airlock.py", ROOT / "termux" / "usb_airlock_prepare.py", Path(__file__)]
        for path in files:
            text = path.read_text()
            self.assertNotIn(chr(0x60), text, str(path))
            self.assertNotIn("shell" + "=True", text, str(path))
        parser_text = (ROOT / "airlock.py").read_text()
        for forbidden in ("--ignore-signature", "--skip-authentication", "--trust-any-key", "--ignore-hash",
                          "--force-success", "PROCEED"):
            self.assertNotIn(forbidden, parser_text)


if __name__ == "__main__":
    unittest.main()
