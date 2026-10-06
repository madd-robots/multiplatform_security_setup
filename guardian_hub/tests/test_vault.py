# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 4 integrity vault tests: custody, package format, read-back, verified release.

Manifests are authenticated here with a test-only HMAC signer/verifier. The
production YubiKey signer and verifier arrive in Stage 5. Until then nothing
in production can verify, and therefore nothing can be released.
"""

import hashlib
import hmac
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.common import errors as E  # noqa: E402
from usbguardian.vault import package as P  # noqa: E402
from usbguardian.vault.custody import CustodyStore  # noqa: E402
from usbguardian.vault.release import plan_names, release_package  # noqa: E402

OWNER_KEY = b"owner-key-material-for-tests-only"


class HmacSigner:
    scheme = "test-hmac-sha256"

    def __init__(self, key=OWNER_KEY, key_id="owner-a"):
        self.key = key
        self.key_id = key_id

    def sign(self, digest):
        assert len(digest) == 32
        return hmac.new(self.key, digest, hashlib.sha256).digest()


class HmacVerifier:
    def __init__(self, keys=None):
        self.keys = keys if keys is not None else {"owner-a": OWNER_KEY}

    def verify(self, scheme, key_id, digest, signature):
        key = self.keys.get(key_id)
        if scheme != HmacSigner.scheme or key is None:
            raise E.IntegrityError("unknown key")
        if not hmac.compare_digest(hmac.new(key, digest, hashlib.sha256).digest(), signature):
            raise E.IntegrityError("bad signature")


# Payloads Guardian must carry byte for byte: no newline, BOM, encoding or
# "sanitizing" changes, even for content that looks malicious.
PAYLOADS = {
    "crlf.txt": b"line one\r\nline two\r\n",
    "bom.txt": b"\xef\xbb\xbfutf-8 with BOM",
    "binary.bin": bytes(range(256)) * 50,
    "invalid-utf8.txt": b"\xff\xfe\xc3\x28 not valid utf-8",
    "zeros.dat": b"\x00" * 1000,
    "empty.dat": b"",
    "eicar.com.txt": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "pe.exe.bin": b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00",
}


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.store = CustodyStore(self.root / "store")
        self.src = self.root / "src"
        self.src.mkdir()
        self.dest = self.root / "dest"
        self.dest.mkdir(mode=0o700)
        self.pkg = self.root / "transfer.gpkg"

    def tearDown(self):
        self.tmp.cleanup()

    def intake_all(self, payloads=PAYLOADS):
        records = []
        for name, data in payloads.items():
            (self.src / name).write_bytes(data)
            records.append(self.store.intake(self.src / name, name))
        return records

    def write(self, records, signer=None, store=None, path=None):
        signer = signer or HmacSigner()
        manifest = P.build_manifest(records, instance_id="guardian-main", scheme=signer.scheme, key_id=signer.key_id)
        fd = os.open(path or self.pkg, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            return manifest, P.write_package(fd, store or self.store, manifest, signer)
        finally:
            os.close(fd)

    def verify(self, path=None, verifier=None, **kwargs):
        fd = os.open(path or self.pkg, os.O_RDONLY)
        try:
            return P.verify_package(fd, verifier or HmacVerifier(), **kwargs)
        finally:
            os.close(fd)

    def release(self, path=None, verifier=None, **kwargs):
        fd = os.open(path or self.pkg, os.O_RDONLY)
        try:
            return release_package(fd, verifier or HmacVerifier(), self.dest, **kwargs)
        finally:
            os.close(fd)

    def dest_entries(self):
        return sorted(os.listdir(self.dest))


class CustodyTests(VaultCase):
    def test_intake_records_exact_identity(self):
        data = b"payload \r\n\x00\xff"
        (self.src / "a.bin").write_bytes(data)
        rec = self.store.intake(self.src / "a.bin", "a.bin")
        self.assertEqual(rec["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(rec["length"], len(data))
        self.assertEqual(self.store.load_record(rec["record_id"]), rec)
        obj = self.store.object_path(rec["sha256"])
        self.assertEqual(obj.read_bytes(), data)
        self.assertEqual(stat.S_IMODE(os.lstat(obj).st_mode), 0o400)
        for d in ("store", "store/objects", "store/records", "store/tmp"):
            self.assertEqual(stat.S_IMODE(os.lstat(self.root / d).st_mode), 0o700)
        self.assertEqual(os.listdir(self.root / "store" / "tmp"), [])

    def test_startup_sweep_removes_only_partial_intakes(self):
        rec = self.store.intake_bytes(b"accepted", "kept.txt")
        (self.root / "store" / "tmp" / "deadbeef").write_bytes(b"partial copy from a killed broker")
        os.symlink("/etc/passwd", self.root / "store" / "tmp" / "planted")
        self.assertEqual(self.store.sweep_tmp(), {"removed": 2, "bytes": 33})
        self.assertEqual(os.listdir(self.root / "store" / "tmp"), [])
        self.assertTrue(os.path.exists("/etc/passwd"))
        self.store.verify_object(rec["sha256"], rec["length"])  # accepted objects are untouched

    def test_source_changes_after_intake_do_not_matter(self):
        (self.src / "a").write_bytes(b"original")
        rec = self.store.intake(self.src / "a", "a")
        (self.src / "a").write_bytes(b"changed!")
        self.store.verify_object(rec["sha256"], rec["length"])
        self.assertEqual(self.store.object_path(rec["sha256"]).read_bytes(), b"original")

    def test_intake_from_pipe_and_name_recorded_as_data(self):
        r, w = os.pipe()
        os.write(w, b"streamed")
        os.close(w)
        rec = self.store.intake(r, b"\xffbad\nname/../x")
        os.close(r)
        self.assertEqual(rec["source_name"], "invalid-utf8:" + b"\xffbad\nname/../x".hex())
        rec2 = self.store.intake(self.src.joinpath("x").write_bytes(b"") or self.src / "x", "../../etc/passwd")
        self.assertEqual(rec2["source_name"], "../../etc/passwd")  # kept verbatim, only data

    def test_intake_refuses_symlinks_and_special_files(self):
        (self.src / "real").write_bytes(b"x")
        os.symlink(self.src / "real", self.src / "link")
        with self.assertRaises(E.ValidationError):
            self.store.intake(self.src / "link", "link")
        os.mkfifo(self.src / "fifo")
        with self.assertRaises(E.SecurityViolation):
            self.store.intake(self.src / "fifo", "fifo")

    def test_size_limit_leaves_nothing_behind(self):
        (self.src / "big").write_bytes(b"x" * 5000)
        with self.assertRaises(E.ResourceLimitExceeded):
            self.store.intake(self.src / "big", "big", max_bytes=4096)
        self.assertEqual(os.listdir(self.root / "store" / "tmp"), [])

    def test_dedupe_verifies_existing_copy(self):
        (self.src / "a").write_bytes(b"same")
        rec = self.store.intake(self.src / "a", "a")
        rec2 = self.store.intake(self.src / "a", "a-again")
        self.assertEqual(rec["sha256"], rec2["sha256"])
        self.assertNotEqual(rec["record_id"], rec2["record_id"])
        self._tamper_object(rec["sha256"], b"evil")
        with self.assertRaises(E.IntegrityError):
            self.store.intake(self.src / "a", "a-third")

    def _tamper_object(self, sha, data):
        obj = self.store.object_path(sha)
        os.chmod(obj, 0o600)
        obj.write_bytes(data)
        os.chmod(obj, 0o400)

    def test_tampered_record_rejected(self):
        (self.src / "a").write_bytes(b"x")
        rec = self.store.intake(self.src / "a", "a")
        path = self.root / "store" / "records" / (rec["record_id"] + ".json")
        os.chmod(path, 0o600)
        path.write_bytes(path.read_bytes().replace(b'"length":1', b'"length":2'))
        os.chmod(path, 0o400)
        with self.assertRaises(E.IntegrityError):
            self.store.load_record(rec["record_id"])  # record no longer matches the stored object
        with self.assertRaises(E.ValidationError):
            self.store.load_record("../../etc")

    def test_object_permission_drift_rejected(self):
        (self.src / "a").write_bytes(b"x")
        rec = self.store.intake(self.src / "a", "a")
        os.chmod(self.store.object_path(rec["sha256"]), 0o644)
        with self.assertRaises(E.IntegrityError):
            self.store.open_object(rec["sha256"])


class PackageTests(VaultCase):
    def test_round_trip_is_byte_identical(self):
        records = self.intake_all()
        manifest, written = self.write(records)
        report = self.verify()
        self.assertEqual(report["package_sha256"], written["package_sha256"])
        self.assertEqual(report["package_length"], os.path.getsize(self.pkg))
        receipt = self.release()
        self.assertEqual(sorted(r["name"] for r in receipt["released"]), sorted(PAYLOADS))
        for name, data in PAYLOADS.items():
            self.assertEqual((self.dest / name).read_bytes(), data, name)
        self.assertEqual(stat.S_IMODE(os.lstat(self.dest / "crlf.txt").st_mode), 0o600)
        self.assertEqual(self.dest_entries(), sorted(PAYLOADS))  # no staging left

    def test_manifest_binds_identity_and_metadata(self):
        records = self.intake_all({"a.txt": b"abc"})
        manifest, _ = self.write(records)
        obj = manifest["objects"][0]
        self.assertEqual((obj["sha256"], obj["length"]), (hashlib.sha256(b"abc").hexdigest(), 3))
        self.assertEqual(manifest["version"], 1)
        self.assertEqual(manifest["sender"], {"instance_id": "guardian-main", "scheme": "test-hmac-sha256",
                                              "key_id": "owner-a"})
        self.assertEqual(manifest["total_length"], 3)

    def _regions(self):
        data = self.pkg.read_bytes()
        mlen = struct.unpack(">I", data[12:16])[0]
        alen_at = 16 + mlen
        alen = struct.unpack(">I", data[alen_at:alen_at + 4])[0]
        payload_at = alen_at + 4 + alen
        return data, {
            "magic": 0, "version": 9, "manifest": 16 + mlen // 2, "auth_len": alen_at + 1,
            "auth": alen_at + 4 + alen // 2, "payload_first": payload_at, "payload_last": len(data) - 41,
            "trailer_magic": len(data) - 40, "trailer_digest": len(data) - 1,
        }

    def test_any_flipped_byte_fails_and_releases_nothing(self):
        self.intake_all({"a.bin": b"A" * 5000, "b.bin": b"B" * 3000})
        self.write([self.store.load_record(r) for r in self._record_ids()])
        original, regions = self._regions()
        for label, offset in regions.items():
            with self.subTest(label):
                data = bytearray(original)
                data[offset] ^= 0x01
                self.pkg.write_bytes(bytes(data))
                with self.assertRaises(E.GuardianError):
                    self.release()
                self.assertEqual(self.dest_entries(), [])

    def _record_ids(self):
        return sorted(p.stem for p in (self.root / "store" / "records").iterdir())

    def test_attacker_who_recomputes_every_digest_is_rejected(self):
        # The attacker can rewrite the medium: new payload, new digests, new
        # trailer, even a well-formed signature block. Without the owner key
        # the signature cannot verify.
        records = self.intake_all({"report.txt": b"genuine contents"})
        manifest, _ = self.write(records)
        evil_store = CustodyStore(self.root / "evil-store")
        (self.src / "evil").write_bytes(b"tampered contents")
        evil_rec = dict(evil_store.intake(self.src / "evil", "report.txt"))
        forged = P.build_manifest([evil_rec], instance_id="guardian-main", scheme="test-hmac-sha256",
                                  key_id="owner-a", transfer_id=manifest["transfer_id"], created=manifest["created"])
        fd = os.open(self.pkg, os.O_RDWR | os.O_TRUNC)
        try:
            P.write_package(fd, evil_store, forged, HmacSigner(key=b"attacker-key"))
        finally:
            os.close(fd)
        with self.assertRaises(E.IntegrityError) as cm:
            self.release()
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")
        self.assertEqual(self.dest_entries(), [])

    def test_signature_key_must_match_sender(self):
        records = self.intake_all({"a": b"x"})
        self.write(records, signer=HmacSigner(key_id="owner-b"))
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify()  # owner-b is not enrolled in this verifier
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")
        self.verify(verifier=HmacVerifier({"owner-b": OWNER_KEY}))
        # swap only the auth block's key id: no longer matches the signed sender
        original = self.pkg.read_bytes()
        data = original.replace(b'{"key_id":"owner-b","scheme"', b'{"key_id":"owner-a","scheme"')
        self.assertNotEqual(data, original)
        self.pkg.write_bytes(data)
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(verifier=HmacVerifier({"owner-a": OWNER_KEY, "owner-b": OWNER_KEY}))
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")

    def test_non_canonical_manifest_rejected_even_if_signature_matches(self):
        records = self.intake_all({"a": b"x"})
        self.write(records)
        data = self.pkg.read_bytes()
        mlen = struct.unpack(">I", data[12:16])[0]
        manifest = json.loads(data[16:16 + mlen])
        pretty = json.dumps(manifest, indent=1).encode()
        rebuilt = data[:12] + struct.pack(">I", len(pretty)) + pretty + data[16 + mlen:-40]
        rebuilt += b"GUARDEND" + hashlib.sha256(rebuilt).digest()  # attacker can recompute the trailer
        self.pkg.write_bytes(rebuilt)
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify()
        self.assertEqual(cm.exception.code, "PACKAGE_MALFORMED")

    def test_truncated_and_extended_packages(self):
        self.write(self.intake_all({"a": b"A" * 4000}))
        data = self.pkg.read_bytes()
        for cut in (5, 20, len(data) - 41, len(data) - 1):
            with self.subTest(cut=cut):
                self.pkg.write_bytes(data[:cut])
                with self.assertRaises(E.IntegrityError):
                    self.release()
                self.assertEqual(self.dest_entries(), [])
        self.pkg.write_bytes(data + b"extra")
        with self.assertRaises(E.IntegrityError) as cm:
            self.release()
        self.assertEqual(cm.exception.code, "PACKAGE_TRAILING_DATA")
        self.assertEqual(self.dest_entries(), [])

    def test_swapped_equal_length_objects_detected(self):
        self.write(self.intake_all({"a": b"A" * 100, "b": b"B" * 100}))
        data = bytearray(self.pkg.read_bytes())
        end = len(data) - 40
        a, b = bytes(data[end - 200:end - 100]), bytes(data[end - 100:end])
        data[end - 200:end] = b + a
        self.pkg.write_bytes(bytes(data))
        with self.assertRaises(E.IntegrityError) as cm:
            self.release()
        self.assertEqual(cm.exception.code, "PAYLOAD_MISMATCH")

    def test_oversized_header_fields_rejected_before_reading(self):
        self.pkg.write_bytes(struct.pack(">8sHHI", b"GUARDPKG", 1, 0, 0xFFFFFFFF))
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify()
        self.assertEqual(cm.exception.code, "PACKAGE_MALFORMED")
        for prelude in (struct.pack(">8sHHI", b"NOTGUARD", 1, 0, 10), struct.pack(">8sHHI", b"GUARDPKG", 2, 0, 10),
                        struct.pack(">8sHHI", b"GUARDPKG", 1, 1, 10)):
            self.pkg.write_bytes(prelude + b"x" * 20)
            with self.assertRaises(E.IntegrityError):
                self.verify()

    def test_no_verifier_means_no_verification(self):
        self.write(self.intake_all({"a": b"x"}))
        fd = os.open(self.pkg, os.O_RDONLY)
        try:
            with self.assertRaises(E.IntegrityError) as cm:
                P.verify_package(fd, None)
        finally:
            os.close(fd)
        self.assertEqual(cm.exception.code, "PACKAGE_UNAUTHENTICATED")

    def test_store_tampering_aborts_write_without_trailer(self):
        records = self.intake_all({"a": b"A" * 3000})
        obj = self.store.object_path(records[0]["sha256"])
        os.chmod(obj, 0o600)
        obj.write_bytes(b"A" * 2999 + b"Z")
        os.chmod(obj, 0o400)
        with self.assertRaises(E.IntegrityError):
            self.write(records)
        self.assertNotIn(b"GUARDEND", self.pkg.read_bytes())
        with self.assertRaises(E.IntegrityError):
            self.verify()

    def test_signer_must_match_manifest(self):
        records = self.intake_all({"a": b"x"})
        manifest = P.build_manifest(records, instance_id="guardian-main", scheme="test-hmac-sha256", key_id="owner-a")
        fd = os.open(self.pkg, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with self.assertRaises(E.ValidationError):
                P.write_package(fd, self.store, manifest, HmacSigner(key_id="owner-b"))
        finally:
            os.close(fd)

    def test_manifest_validation(self):
        records = self.intake_all({"a": b"x"})
        good = P.build_manifest(records, instance_id="guardian-main", scheme="test-hmac-sha256", key_id="owner-a")
        bad_variants = [dict(good, total_length=5), dict(good, version=2), dict(good, objects=[]),
                        dict(good, extra=True), dict(good, sender=dict(good["sender"], instance_id="Bad Id"))]
        for bad in bad_variants:
            with self.assertRaises(E.ValidationError):
                P._check_manifest(bad)


class ReadbackTests(VaultCase):
    def test_readback_passes_on_intact_medium(self):
        records = self.intake_all({"a": b"A" * 70000, "b": b""})
        signer = HmacSigner()
        manifest = P.build_manifest(records, instance_id="guardian-main", scheme=signer.scheme, key_id=signer.key_id)
        fd = os.open(self.pkg, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            written = P.write_package(fd, self.store, manifest, signer)
            report = P.readback_verify(fd, HmacVerifier(), written)
        finally:
            os.close(fd)
        self.assertEqual(report["package_sha256"], written["package_sha256"])

    def test_readback_detects_medium_corruption(self):
        records = self.intake_all({"a": b"A" * 70000})
        signer = HmacSigner()
        manifest = P.build_manifest(records, instance_id="guardian-main", scheme=signer.scheme, key_id=signer.key_id)
        fd = os.open(self.pkg, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            written = P.write_package(fd, self.store, manifest, signer)
            os.pwrite(fd, b"Z", 40000)  # the medium stores something else
            with self.assertRaises(E.IntegrityError):
                P.readback_verify(fd, HmacVerifier(), written)
        finally:
            os.close(fd)

    def test_readback_detects_a_different_valid_package(self):
        self.write(self.intake_all({"a": b"one"}))
        _, other = self.write(self.intake_all({"b": b"two"}), path=self.root / "other.gpkg")
        fd = os.open(self.pkg, os.O_RDWR)
        try:
            with self.assertRaises(E.IntegrityError) as cm:
                P.readback_verify(fd, HmacVerifier(), other)
        finally:
            os.close(fd)
        self.assertEqual(cm.exception.code, "READBACK_MISMATCH")

    def test_raw_device_layout_package_at_offset(self):
        self.write(self.intake_all({"a": b"payload"}))
        data = self.pkg.read_bytes()
        device = self.root / "device.img"
        device.write_bytes(b"\x00" * 512 + data + os.urandom(4096))
        self.verify(path=device, start=512, require_end=False)
        with self.assertRaises(E.IntegrityError) as cm:
            self.verify(path=device, start=512, require_end=True)
        self.assertEqual(cm.exception.code, "PACKAGE_TRAILING_DATA")


class ReleaseTests(VaultCase):
    def test_strict_policy_refuses_unsafe_names(self):
        for name in ("../escape", "a/b", "CON", "evil‮txt.exe", "-rf", "x\n"):
            with self.subTest(name=name):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                store = CustodyStore(Path(tmp.name) / "s")
                (self.src / "f").write_bytes(b"data")
                rec = store.intake(self.src / "f", name)
                self.write([rec], store=store)
                with self.assertRaises(E.ValidationError) as cm:
                    self.release()
                self.assertEqual(cm.exception.code, "UNSAFE_RELEASE_NAME")
                self.assertEqual(self.dest_entries(), [])

    def test_generate_policy_renames_but_keeps_bytes_and_original_name(self):
        (self.src / "f").write_bytes(b"\r\nexact")
        rec = self.store.intake(self.src / "f", "../../etc/cron.d/evil")
        self.write([rec])
        receipt = self.release(name_policy="generate")
        entry = receipt["released"][0]
        self.assertTrue(entry["renamed"])
        self.assertEqual(entry["source_name"], "../../etc/cron.d/evil")
        self.assertTrue(entry["name"].startswith("guardian-object-0000-"))
        self.assertEqual((self.dest / entry["name"]).read_bytes(), b"\r\nexact")
        self.assertEqual(self.dest_entries(), [entry["name"]])

    def test_duplicate_names_case_insensitive(self):
        self.assertEqual(plan_names([{"source_name": "a.txt", "sha256": "0" * 64},
                                     {"source_name": "A.TXT", "sha256": "1" * 64}], "generate")[1][1], True)
        with self.assertRaises(E.ValidationError):
            plan_names([{"source_name": "a.txt", "sha256": "0" * 64},
                        {"source_name": "A.TXT", "sha256": "1" * 64}], "strict")

    def test_existing_destination_file_never_overwritten(self):
        (self.dest / "a.txt").write_bytes(b"keep me")
        self.write(self.intake_all({"a.txt": b"new", "b.txt": b"other"}))
        with self.assertRaises(E.SecurityViolation) as cm:
            self.release()
        self.assertEqual(cm.exception.code, "DESTINATION_EXISTS")
        self.assertEqual((self.dest / "a.txt").read_bytes(), b"keep me")
        self.assertEqual(self.dest_entries(), ["a.txt"])

    def test_unsafe_destination_refused(self):
        self.write(self.intake_all({"a": b"x"}))
        os.chmod(self.dest, 0o777)
        with self.assertRaises(E.SecurityViolation):
            self.release()
        os.chmod(self.dest, 0o700)
        os.symlink(self.dest, self.root / "dest-link")
        with self.assertRaises(E.SecurityViolation):
            fd = os.open(self.pkg, os.O_RDONLY)
            try:
                release_package(fd, HmacVerifier(), self.root / "dest-link")
            finally:
                os.close(fd)

    def test_failure_after_staging_cleans_up(self):
        # Payload verifies and is staged, then the trailer fails: nothing may remain.
        self.write(self.intake_all({"a": b"A" * 9000}))
        data = bytearray(self.pkg.read_bytes())
        data[-1] ^= 0xFF
        self.pkg.write_bytes(bytes(data))
        with self.assertRaises(E.IntegrityError):
            self.release()
        self.assertEqual(self.dest_entries(), [])

    def test_parameter_validation(self):
        self.write(self.intake_all({"a": b"x"}))
        for kwargs in (dict(name_policy="lenient"), dict(file_mode=0o666), dict(file_mode=0o200)):
            with self.assertRaises(E.ValidationError):
                self.release(**kwargs)
        self.assertEqual(self.dest_entries(), [])


if __name__ == "__main__":
    unittest.main()
