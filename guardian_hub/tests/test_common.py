# SPDX-License-Identifier: GPL-3.0-or-later
"""Stage 1 foundation tests.  Run from guardian_hub/:

    python3 -I -B -m unittest discover -s tests -v
"""

import io
import json
import logging
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from usbguardian.common import canonical as C  # noqa: E402
from usbguardian.common import errors as E  # noqa: E402
from usbguardian.common import fsutil as F  # noqa: E402
from usbguardian.common import log as L  # noqa: E402
from usbguardian.common import names as N  # noqa: E402
from usbguardian.common.text import display_text  # noqa: E402


class TextTests(unittest.TestCase):
    def test_escapes_terminal_and_bidi(self):
        self.assertEqual(display_text("a\x1b[31mb"), "a\\x1b[31mb")
        self.assertEqual(display_text("x\u202ey"), "x\\u202ey")
        self.assertEqual(display_text("line\nforged"), "line\\x0aforged")
        self.assertEqual(display_text(b"\xff"), "\\xff")
        self.assertEqual(display_text("\\"), "\\\\")
        self.assertEqual(display_text(None), "")

    def test_truncates(self):
        self.assertEqual(display_text("a" * 10, 4), "aaaa...(truncated)")


class ErrorTests(unittest.TestCase):
    def test_codes_and_wire(self):
        err = E.IntegrityError("bad \x1b hash")
        self.assertEqual(err.code, "INTEGRITY_FAILURE")
        self.assertIsInstance(err, E.SecurityViolation)
        self.assertEqual(err.to_wire(), {"code": "INTEGRITY_FAILURE", "message": "bad \\x1b hash"})

    def test_custom_code_validated(self):
        self.assertEqual(E.ValidationError("x", code="PATH_TRAVERSAL").code, "PATH_TRAVERSAL")
        for bad in ("lower", "A", "X" * 70, "BAD-CODE", 5):
            with self.assertRaises(ValueError):
                E.GuardianError("x", code=bad)

    def test_from_wire_roundtrip_and_hostile(self):
        back = E.error_from_wire(E.PermissionDenied("no").to_wire())
        self.assertIsInstance(back, E.PermissionDenied)
        unknown = E.error_from_wire({"code": "SOMETHING_NEW", "message": "m"})
        self.assertEqual(type(unknown), E.GuardianError)
        self.assertEqual(unknown.code, "SOMETHING_NEW")
        for hostile in (None, [], {"code": "x", "message": "m"}, {"code": "ABC"},
                        {"code": "ABC", "message": "m", "extra": 1}, {"code": "ABC", "message": 5}):
            self.assertIsInstance(E.error_from_wire(hostile), E.ProtocolError)
        self.assertNotIn("\x1b", E.error_from_wire({"code": "ABC", "message": "\x1b[2J"}).message)

    def test_unexpected_exceptions_do_not_leak(self):
        err = E.as_guardian_error(KeyError("/root/secret-path"))
        self.assertIsInstance(err, E.InternalError)
        self.assertNotIn("secret", err.message)
        self.assertIsInstance(E.as_guardian_error(MemoryError()), E.ResourceLimitExceeded)


class CanonicalTests(unittest.TestCase):
    def test_sorted_compact_utf8(self):
        self.assertEqual(C.canonical_dumps({"b": 1, "a": [True, None, "\u00e9"]}),
                         '{"a":[true,null,"\u00e9"],"b":1}'.encode("utf-8"))

    def test_rfc8785_key_order_utf16(self):
        # U+1F600 (surrogate pair D83D...) sorts before U+FB01 in UTF-16 order,
        # but after it in code point order.
        out = C.canonical_dumps({"\ufb01": 1, "\U0001f600": 2})
        self.assertEqual(out, '{"\U0001f600":2,"\ufb01":1}'.encode("utf-8"))

    def test_rfc8785_string_escapes(self):
        self.assertEqual(C.canonical_dumps("\u0000\b\t\n\f\r\"\\\u001f\u007f\u2028"),
                         b'"\\u0000\\b\\t\\n\\f\\r\\"\\\\\\u001f\x7f\xe2\x80\xa8"')

    def test_rejected_values(self):
        for bad in (1.5, float("nan"), b"x", {1: 2}, {"a": set()}, 2 ** 53, -(2 ** 53), "\ud800",
                    {"\udc00": 1}, object()):
            with self.assertRaises(E.ValidationError, msg=repr(bad)):
                C.canonical_dumps(bad)

    def test_depth_limit_and_cycles(self):
        deep = []
        for _ in range(40):
            deep = [deep]
        with self.assertRaises(E.ValidationError):
            C.canonical_dumps(deep)
        cyc = []
        cyc.append(cyc)
        with self.assertRaises(E.ValidationError):
            C.canonical_dumps(cyc)

    def test_tuple_and_bool_int(self):
        self.assertEqual(C.canonical_dumps((1, True, 0)), b"[1,true,0]")

    def test_loads_strict(self):
        self.assertEqual(C.canonical_loads(b'{"a":[1,"x"]}'), {"a": [1, "x"]})
        self.assertEqual(C.canonical_loads(b' \n{"a":1} \n'), {"a": 1})
        bad_inputs = [
            b'{"a":1,"a":2}', b"1.0", b"1e3", b"NaN", b"Infinity", b"-Infinity",
            b"\xef\xbb\xbf{}", b"\xff", b'"\\ud800"', b"[1] [2]", b"9007199254740992",
            b"1" * 5000, b"[" * 100 + b"]" * 100, b'{"a":}', b"",
        ]
        for raw in bad_inputs:
            with self.assertRaises(E.ValidationError, msg=repr(raw[:20])):
                C.canonical_loads(raw)
        with self.assertRaises(E.ResourceLimitExceeded):
            C.canonical_loads(b"[" + b"1," * 100 + b"1]", max_bytes=50)
        with self.assertRaises(E.ValidationError):
            C.canonical_loads("{}")

    def test_brackets_inside_strings_do_not_count_as_depth(self):
        self.assertEqual(C.canonical_loads(b'["' + b"[" * 100 + b'"]'), ["[" * 100])
        self.assertEqual(C.canonical_loads(b'["\\"[[[["]', max_depth=1), ['"[[[['])

    def test_require_canonical(self):
        self.assertEqual(C.canonical_loads(b'{"a":1,"b":2}', require_canonical=True), {"a": 1, "b": 2})
        for raw in (b'{"b":2,"a":1}', b'{"a": 1}', b'"\\u00e9"', b'{"a":1}\n'):
            with self.assertRaises(E.ValidationError):
                C.canonical_loads(raw, require_canonical=True)

    def test_roundtrip(self):
        value = {"z": [1, -2, {"y": None}], "\u00e9": "\U0001f600", "a": False}
        self.assertEqual(C.canonical_loads(C.canonical_dumps(value), require_canonical=True), value)

    def test_digest_domain_separation(self):
        a = C.canonical_digest("guardian/deployment/v1", {"x": 1})
        b = C.canonical_digest("guardian/epoch/v1", {"x": 1})
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)
        self.assertEqual(a, C.canonical_digest("guardian/deployment/v1", {"x": 1}))
        for bad in ("", "Upper", "a\x00b", "x" * 70):
            with self.assertRaises(ValueError):
                C.canonical_digest(bad, {})

    def test_base64_strict(self):
        self.assertEqual(C.b64decode(C.b64encode(b"\x00\xffab")), b"\x00\xffab")
        for bad in ("QQ", "QQ=", "Q Q==", "QR==", "QQ==\n", "-_8=", 5):
            with self.assertRaises(E.ValidationError, msg=repr(bad)):
                C.b64decode(bad)
        with self.assertRaises(E.ResourceLimitExceeded):
            C.b64decode("QUFB" * 10, max_bytes=6)


class NameTests(unittest.TestCase):
    def test_safe_names(self):
        for ok in ("report.json", "Guardian_USB-01.txt", "a", "x" * 128):
            self.assertEqual(N.check_component(ok), [], ok)

    def test_unsafe_names(self):
        cases = {
            "..": "PATH_TRAVERSAL", ".": "EMPTY_OR_DOT_NAME", "": "EMPTY_OR_DOT_NAME",
            "a/b": "EMBEDDED_SLASH", "a\\b": "EMBEDDED_BACKSLASH", "a\x00b": "NUL_IN_NAME",
            "a\nb": "NEWLINE_IN_NAME", "a\x1bb": "CONTROL_CHARACTER_IN_NAME",
            "evil\u202etxt.exe": "BIDI_CONTROL_IN_NAME", "a\u200bb": "ZERO_WIDTH_CHARACTER_IN_NAME",
            "a\ud800": "INVALID_NAME_ENCODING", "caf\u00e9": "NON_ASCII_NAME",
            "\u0430pple": "NON_ASCII_NAME", "x.": "TRAILING_SPACE_OR_DOT", "x ": "TRAILING_SPACE_OR_DOT",
            " x": "LEADING_SPACE", "-rf": "LEADING_DASH", "CON": "WINDOWS_RESERVED_NAME",
            "nul.txt": "WINDOWS_RESERVED_NAME", "com1 .log": "WINDOWS_RESERVED_NAME",
            "a:b": "WINDOWS_INVALID_CHARACTER", "x" * 129: "NAME_TOO_LONG",
            "e\u0301": "NOT_NFC_NORMALIZED", "a\u00a0b": "UNUSUAL_WHITESPACE_IN_NAME",
            "a\ue000": "UNASSIGNED_OR_PRIVATE_CHARACTER_IN_NAME", 7: "NOT_A_STRING",
        }
        for name, reason in cases.items():
            self.assertIn(reason, N.check_component(name), repr(name))
        self.assertEqual(N.check_component("-x", allow_leading_dash=True), [])
        self.assertEqual(N.check_component("caf\u00e9", allow_non_ascii=True), [])
        self.assertIn("NAME_TOO_LONG", N.check_component("\u00e9" * 128, allow_non_ascii=True, max_len=200))

    def test_validate_relative_path(self):
        self.assertEqual(N.validate_relative_path("a/b.txt"), ["a", "b.txt"])
        for bad, code in (("../x", "PATH_TRAVERSAL"), ("a/../b", "PATH_TRAVERSAL"), ("/etc/passwd", "ABSOLUTE_PATH"),
                          ("\\\\srv\\x", "ABSOLUTE_PATH"), ("C:x", "ABSOLUTE_PATH"), ("a//b", "UNSAFE_NAME"),
                          ("", "PATH_TRAVERSAL"), (None, "PATH_TRAVERSAL"), ("a/", "UNSAFE_NAME")):
            with self.assertRaises(E.ValidationError) as cm:
                N.validate_relative_path(bad)
            self.assertEqual(cm.exception.code, code, repr(bad))
        self.assertEqual(N.safe_join(Path("/base"), "a/b"), Path("/base/a/b"))

    def test_sanitize_component(self):
        cases = {
            "SanDisk Ultra USB 3.0": "SanDisk_Ultra_USB_3.0", "../../etc/passwd": "etc_passwd",
            "\u202eexe.txt": "exe.txt", "Caf\u00e9 \u00fcber": "Cafe_uber", "": "unnamed", None: "unnamed",
            "....": "unnamed", "-rf --no-preserve-root": "rf_--no-preserve-root", "CON": "_CON",
            "nul.txt": "_nul.txt", "\x1b[31mred": "31mred", b"\xffbytes": "bytes",
        }
        for raw, expected in cases.items():
            out = N.sanitize_component(raw)
            self.assertEqual(out, expected, repr(raw))
            self.assertEqual(N.check_component(out), [], repr(raw))
        long = N.sanitize_component("a" * 500, max_len=10)
        self.assertEqual(long, "a" * 10)
        with self.assertRaises(ValueError):
            N.sanitize_component("x", fallback="../bad")
        with self.assertRaises(ValueError):
            N.sanitize_component("x", max_len=0)

    def test_sanitize_never_unsafe_fuzz(self):
        import random
        rng = random.Random(1234)
        alphabet = "aZ09._- /\\:\x00\x1b\u202e\u200b\u00e9\U0001f600CONPRLUX."
        for _ in range(3000):
            raw = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
            out = N.sanitize_component(raw, max_len=rng.randint(1, 40))
            self.assertEqual(N.check_component(out), [], repr(raw))


class FsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chmod(self.root, 0o700)

    def tearDown(self):
        self.tmp.cleanup()

    def test_private_dir(self):
        d = self.root / "state"
        F.ensure_private_dir(d)
        self.assertEqual(stat.S_IMODE(os.lstat(d).st_mode), 0o700)
        os.chmod(d, 0o755)
        with self.assertRaises(E.SecurityViolation):
            F.ensure_private_dir(d)
        link = self.root / "link"
        os.symlink(self.root, link)
        with self.assertRaises(E.SecurityViolation):
            F.ensure_private_dir(link)

    def test_atomic_write_and_read(self):
        p = self.root / "data.json"
        F.atomic_write(p, b"one")
        F.atomic_write(p, b"two")
        self.assertEqual(F.read_file_bounded(p, 10, require_private=True), b"two")
        self.assertEqual(stat.S_IMODE(os.lstat(p).st_mode), 0o600)
        self.assertEqual(sorted(os.listdir(self.root)), ["data.json"])

    def test_atomic_write_refuses_unsafe(self):
        target = self.root / "real"
        target.write_bytes(b"keep")
        link = self.root / "link"
        os.symlink(target, link)
        with self.assertRaises(E.SecurityViolation):
            F.atomic_write(link, b"x")
        self.assertEqual(target.read_bytes(), b"keep")
        os.mkdir(self.root / "dir")
        with self.assertRaises(E.SecurityViolation):
            F.atomic_write(self.root / "dir", b"x")
        with self.assertRaises(E.ValidationError):
            F.atomic_write(self.root / "bad\nname", b"x")
        os.symlink(self.root / "dir", self.root / "dirlink")
        with self.assertRaises(OSError):
            F.atomic_write(self.root / "dirlink" / "f", b"x")
        self.assertEqual(sorted(os.listdir(self.root)), ["dir", "dirlink", "link", "real"])

    def test_read_bounded_rejections(self):
        p = self.root / "big"
        p.write_bytes(b"x" * 100)
        with self.assertRaises(E.ResourceLimitExceeded):
            F.read_file_bounded(p, 99)
        os.symlink(p, self.root / "ln")
        with self.assertRaises(E.ValidationError):
            F.read_file_bounded(self.root / "ln", 1000)
        os.mkfifo(self.root / "fifo")
        with self.assertRaises(E.SecurityViolation):
            F.read_file_bounded(self.root / "fifo", 1000)
        os.chmod(p, 0o644)
        with self.assertRaises(E.SecurityViolation):
            F.read_file_bounded(p, 1000, require_private=True)
        with self.assertRaises(E.ValidationError):
            F.read_file_bounded(self.root / "missing", 10)

    def test_check_trusted_file(self):
        p = self.root / "policy.json"
        p.write_bytes(b"{}")
        os.chmod(p, 0o644)
        owners = (0, os.geteuid())
        F.check_trusted_file(p, allowed_owners=owners)
        os.chmod(p, 0o666)
        with self.assertRaises(E.SecurityViolation):
            F.check_trusted_file(p, allowed_owners=owners)
        os.chmod(p, 0o644)
        os.chmod(self.root, 0o777)
        with self.assertRaises(E.SecurityViolation):
            F.check_trusted_file(p, allowed_owners=owners)
        os.chmod(self.root, 0o700)
        os.symlink(p, self.root / "ln")
        with self.assertRaises(E.SecurityViolation):
            F.check_trusted_file(self.root / "ln", allowed_owners=owners)
        with self.assertRaises(E.SecurityViolation):
            F.check_trusted_file(p, allowed_owners=(4242424,))


class LogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.logger = logging.getLogger("usbguardian.test.%s" % self.id().rsplit(".", 1)[1].lower())
        self.logger.handlers[:] = []
        self.logger.propagate = False
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        for h in self.logger.handlers:
            h.close()
        self.tmp.cleanup()

    def _capture(self, formatter=None):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(formatter or L.JsonLineFormatter())
        self.logger.addHandler(handler)
        return stream

    def test_redaction(self):
        stream = self._capture()
        L.log_event(self.logger, logging.INFO, "vault.unlock", passphrase="hunter2", pin="123456",
                    master_key="abc", wrapped_key="def", key="k", api_token="t", key_id="kid-1",
                    key_epoch=22, blob=b"\x00secret", nested={"private_key": "pk", "ok": "fine"})
        entry = json.loads(stream.getvalue())
        f = entry["fields"]
        for name in ("passphrase", "pin", "master_key", "wrapped_key", "key", "api_token"):
            self.assertEqual(f[name], L.REDACTED, name)
        self.assertEqual(f["key_id"], "kid-1")
        self.assertEqual(f["key_epoch"], 22)
        self.assertEqual(f["blob"], "<binary len=7 redacted>")
        self.assertEqual(f["nested"], {"private_key": L.REDACTED, "ok": "fine"})
        for secret in ("hunter2", "123456", "secret"):
            self.assertNotIn(secret, stream.getvalue())

    def test_log_injection_neutralized(self):
        stream = self._capture()
        L.log_event(self.logger, logging.WARNING, "device.seen", model="Evil\n{\"forged\":1}\x1b[2J\u202e")
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].isascii())
        self.assertNotIn("\x1b", lines[0])
        self.assertIn("\\\\x1b", lines[0])
        console = self._capture(L.ConsoleFormatter())
        L.log_event(self.logger, logging.WARNING, "device.seen", model="a\nb\x1b")
        self.assertEqual(console.getvalue().count("\n"), 1)
        self.assertNotIn("\x1b", console.getvalue())

    def test_event_and_field_names_validated(self):
        with self.assertRaises(ValueError):
            L.log_event(self.logger, logging.INFO, "Bad Event")
        with self.assertRaises(ValueError):
            L.log_event(self.logger, logging.INFO, "ok", **{"bad-name": 1})

    def test_exceptions_without_traceback(self):
        stream = self._capture()
        try:
            raise E.IntegrityError("hash /secret/path mismatch")
        except E.IntegrityError as exc:
            L.log_event(self.logger, logging.ERROR, "vault.check", exc_info=exc)
        entry = json.loads(stream.getvalue())
        self.assertEqual(entry["exception"], {"type": "IntegrityError", "code": "INTEGRITY_FAILURE"})
        self.assertNotIn("Traceback", stream.getvalue())

    def test_plain_messages_are_sanitized(self):
        stream = self._capture()
        self.logger.warning("free text with %s", "\x1b[2Jarg")
        entry = json.loads(stream.getvalue())
        self.assertEqual(entry["event"], "message")
        self.assertEqual(entry["fields"]["text"], "free text with \\x1b[2Jarg")

    def test_private_file_handler(self):
        path = self.root / "guardian.log"
        handler = L.PrivateFileHandler(path, max_bytes=4096, backups=2)
        self.logger.addHandler(handler)
        for i in range(200):
            L.log_event(self.logger, logging.INFO, "tick", i=i)
        handler.close()
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        self.assertTrue((self.root / "guardian.log.1").exists())
        self.assertTrue((self.root / "guardian.log.2").exists())
        self.assertFalse((self.root / "guardian.log.3").exists())
        for p in self.root.iterdir():
            self.assertLessEqual(p.stat().st_size, 4096)
            for line in p.read_text("ascii").splitlines():
                json.loads(line)

    def test_private_file_handler_refuses_symlink_and_shared(self):
        target = self.root / "target"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        os.symlink(target, self.root / "ln.log")
        with self.assertRaises(E.SecurityViolation):
            L.PrivateFileHandler(self.root / "ln.log")
        shared = self.root / "shared.log"
        shared.write_bytes(b"")
        os.chmod(shared, 0o644)
        with self.assertRaises(E.SecurityViolation):
            L.PrivateFileHandler(shared)

    def test_configure_logging_idempotent(self):
        root = L.configure_logging(self.root / "a.log", console=False)
        root = L.configure_logging(self.root / "a.log", console=True)
        ours = [h for h in root.handlers if getattr(h, "_guardian_handler", False)]
        self.assertEqual(len(ours), 2)
        L.configure_logging(None, console=False)
        self.assertEqual([h for h in root.handlers if getattr(h, "_guardian_handler", False)], [])


if __name__ == "__main__":
    unittest.main()
