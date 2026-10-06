# SPDX-License-Identifier: GPL-3.0-or-later
"""Source hygiene: dangerous constructs must not appear in Guardian code."""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted((ROOT / "usbguardian").rglob("*.py")) + [ROOT / "guardian.py"]

FORBIDDEN = {
    "shell=True": re.compile(r"shell\s*=\s*True"),
    "os.system": re.compile(r"\bos\.system\s*\("),
    "os.popen": re.compile(r"\bos\.popen\s*\("),
    "eval": re.compile(r"(?<![.\w])eval\s*\("),
    "exec": re.compile(r"(?<![.\w])exec\s*\("),
    "pickle": re.compile(r"\b(c?pickle|marshal|shelve)\b"),
    "dynamic import": re.compile(r"__import__\s*\(|\bimportlib\b"),
    "bash -c": re.compile(r"""["'](ba|z|da)?sh["']\s*,\s*["']-c["']"""),
    "tempfile.mktemp": re.compile(r"\bmktemp\s*\("),
    "unbounded read()": re.compile(r"\.read\(\)"),
}


class HygieneTests(unittest.TestCase):
    def test_sources_found(self):
        self.assertGreater(len(SOURCES), 10)

    def test_no_forbidden_constructs(self):
        for path in SOURCES:
            text = path.read_text("utf-8")
            for label, pattern in FORBIDDEN.items():
                self.assertIsNone(pattern.search(text), "%s in %s" % (label, path.relative_to(ROOT)))

    def test_license_headers(self):
        for path in SOURCES:
            head = path.read_text("utf-8").splitlines()[:2]
            self.assertTrue(any("SPDX-License-Identifier: GPL-3.0-or-later" in line for line in head), path)

    def test_ascii_source(self):
        # Keeps bidi/zero-width tricks out of the code itself.
        for path in SOURCES:
            self.assertTrue(path.read_bytes().isascii(), path)

    def test_runtime_is_stdlib_only(self):
        allowed_prefixes = ("usbguardian",)
        stdlib = set(sys.stdlib_module_names)
        for path in SOURCES:
            for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_][\w]*)", path.read_text("utf-8"), re.M):
                name = m.group(1)
                if name in ("__future__",) or name.startswith(allowed_prefixes):
                    continue
                self.assertIn(name, stdlib, "%s imports non-stdlib %s" % (path.relative_to(ROOT), name))


    def test_generated_shell_has_no_backticks(self):
        # Backtick rule (owner handoff): Guardian's own shell code uses no legacy command substitution.
        sys.path.insert(0, str(ROOT))
        from usbguardian.deploy.debian import USBGUARD_SUGGESTION, InstallLayout, init_script
        script = init_script(InstallLayout(), python="/usr/bin/python3", worker_user="usbguardian-worker",
                             instance_id="desk")
        for text in (script, USBGUARD_SUGGESTION):
            self.assertNotIn(chr(0x60), text)
        self.assertNotIn("eval ", script)


if __name__ == "__main__":
    unittest.main()
