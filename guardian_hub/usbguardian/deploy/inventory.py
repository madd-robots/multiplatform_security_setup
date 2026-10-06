# SPDX-License-Identifier: GPL-3.0-or-later
"""Dependency inventory, derived from the code.

``referenced_tools`` lists every external tool the code asks for
(``find_tool``/``require_tool`` with a literal name). Each must have an
entry in ``TOOLS``; a test enforces that, so the inventory and the code
cannot drift apart. Python itself and packages that only matter for hardware
are listed separately.

Classes: REQUIRED RUNTIME, REQUIRED INSTALLER, OPTIONAL FEATURE, HARDWARE
FEATURE, DEVELOPMENT / TEST.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set

from .system import Runner, system_runner

REQUIRED_RUNTIME = "REQUIRED RUNTIME"
REQUIRED_INSTALLER = "REQUIRED INSTALLER"
OPTIONAL_FEATURE = "OPTIONAL FEATURE"
HARDWARE_FEATURE = "HARDWARE FEATURE"
DEVELOPMENT_TEST = "DEVELOPMENT / TEST"

# tool -> (Debian package, class, what uses it)
TOOLS: Dict[str, Any] = {
    "python3": ("python3", REQUIRED_RUNTIME, "Guardian itself (standard library only)"),
    "ssh-keygen": ("openssh-client", REQUIRED_RUNTIME, "owner signatures and verification (SSHSIG)"),
    "start-stop-daemon": ("dpkg", REQUIRED_RUNTIME, "the SysVinit service script"),
    "mount": ("mount", OPTIONAL_FEATURE, "Airlock: read-only acquisition"),
    "umount": ("mount", OPTIONAL_FEATURE, "Airlock: read-only acquisition"),
    "clamscan": ("clamav", OPTIONAL_FEATURE, "Airlock malware scan (without it every file is BLOCKED)"),
    "update-rc.d": ("init-system-helpers", REQUIRED_INSTALLER, "SysVinit service registration"),
    "invoke-rc.d": ("init-system-helpers", REQUIRED_INSTALLER, "SysVinit service control"),
    "runlevel": ("sysvinit-core", REQUIRED_INSTALLER, "SysVinit preflight"),
    "dpkg": ("dpkg", REQUIRED_INSTALLER, "preflight, architecture, package verification"),
    "dpkg-query": ("dpkg", REQUIRED_INSTALLER, "package state and ownership"),
    "dpkg-deb": ("dpkg", REQUIRED_INSTALLER, "offline bundle build: package metadata"),
    "apt-get": ("apt", REQUIRED_INSTALLER, "installs missing packages (authenticated, never upgrades)"),
    "adduser": ("adduser", REQUIRED_INSTALLER, "creates the dedicated worker account if missing"),
}
EXTRA_PACKAGES: List[Dict[str, str]] = [
    {"package": "libfido2-1", "class": HARDWARE_FEATURE,
     "used_for": "YubiKey FIDO2 signing through ssh-keygen (normally pulled in by openssh-client)"},
    {"package": "pcscd", "class": HARDWARE_FEATURE, "used_for": "age-plugin-yubikey (D7, deferred; not installed)"},
    {"package": "(none beyond the above)", "class": DEVELOPMENT_TEST,
     "used_for": "the test suite uses the standard library and ssh-keygen with software keys"},
]
TOOL_CALL = re.compile(r"(?:find_tool|require_tool)\(\s*\"([A-Za-z0-9._-]+)\"\s*\)")
ARGV_TOOL = re.compile(r"(?:run\(|argv\s*=\s*)\[\s*\"([A-Za-z0-9._-]+)\"")


def referenced_tools(code_root: Path) -> Set[str]:
    """Tool names the code resolves, from literal find_tool/require_tool calls and runner argv[0]."""
    names: Set[str] = set()
    paths = sorted((Path(code_root) / "usbguardian").rglob("*.py")) + [Path(code_root) / "guardian.py"]
    for path in paths:
        text = path.read_text("utf-8")
        names.update(TOOL_CALL.findall(text))
        names.update(ARGV_TOOL.findall(text))
    return names


def inventory() -> List[Dict[str, str]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for tool, (package, cls, used_for) in sorted(TOOLS.items()):
        row = rows.setdefault(package, {"package": package, "class": cls, "tools": [], "used_for": []})
        row["tools"].append(tool)
        if used_for not in row["used_for"]:
            row["used_for"].append(used_for)
        if cls == REQUIRED_RUNTIME:  # the strongest class wins
            row["class"] = cls
    out = [dict(r, tools=", ".join(r["tools"]), used_for="; ".join(r["used_for"])) for r in rows.values()]
    return out + [dict(e, tools="") for e in EXTRA_PACKAGES]


def package_state(packages: List[str], run: Runner = system_runner) -> Dict[str, Dict[str, Any]]:
    """{package: {installed, version, architecture}} from the dpkg database (read-only)."""
    out: Dict[str, Dict[str, Any]] = {}
    for pkg in packages:
        rc, text, _ = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Version}\t${Architecture}", pkg])
        parts = text.split("\t")
        if rc == 0 and len(parts) == 3 and parts[0].startswith("ii"):
            out[pkg] = {"installed": True, "version": parts[1], "architecture": parts[2].strip()}
        else:
            out[pkg] = {"installed": False, "version": None, "architecture": None}
    return out
