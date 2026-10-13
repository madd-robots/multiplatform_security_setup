# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only SysVinit preflight (ROADMAP D9).

Checks, without changing anything:
- PID 1: name, command line, executable (when readable), and whether
  systemd is running. Anything other than SysVinit's init stops service
  installation with ENVIRONMENT MISMATCH - SYSVINIT NOT ACTIVE.
- the package that owns the init executable, and its version
- the runlevel
- /etc/init.d and the rc directories, update-rc.d, invoke-rc.d,
  start-stop-daemon (presence, ownership, permissions)
- ``dpkg --audit`` and ``dpkg --verify`` of the init packages; a changed
  critical init file (not a configuration file) is BLOCKING and is reported
  with package, path, observed evidence and method, never repaired

Result: PASS, PASS WITH FINDINGS, BLOCKED or UNKNOWN. UNKNOWN is never
treated as PASS. dpkg verification compares files with the package
database's checksums: an integrity signal, not proof that the system is
clean (the database itself can be altered by root).
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..common.tools import find_tool
from .system import Runner, read_small, system_runner

MISMATCH = "ENVIRONMENT MISMATCH - SYSVINIT NOT ACTIVE"
INIT_PACKAGES = ("sysvinit-core", "sysv-rc", "initscripts", "init-system-helpers", "sysvinit-utils")
SERVICE_TOOLS = ("update-rc.d", "invoke-rc.d", "start-stop-daemon")
RC_DIRS = ("rc0.d", "rc1.d", "rc2.d", "rc3.d", "rc4.d", "rc5.d", "rc6.d", "rcS.d")
VERIFY_LINE = re.compile(r"^(missing  |\?\?[?.5]\?{6}|[?.0-9a-zA-Z]{9}) +(c )?(/\S.*)$")


class Checks:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(self, check: str, status: str, detail: str, method: str, **evidence: Any) -> None:
        assert status in ("ok", "info", "finding", "blocking", "unknown")
        entry: Dict[str, Any] = {"check": check, "status": status, "detail": detail, "method": method}
        if evidence:
            entry["evidence"] = evidence
        self.items.append(entry)

    def result(self) -> str:
        statuses = {c["status"] for c in self.items}
        if "blocking" in statuses:
            return "BLOCKED"
        if "unknown" in statuses:
            return "UNKNOWN"
        if "finding" in statuses:
            return "PASS WITH FINDINGS"
        return "PASS"


def systemd_active(proc_root: Path = Path("/proc"), fs_root: Path = Path("/")) -> bool:
    comm = (read_small(Path(proc_root) / "1/comm", 256) or "").strip()
    return comm == "systemd" or os.path.isdir(Path(fs_root) / "run/systemd/system")


def _root_protected(path: Path) -> Optional[str]:
    try:
        st = os.lstat(path)
    except OSError:
        return "missing"
    if stat.S_ISLNK(st.st_mode):
        try:
            st = os.stat(path)
        except OSError:
            return "dangling symlink"
    if st.st_uid != 0:
        return "owned by uid %d" % st.st_uid
    if st.st_mode & 0o022:
        return "writable by group or others (mode %o)" % stat.S_IMODE(st.st_mode)
    return None


def sysvinit_preflight(*, proc_root: Path = Path("/proc"), fs_root: Path = Path("/"),
                       run: Runner = system_runner) -> Dict[str, Any]:
    c = Checks()
    proc_root, fs_root = Path(proc_root), Path(fs_root)
    comm = (read_small(proc_root / "1/comm", 256) or "").strip()
    cmdline = [a for a in (read_small(proc_root / "1/cmdline", 4096) or "").split("\x00") if a]
    try:
        exe: Optional[str] = os.readlink(proc_root / "1/exe")
    except OSError:
        exe = None
    pid1 = {"comm": comm, "cmdline": cmdline[:4], "exe": exe}
    systemd = comm == "systemd" or (exe or "").endswith("/systemd") or os.path.isdir(fs_root / "run/systemd/system")
    if not comm:
        c.add("pid1", "unknown", "PID 1 is not readable", "/proc/1/comm", **pid1)
    elif systemd:
        c.add("pid1", "blocking", MISMATCH + ": systemd is PID 1", "/proc/1/comm, /proc/1/exe, /run/systemd/system",
              **pid1)
    elif comm != "init":
        c.add("pid1", "blocking", MISMATCH + ": PID 1 is %r" % comm[:32], "/proc/1/comm", **pid1)
    else:
        c.add("pid1", "ok", "PID 1 is init", "/proc/1/comm", **pid1)
        if exe is None:
            c.add("pid1_exe", "info", "PID 1 executable not readable without root; using its command line",
                  "/proc/1/exe")

    init_path = exe or (cmdline[0] if cmdline and cmdline[0].startswith("/") else "/sbin/init")
    real_init = os.path.realpath(fs_root / init_path.lstrip("/"))
    owner = None
    rc, out, _ = run(["dpkg-query", "-S", init_path])
    m = re.match(r"^([a-z0-9][a-z0-9+.-]*)(?::[a-z0-9-]+)?: ", out.strip()) if rc == 0 else None
    if m:
        owner = m.group(1)
        if owner == "systemd-sysv" or owner == "systemd":
            c.add("init_package", "blocking", MISMATCH + ": %s belongs to %s" % (init_path, owner), "dpkg-query -S")
        elif owner != "sysvinit-core":
            c.add("init_package", "finding", "%s belongs to %s, not sysvinit-core" % (init_path, owner),
                  "dpkg-query -S")
        else:
            c.add("init_package", "ok", "%s belongs to sysvinit-core" % init_path, "dpkg-query -S")
    else:
        c.add("init_package", "unknown", "owner of %s could not be determined" % init_path, "dpkg-query -S")
    if owner:
        rc, out, _ = run(["dpkg-query", "-W", "-f=${Version}", owner])
        version = out.strip() if rc == 0 and re.fullmatch(r"[0-9A-Za-z.+~:-]{1,64}", out.strip()) else None
        c.add("init_version", "ok" if version else "unknown", version or "version unknown", "dpkg-query -W",
              package=owner)

    rc, out, _ = run(["runlevel"])
    m = re.fullmatch(r"([0-6SsN]) ([0-6Ss])", out.strip()) if rc == 0 else None
    if not m:
        c.add("runlevel", "unknown", "runlevel unavailable or malformed: %r" % out.strip()[:40], "runlevel(8)")
    elif m.group(2) in "2345":
        c.add("runlevel", "ok", "runlevel %s" % m.group(2), "runlevel(8)")
    else:
        c.add("runlevel", "finding", "unexpected runlevel %s" % m.group(2), "runlevel(8)")

    initd = fs_root / "etc/init.d"
    problem = _root_protected(initd)
    c.add("init_d", "blocking" if problem else "ok", "/etc/init.d %s" % (problem or "is root-owned and protected"),
          "lstat")
    missing = [d for d in RC_DIRS if not os.path.isdir(fs_root / "etc" / d)]
    c.add("rc_dirs", "blocking" if missing else "ok",
          "missing rc directories: %s" % ", ".join(missing) if missing else "rc directories present", "stat")
    critical = {real_init: "init"}
    for tool in SERVICE_TOOLS:
        path = find_tool(tool) if fs_root == Path("/") else None
        if path is None and fs_root != Path("/"):
            for d in ("usr/sbin", "sbin", "usr/bin", "bin"):
                if os.path.exists(fs_root / d / tool):
                    path = str(fs_root / d / tool)
                    break
        if path is None:
            c.add("tool_" + tool, "blocking", "%s not found in trusted system directories" % tool, "find_tool")
        else:
            critical[os.path.realpath(path)] = tool
            c.add("tool_" + tool, "ok", path, "find_tool")
    for path, role in sorted(critical.items()):
        problem = _root_protected(Path(path))
        if problem:
            c.add("critical_" + role, "blocking", "%s: %s" % (path, problem), "lstat", path=path)

    rc, out, _ = run(["dpkg", "--audit"])
    if rc == 127:
        c.add("dpkg_audit", "unknown", "dpkg unavailable", "dpkg --audit")
    elif out.strip():
        c.add("dpkg_audit", "finding", "package database reports problems: %s" % out.strip()[:300], "dpkg --audit")
    else:
        c.add("dpkg_audit", "ok", "no problems reported", "dpkg --audit")

    installed = []
    for pkg in INIT_PACKAGES:
        rc, out, _ = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", pkg])
        if rc == 0 and out.startswith("ii"):
            installed.append(pkg)
    if not installed:
        c.add("dpkg_verify", "unknown", "no init packages found to verify", "dpkg-query -W")
    else:
        rc, out, _ = run(["dpkg", "--verify"] + installed)
        if rc not in (0, 1):
            c.add("dpkg_verify", "unknown", "dpkg --verify failed (status %d)" % rc, "dpkg --verify")
        else:
            changed = []
            for line in out.splitlines():
                m = VERIFY_LINE.match(line.rstrip())
                if not m:
                    continue
                flags, conffile, path = m.group(1).strip(), bool(m.group(2)), m.group(3)
                changed.append(path)
                real = os.path.realpath(fs_root / path.lstrip("/"))
                if not conffile and (real in critical or path in critical):
                    c.add("dpkg_verify_critical", "blocking", "critical init file differs from the package database",
                          "dpkg --verify", path=path, observed=flags, expected="checksum in dpkg database",
                          packages=installed)
                elif conffile:
                    c.add("dpkg_verify_conffile", "info", "configuration file changed: %s" % path, "dpkg --verify",
                          path=path, observed=flags)
                else:
                    c.add("dpkg_verify_file", "finding", "packaged file differs: %s" % path, "dpkg --verify",
                          path=path, observed=flags)
            if not changed:
                c.add("dpkg_verify", "ok", "no differences in %s" % ", ".join(installed), "dpkg --verify")
    return {"result": c.result(), "checks": c.items, "pid1": pid1,
            "note": "dpkg verification is an integrity signal, not proof that the system is uncompromised"}
