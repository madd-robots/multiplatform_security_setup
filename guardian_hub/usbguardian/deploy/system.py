# SPDX-License-Identifier: GPL-3.0-or-later
"""Host facts for the installer: a fixed-tool command runner and platform detection.

Every external command is a tool name resolved in root-owned system
directories (common/tools.py), run without a shell, with a fixed
environment, no stdin and a timeout. Tests replace the runner.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..common.errors import GuardianError
from ..common.tools import SAFE_ENV, find_tool

Result = Tuple[int, str, str]          # (returncode, stdout, stderr); returncode 127: tool missing
Runner = Callable[[List[str]], Result]
MAX_OUTPUT = 4 * 1024 * 1024


def system_runner(argv: List[str], timeout: float = 600.0) -> Result:
    exe = find_tool(argv[0])
    if exe is None:
        return 127, "", "tool %s not found in trusted system directories" % argv[0]
    try:
        proc = subprocess.run([exe] + argv[1:], env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    return (proc.returncode, proc.stdout[:MAX_OUTPUT].decode("utf-8", "replace"),
            proc.stderr[:MAX_OUTPUT].decode("utf-8", "replace"))


def read_small(path: Path, limit: int = 64 * 1024) -> Optional[str]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        return os.read(fd, limit).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def os_release(fs_root: Path) -> Dict[str, str]:
    text = read_small(Path(fs_root) / "etc/os-release") or read_small(Path(fs_root) / "usr/lib/os-release") or ""
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([A-Z_]{1,32})=\"?([^\"\n]{0,128})\"?", line.strip())
        if m:
            out[m.group(1)] = m.group(2)
    return out


def detect_platform(fs_root: Path = Path("/"), run: Runner = system_runner) -> Dict[str, Optional[str]]:
    """{distribution, release, debian, architecture}; None where it cannot be determined."""
    rel = os_release(fs_root)
    mx = read_small(Path(fs_root) / "etc/mx-version") or ""
    m = re.match(r"MX-(\d{1,3})", mx.strip())
    debian = (read_small(Path(fs_root) / "etc/debian_version") or "").strip()
    rc, out, _ = run(["dpkg", "--print-architecture"])
    arch = out.strip() if rc == 0 and re.fullmatch(r"[a-z0-9-]{1,16}", out.strip()) else None
    return {
        "distribution": "mx" if m else (rel.get("ID") or None),
        "release": m.group(1) if m else (rel.get("VERSION_ID") or None),
        "debian": debian.split(".", 1)[0] if re.match(r"\d", debian) else None,
        "architecture": arch,
        "pretty_name": rel.get("PRETTY_NAME"),
    }


class InstallerError(GuardianError):
    code = "INSTALLATION_BLOCKED"
