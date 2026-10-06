# SPDX-License-Identifier: GPL-3.0-or-later
"""External tools: located only in root-owned system directories, never via PATH."""

from __future__ import annotations

import os
import re
import stat
from typing import Optional

from .errors import GuardianError

TOOL_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
SAFE_ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}


class ToolMissing(GuardianError):
    code = "TOOL_MISSING"


def _trusted_dir(path: str) -> bool:
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


def find_tool(name: str) -> Optional[str]:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("invalid tool name")
    for directory in TOOL_DIRS:
        if not _trusted_dir(directory):
            continue
        candidate = os.path.join(directory, name)
        try:
            st = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and st.st_uid == 0 and not st.st_mode & 0o022:
            return candidate
    return None


def require_tool(name: str) -> str:
    path = find_tool(name)
    if path is None:
        raise ToolMissing("required tool %s not found in trusted system directories" % name)
    return path
