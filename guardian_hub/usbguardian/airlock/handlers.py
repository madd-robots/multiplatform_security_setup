# SPDX-License-Identifier: GPL-3.0-or-later
"""Airlock worker handlers.  Each runs in a fresh sandboxed worker on read-only descriptors.

    airlock.structure      partition table and boot structures of a whole device
    airlock.inspect_files  static content inspection of quarantined files
    airlock.clamscan       ClamAV over quarantined files (one signal, never proof)

The descriptors are inherited from the broker under the numbers given in
the parameters (runtime/workers.py checks they are read-only).
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Any, Dict, List

from ..common.tools import SAFE_ENV, find_tool
from ..runtime import schema as S
from ..runtime.handlers import Handler, register
from ..runtime.workers import WorkerProfile
from .content import inspect_file
from .structure import fd_reader, inspect_structure

AIRLOCK_REGISTRY: Dict[str, Handler] = {}
MAX_BATCH = 16
FD_SPEC = S.Int(min_value=3, max_value=65535)

STRUCTURE_PROFILE = WorkerProfile(name="airlock-structure", cpu_seconds=10, memory_bytes=256 * 1024 * 1024,
                                  max_open_files=64, wall_timeout=30.0)
CONTENT_PROFILE = WorkerProfile(name="airlock-content", cpu_seconds=60, memory_bytes=1024 * 1024 * 1024,
                                max_open_files=64, wall_timeout=120.0)
# clamscan loads its signature database into memory (about 1 GiB or more).
SCAN_PROFILE = WorkerProfile(name="airlock-clamscan", cpu_seconds=900, memory_bytes=4 * 1024 ** 3,
                             max_open_files=256, allow_subprocess=True, wall_timeout=1200.0)


@register("airlock.structure", S.Obj({"fd": FD_SPEC, "size": S.Int(min_value=0, max_value=2 ** 53 - 1),
                                      "logical_block_size": S.Int(min_value=512, max_value=65536)}),
          AIRLOCK_REGISTRY)
def _structure(params: Dict[str, Any]) -> Any:
    return inspect_structure(fd_reader(params["fd"], params["size"]), params["size"], params["logical_block_size"])


@register("airlock.inspect_files", S.Obj({"files": S.List(S.Obj({"fd": FD_SPEC, "name": S.Str(max_len=255)}),
                                                          min_items=1, max_items=MAX_BATCH)}), AIRLOCK_REGISTRY)
def _inspect(params: Dict[str, Any]) -> Any:
    return {"results": [inspect_file(f["fd"], f["name"]) for f in params["files"]]}


CLAM_LINE = re.compile(r"^/dev/fd/(\d+): (?:(OK)|(.{1,200}) FOUND|(.{0,200}) ERROR)$")


def parse_clamscan(output: str, fds: List[int], returncode: int) -> List[Dict[str, Any]]:
    """Map clamscan's per-file lines to results.  Anything unaccounted for is an error (fail closed)."""
    results: Dict[int, Dict[str, Any]] = {}
    for line in output.splitlines():
        m = CLAM_LINE.match(line.strip())
        if not m:
            continue
        fd = int(m.group(1))
        if m.group(2):
            results[fd] = {"status": "clean", "signature": ""}
        elif m.group(3) is not None:
            results[fd] = {"status": "found", "signature": m.group(3)[:120]}
        else:
            results[fd] = {"status": "error", "signature": (m.group(4) or "")[:120]}
    if returncode not in (0, 1):
        return [{"status": "error", "signature": "clamscan exit status %d" % returncode} for _ in fds]
    out = []
    for fd in fds:
        r = results.get(fd, {"status": "error", "signature": "no result reported"})
        if returncode == 0 and r["status"] == "found":
            r = {"status": "error", "signature": "inconsistent scanner output"}
        out.append(r)
    return out


@register("airlock.clamscan", S.Obj({"fds": S.List(FD_SPEC, min_items=1, max_items=MAX_BATCH, unique=True)}),
          AIRLOCK_REGISTRY)
def _clamscan(params: Dict[str, Any]) -> Any:
    exe = find_tool("clamscan")
    fds = params["fds"]
    if exe is None:
        return {"available": False, "version": "", "results": [{"status": "unavailable", "signature": ""}
                                                                 for _ in fds]}
    version = subprocess.run([exe, "--version"], capture_output=True, env=dict(SAFE_ENV), timeout=60,
                             stdin=subprocess.DEVNULL, check=False).stdout.decode("ascii", "replace").strip()[:120]
    # /dev/fd/N reopens each quarantined file (group-readable by the worker account only).
    argv = [exe, "--no-summary", "--stdout", "--alert-exceeds-max=yes", "--"] + ["/dev/fd/%d" % fd for fd in fds]
    try:
        proc = subprocess.run(argv, capture_output=True, env=dict(SAFE_ENV), timeout=1100, pass_fds=tuple(fds),
                              stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        return {"available": True, "version": version, "results": [{"status": "error", "signature": "timeout"}
                                                                    for _ in fds]}
    return {"available": True, "version": version,
            "results": parse_clamscan(proc.stdout.decode("utf-8", "replace"), fds, proc.returncode)}


def close_quietly(fds: List[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass
