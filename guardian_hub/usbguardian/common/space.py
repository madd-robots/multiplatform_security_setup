# SPDX-License-Identifier: GPL-3.0-or-later
"""Free-space checks (ROADMAP D8).

Every Guardian operation that writes data checks, before it starts, that
the target filesystem keeps a reserve after the write. It re-checks while
writing, so a disk that someone fills during a long operation is noticed
instead of hitting ENOSPC part-way. A refusal is a clean, early error with
nothing written. A mid-operation stop cleans up like any other failure
(nothing is released, and partial custody copies and staging are removed).

Only space available to unprivileged users (``f_bavail``) is counted, so
a root broker never eats into the blocks the filesystem keeps for root.
Inodes are checked too, because filling a disk with empty files is as
effective as filling it with data. Filesystems that report no inode
counts (FAT, exFAT) skip the inode check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Union

from .errors import ResourceLimitExceeded

MIB = 1024 * 1024
GIB = 1024 * MIB
CHECK_INTERVAL = 64 * MIB
PER_FILE_OVERHEAD = 64 * 1024  # directory entries, inode tables, journal

StatvfsFn = Callable[[Union[int, str, "os.PathLike[str]"]], Any]


class InsufficientSpace(ResourceLimitExceeded):
    code = "INSUFFICIENT_SPACE"


@dataclass(frozen=True)
class SpacePolicy:
    """Reserve kept free after any Guardian write.

    The byte reserve is the largest of ``reserve_bytes`` and
    ``reserve_fraction_ppm`` of the filesystem (capped at
    ``reserve_cap_bytes``), so small sticks and large disks both keep
    headroom.
    """

    reserve_bytes: int = 128 * MIB
    reserve_fraction_ppm: int = 10_000  # 1 %
    reserve_cap_bytes: int = 4 * GIB
    reserve_inodes: int = 1024
    check_interval: int = CHECK_INTERVAL  # bytes between re-checks during a write
    statvfs: Optional[StatvfsFn] = None  # injectable for tests

    def __post_init__(self) -> None:
        if min(self.reserve_bytes, self.reserve_fraction_ppm, self.reserve_cap_bytes, self.reserve_inodes) < 0 \
                or self.reserve_fraction_ppm > 1_000_000 or self.check_interval < 4096:
            raise ValueError("invalid space policy")


DEFAULT_POLICY = SpacePolicy()


def space_report(target: Union[int, str, "os.PathLike[str]"], policy: SpacePolicy = DEFAULT_POLICY) -> Dict[str, int]:
    fn = policy.statvfs or (os.fstatvfs if isinstance(target, int) else os.statvfs)
    st = fn(target)
    total = st.f_blocks * st.f_frsize
    fraction = min(total * policy.reserve_fraction_ppm // 1_000_000, policy.reserve_cap_bytes)
    return {
        "available_bytes": st.f_bavail * st.f_frsize,
        "total_bytes": total,
        "reserve_bytes": max(policy.reserve_bytes, fraction),
        "available_inodes": st.f_favail,
        "total_inodes": st.f_files,
        "reserve_inodes": policy.reserve_inodes,
    }


def require_space(target: Union[int, str, "os.PathLike[str]"], needed_bytes: int, *, files: int = 1,
                  what: str = "write", policy: SpacePolicy = DEFAULT_POLICY) -> Dict[str, int]:
    """Raise InsufficientSpace unless ``needed_bytes`` (+ overhead) fits and the reserve remains."""
    if needed_bytes < 0 or files < 0:
        raise ValueError("negative space request")
    report = space_report(target, policy)
    needed = needed_bytes + files * PER_FILE_OVERHEAD
    if report["available_bytes"] - needed < report["reserve_bytes"]:
        raise InsufficientSpace(
            "not enough free space for %s: %d MiB needed plus a %d MiB reserve, %d MiB available"
            % (what, -(-needed // MIB), report["reserve_bytes"] // MIB, report["available_bytes"] // MIB))
    if report["total_inodes"] > 0 and report["available_inodes"] - files < report["reserve_inodes"]:
        raise InsufficientSpace("not enough free inodes for %s (%d available, %d reserved)"
                                % (what, report["available_inodes"], report["reserve_inodes"]))
    return report


class SpaceGuard:
    """Re-checks free space while a long write runs.

    ``remaining`` is the number of bytes still to be written when known
    (None for a stream of unknown length). Each check requires that the
    remaining bytes still fit above the reserve.
    """

    def __init__(self, target: Union[int, str, "os.PathLike[str]"], *, total: Optional[int], what: str,
                 policy: SpacePolicy = DEFAULT_POLICY):
        self.target = target
        self.total = total
        self.what = what
        self.policy = policy
        self.interval = policy.check_interval
        self.written = 0
        self._next_check = self.interval

    def start(self, files: int = 1) -> None:
        require_space(self.target, self.total or 0, files=files, what=self.what, policy=self.policy)

    def advance(self, nbytes: int) -> None:
        self.written += nbytes
        if self.written >= self._next_check:
            self._next_check = self.written + self.interval
            remaining = max(0, self.total - self.written) if self.total is not None else 0
            require_space(self.target, remaining, files=0, what=self.what, policy=self.policy)
