# SPDX-License-Identifier: GPL-3.0-or-later
"""Process self-restriction applied inside a worker before it reads input.

Order matters: privileges are dropped first, then resource limits are
lowered, then the process is made non-dumpable and NO_NEW_PRIVS is set.
Only after every step has succeeded and been verified does the worker read
its (untrusted) request.  Any failure aborts the worker: there is no
"degraded" mode.

Not implemented yet (see ROADMAP.md, planned hardening): seccomp filters,
Landlock filesystem restriction and network namespaces.  Those need
validation on the target MX kernel before they can be relied on.
"""

from __future__ import annotations

import ctypes
import os
import resource
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..common.errors import SecurityViolation
from . import schema as S

PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39

UID_MAX = 2 ** 32 - 2

PROFILE_SPEC = S.Obj({
    "name": S.Str(pattern=r"[a-z][a-z0-9_.-]{0,63}", max_len=64),
    "cpu_seconds": S.Int(min_value=1, max_value=3600),
    "memory_bytes": S.Int(min_value=64 * 1024 * 1024, max_value=16 * 1024 ** 3),
    "max_open_files": S.Int(min_value=8, max_value=4096),
    "max_file_size": S.Int(min_value=0, max_value=2 ** 40),
    "allow_subprocess": S.Bool(),
    "run_as_uid": S.Nullable(S.Int(min_value=1, max_value=UID_MAX)),
    "run_as_gid": S.Nullable(S.Int(min_value=1, max_value=UID_MAX)),
    "io_timeout": S.Int(min_value=1, max_value=3600),
    "test_handlers": S.Bool(),
})


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    cpu_seconds: int
    memory_bytes: int
    max_open_files: int
    max_file_size: int
    allow_subprocess: bool
    run_as_uid: Optional[int]
    run_as_gid: Optional[int]
    io_timeout: int
    test_handlers: bool

    @classmethod
    def from_document(cls, doc: Any) -> "SandboxProfile":
        checked = S.validate(PROFILE_SPEC, doc)
        if (checked["run_as_uid"] is None) != (checked["run_as_gid"] is None):
            raise SecurityViolation("run_as_uid and run_as_gid must be set together", code="SANDBOX_FAILED")
        return cls(**checked)

    def to_document(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _libc() -> Any:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
    except (OSError, AttributeError):
        raise SecurityViolation("prctl is unavailable", code="SANDBOX_FAILED") from None
    prctl.restype = ctypes.c_int
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    return prctl


def prctl(option: int, arg2: int = 0) -> int:
    rc = _libc()(option, arg2, 0, 0, 0)
    if rc < 0:
        err = ctypes.get_errno()
        raise SecurityViolation("prctl(%d) failed: %s" % (option, os.strerror(err)), code="SANDBOX_FAILED")
    return rc


def _drop_privileges(uid: int, gid: int) -> None:
    try:
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
    except OSError as exc:
        raise SecurityViolation("cannot drop privileges: %s" % exc.strerror, code="SANDBOX_FAILED") from None
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
        raise SecurityViolation("privilege drop did not take effect", code="SANDBOX_FAILED")
    try:
        os.setresuid(0, 0, 0)
    except PermissionError:
        pass
    else:
        raise SecurityViolation("root could be regained after the privilege drop", code="SANDBOX_FAILED")


def _lower_limit(which: int, soft: int, hard: Optional[int] = None) -> None:
    hard = soft if hard is None else hard
    cur_soft, cur_hard = resource.getrlimit(which)
    if cur_hard != resource.RLIM_INFINITY:
        hard = min(hard, cur_hard)
    soft = min(soft, hard)
    resource.setrlimit(which, (soft, hard))
    if resource.getrlimit(which) != (soft, hard):
        raise SecurityViolation("resource limit %d did not take effect" % which, code="SANDBOX_FAILED")


def apply(profile: SandboxProfile) -> None:
    """Restrict the current process.  Raises SecurityViolation on any failure."""
    os.umask(0o077)
    if profile.run_as_uid is not None and profile.run_as_gid is not None:
        if os.geteuid() == 0:
            _drop_privileges(profile.run_as_uid, profile.run_as_gid)
        elif os.getresuid() != (profile.run_as_uid,) * 3:
            raise SecurityViolation("worker started with an unexpected uid", code="SANDBOX_FAILED")
    if os.geteuid() == 0 or os.getuid() == 0 or 0 in os.getresuid():
        # Untrusted input is never parsed as root.
        raise SecurityViolation("worker would run as root", code="WORKER_RUNS_AS_ROOT")
    try:
        _lower_limit(resource.RLIMIT_CORE, 0)
        _lower_limit(resource.RLIMIT_CPU, profile.cpu_seconds, profile.cpu_seconds + 1)
        _lower_limit(resource.RLIMIT_AS, profile.memory_bytes)
        _lower_limit(resource.RLIMIT_NOFILE, profile.max_open_files)
        _lower_limit(resource.RLIMIT_FSIZE, profile.max_file_size)
        if not profile.allow_subprocess:
            _lower_limit(resource.RLIMIT_NPROC, 0)
    except (OSError, ValueError) as exc:
        raise SecurityViolation("cannot set resource limits: %s" % exc, code="SANDBOX_FAILED") from None
    prctl(PR_SET_DUMPABLE, 0)
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    if prctl(PR_GET_NO_NEW_PRIVS) != 1 or prctl(PR_GET_DUMPABLE) != 0:
        raise SecurityViolation("process flags did not take effect", code="SANDBOX_FAILED")


def make_non_dumpable() -> None:
    """Used by the broker on itself: blocks same-uid ptrace and core dumps."""
    prctl(PR_SET_DUMPABLE, 0)
