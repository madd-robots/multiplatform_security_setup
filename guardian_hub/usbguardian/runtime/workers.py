# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker side of worker isolation: spawn, feed, bound, collect, kill.

One fresh process per job.  Nothing is reused between jobs, so a worker
compromised by hostile input cannot affect the next one.  Worker output is
treated as untrusted: it must be exactly one canonical frame within the size
limit, produced before the wall-clock deadline, by a process that exits 0.
"""

from __future__ import annotations

import fcntl
import logging
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from ..common.canonical import canonical_dumps
from ..common.errors import (ConfigError, GuardianError, OperationTimeout, ProtocolError,
                             ResourceLimitExceeded, SecurityViolation, WorkerFailure, error_from_wire)
from ..common.fsutil import check_trusted_file
from ..common.log import get_logger, log_event
from ..common.text import display_text
from . import ipc
from . import schema as S
from .sandbox import SandboxProfile

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
WORKER_ENTRY = Path(__file__).resolve().parent / "_worker_entry.py"
WORKER_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
MAX_STDERR = 16 * 1024

WORKER_OK_SPEC = S.Obj({"ok": S.Const(True), "result": S.Any_()})
WORKER_ERR_SPEC = S.Obj({"ok": S.Const(False), "error": ipc.ERROR_SPEC})


@dataclass(frozen=True)
class WorkerProfile:
    """Per-operation limits.  The defaults suit metadata parsers."""

    name: str
    cpu_seconds: int = 5
    memory_bytes: int = 512 * 1024 * 1024
    max_open_files: int = 32
    max_file_size: int = 0
    allow_subprocess: bool = False
    wall_timeout: float = 15.0
    max_output: int = ipc.MAX_FRAME


def verify_code_tree(root: Path) -> None:
    """A root broker must only execute code that only root can modify."""
    check_trusted_file(root, allowed_owners=(0,))
    def unreadable(exc: OSError) -> None:
        raise SecurityViolation("cannot inspect code tree: %s" % exc.strerror, code="UNTRUSTED_PATH")

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable, followlinks=False):
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(st.st_mode):
                raise SecurityViolation("symlink in code tree: %s" % display_text(name), code="UNTRUSTED_PATH")
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise SecurityViolation("code file %s is not root-owned and protected" % display_text(name),
                                        code="UNTRUSTED_PATH")


def _kill_group(proc: "subprocess.Popen[bytes]") -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.kill()
    except OSError:
        pass
    proc.wait()


class WorkerLauncher:
    def __init__(self, *, worker_uid: Optional[int] = None, worker_gid: Optional[int] = None,
                 python: str = sys.executable, enable_test_handlers: bool = False,
                 logger: Optional[logging.Logger] = None):
        self.logger = logger or get_logger("workers")
        if (worker_uid is None) != (worker_gid is None):
            raise ConfigError("worker uid and gid must be given together")
        # Resolve once and execute the resolved path, so a later symlink
        # change cannot swap the interpreter.
        python = os.path.realpath(python)
        if os.geteuid() == 0:
            if worker_uid is None:
                raise ConfigError("a root broker needs a dedicated unprivileged worker user")
            verify_code_tree(PACKAGE_ROOT)
            check_trusted_file(Path(python), allowed_owners=(0,))
        elif worker_uid is not None and worker_uid != os.geteuid():
            raise ConfigError("only a root broker can run workers as another user")
        if worker_uid == 0 or worker_gid == 0:
            raise ConfigError("workers must not run as root")
        self.worker_uid = worker_uid if os.geteuid() == 0 else None
        self.worker_gid = worker_gid if os.geteuid() == 0 else None
        self.python = python
        self.enable_test_handlers = enable_test_handlers

    def _sandbox_profile(self, profile: WorkerProfile) -> SandboxProfile:
        return SandboxProfile(
            name=profile.name, cpu_seconds=profile.cpu_seconds, memory_bytes=profile.memory_bytes,
            max_open_files=profile.max_open_files, max_file_size=profile.max_file_size,
            allow_subprocess=profile.allow_subprocess, run_as_uid=self.worker_uid, run_as_gid=self.worker_gid,
            io_timeout=max(1, int(profile.wall_timeout)), test_handlers=self.enable_test_handlers)

    def run(self, profile: WorkerProfile, handler: str, params: Dict[str, Any], *,
            fds: Tuple[int, ...] = ()) -> Any:
        """Run one job.  ``fds`` are inherited by the worker under the same numbers.

        Pass only descriptors opened read-only for exactly the data the job
        needs (for example quarantined files); the handler's parameters
        name them.
        """
        for fd in fds:
            if not isinstance(fd, int) or fd < 3 or fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                raise ValueError("workers receive only read-only descriptors")
        sandbox_doc = canonical_dumps(self._sandbox_profile(profile).to_document()).decode("utf-8")
        request = ipc.encode_frame({"handler": handler, "params": params})
        argv = [self.python, "-I", "-B", "-S", str(WORKER_ENTRY), sandbox_doc]
        started = time.monotonic()
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    env=dict(WORKER_ENV), cwd="/", close_fds=True, pass_fds=tuple(fds),
                                    start_new_session=True, shell=False)
        except OSError as exc:
            raise WorkerFailure("worker could not be started: %s" % exc.strerror) from None
        try:
            out, err = self._exchange(proc, request, started + profile.wall_timeout, profile.max_output + 4)
        except BaseException:
            _kill_group(proc)
            raise
        rc = proc.returncode
        if err:
            log_event(self.logger, logging.WARNING, "worker.stderr", handler=handler, returncode=rc,
                      stderr=display_text(err[:2000], 2000))
        return self._interpret(rc, out)

    def _exchange(self, proc: "subprocess.Popen[bytes]", data: bytes, deadline: float,
                  max_out: int) -> Tuple[bytes, bytes]:
        assert proc.stdin and proc.stdout and proc.stderr
        sel = selectors.DefaultSelector()
        pending = memoryview(data)
        out = bytearray()
        err = bytearray()
        for f in (proc.stdin, proc.stdout, proc.stderr):
            os.set_blocking(f.fileno(), False)
        sel.register(proc.stdin, selectors.EVENT_WRITE)
        sel.register(proc.stdout, selectors.EVENT_READ)
        sel.register(proc.stderr, selectors.EVENT_READ)
        try:
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise OperationTimeout("worker did not finish in time")
                for key, _ in sel.select(remaining):
                    f = key.fileobj
                    if f is proc.stdin:
                        try:
                            written = os.write(proc.stdin.fileno(), pending[:65536])
                            pending = pending[written:]
                        except BrokenPipeError:
                            pending = pending[:0]
                        except BlockingIOError:
                            continue
                        if not pending:
                            sel.unregister(proc.stdin)
                            proc.stdin.close()
                        continue
                    try:
                        chunk = os.read(f.fileno(), 65536)  # type: ignore[union-attr]
                    except BlockingIOError:
                        continue
                    if not chunk:
                        sel.unregister(f)
                        continue
                    if f is proc.stdout:
                        out += chunk
                        if len(out) > max_out:
                            raise ResourceLimitExceeded("worker output exceeded %d bytes" % max_out)
                    elif len(err) < MAX_STDERR:
                        err += chunk[:MAX_STDERR - len(err)]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OperationTimeout("worker did not finish in time")
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise OperationTimeout("worker did not exit in time") from None
        finally:
            sel.close()
            for f in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    f.close()
                except OSError:
                    pass
        return bytes(out), bytes(err)

    @staticmethod
    def _interpret(rc: int, out: bytes) -> Any:
        if rc < 0:
            sig = -rc
            if sig == signal.SIGXCPU:
                raise ResourceLimitExceeded("worker exceeded its CPU limit")
            if sig == signal.SIGKILL:
                raise ResourceLimitExceeded("worker was killed (hard CPU limit or out of memory)")
            if sig == signal.SIGXFSZ:
                raise ResourceLimitExceeded("worker exceeded its file size limit")
            raise WorkerFailure("worker terminated by signal %d" % sig)
        if rc != 0:
            raise WorkerFailure("worker exited with status %d" % rc)
        if len(out) < ipc.HEADER.size:
            raise WorkerFailure("worker produced no response")
        (length,) = ipc.HEADER.unpack(out[:ipc.HEADER.size])
        if length == 0 or len(out) != ipc.HEADER.size + length:
            raise ProtocolError("worker output is not exactly one frame")
        message = ipc.decode_payload(out[ipc.HEADER.size:])
        try:
            if isinstance(message, dict) and message.get("ok") is True:
                return S.validate(WORKER_OK_SPEC, message)["result"]
            error = S.validate(WORKER_ERR_SPEC, message)["error"]
        except GuardianError as exc:
            raise ProtocolError("invalid worker response: %s" % exc.message) from None
        raise error_from_wire(error)
