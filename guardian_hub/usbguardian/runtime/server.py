# SPDX-License-Identifier: GPL-3.0-or-later
"""Unix-socket front end of the broker.

The client's identity comes from SO_PEERCRED (the kernel), never from the
request.  A uid without a policy entry is refused before any request is read.
Connections are bounded in number, idle time and frame size.
"""

from __future__ import annotations

import logging
import os
import socket
import stat
import struct
import threading
from pathlib import Path
from typing import Optional, Tuple

from ..common.errors import (GuardianError, OperationTimeout, PermissionDenied, SecurityViolation,
                             as_guardian_error)
from ..common.log import get_logger, log_event
from ..common.text import display_text
from . import ipc
from .authz import Policy
from .broker import Broker
from .session import Session

_PEERCRED = struct.Struct("iII")


def peer_credentials(conn: socket.socket) -> Tuple[int, int, int]:
    pid, uid, gid = _PEERCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEERCRED.size))
    return pid, uid, gid


def _check_socket_dir(directory: Path) -> None:
    try:
        st = os.lstat(directory)
    except OSError as exc:
        raise SecurityViolation("socket directory %s: %s" % (display_text(directory), exc.strerror),
                                code="UNTRUSTED_PATH") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise SecurityViolation("socket directory %s must be a directory owned by the broker user and not "
                                "writable by others" % display_text(directory), code="UNTRUSTED_PATH")


class BrokerServer:
    def __init__(self, broker: Broker, policy: Policy, socket_path: Path, *, socket_mode: int = 0o600,
                 max_connections: int = 16, idle_timeout: float = 30.0, logger: Optional[logging.Logger] = None):
        if socket_mode & 0o111 or socket_mode & ~0o777:
            raise ValueError("invalid socket mode")
        ipc.check_socket_path(Path(socket_path))
        self.broker = broker
        self.policy = policy
        self.socket_path = Path(socket_path)
        self.socket_mode = socket_mode
        self.idle_timeout = idle_timeout
        self.logger = logger or get_logger("server")
        self._slots = threading.BoundedSemaphore(max_connections)
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None

    def bind(self) -> None:
        _check_socket_dir(self.socket_path.parent)
        try:
            st = os.lstat(self.socket_path)
        except FileNotFoundError:
            st = None
        if st is not None:
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid != os.geteuid():
                raise SecurityViolation("%s exists and is not a stale broker socket" % display_text(self.socket_path),
                                        code="UNTRUSTED_PATH")
            os.unlink(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        old_umask = os.umask(0o177)
        try:
            sock.bind(str(self.socket_path))
        finally:
            os.umask(old_umask)
        os.chmod(self.socket_path, self.socket_mode)
        sock.listen(16)
        sock.settimeout(0.5)
        self._sock = sock
        log_event(self.logger, logging.INFO, "server.listening", socket=str(self.socket_path))

    def serve_forever(self) -> None:
        if self._sock is None:
            self.bind()
        assert self._sock is not None
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = self._sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                if not self._slots.acquire(blocking=False):
                    log_event(self.logger, logging.WARNING, "server.connection_rejected", reason="too_many")
                    conn.close()
                    continue
                try:
                    threading.Thread(target=self._serve_connection, args=(conn,), daemon=True).start()
                except RuntimeError:
                    conn.close()
                    self._slots.release()
        finally:
            self.close()

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()
            try:
                st = os.lstat(self.socket_path)
                if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid():
                    os.unlink(self.socket_path)
            except OSError:
                pass

    def _serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.setblocking(True)
            fd = conn.fileno()
            pid, uid, gid = peer_credentials(conn)
            principal = self.policy.principal_for_uid(uid)
            if principal is None:
                log_event(self.logger, logging.WARNING, "server.unknown_peer", uid=uid, pid=pid)
                ipc.send_frame(fd, ipc.error_response("connect", PermissionDenied("uid is not in the broker policy")),
                               timeout=5)
                return
            log_event(self.logger, logging.INFO, "server.connected", principal=principal.name, uid=uid, pid=pid)
            session = Session(uid, gid, pid)
            while not self._stop.is_set():
                try:
                    message, fds = ipc.recv_frame_fds(conn, timeout=self.idle_timeout, allow_eof=True)
                except OperationTimeout:
                    return
                except GuardianError as exc:
                    # Malformed frame: answer once, then drop the connection.
                    log_event(self.logger, logging.WARNING, "server.protocol_error", uid=uid, code=exc.code)
                    ipc.send_frame(fd, ipc.error_response("invalid", exc), timeout=5)
                    return
                if message is None:
                    return
                session.fds = fds
                try:
                    response = self.broker.handle(principal, message, session)
                finally:
                    session.close_fds()  # anything the operation did not take
                ipc.send_frame(fd, response, timeout=self.idle_timeout)
        except Exception as exc:
            err = as_guardian_error(exc)
            log_event(self.logger, logging.WARNING, "server.connection_error", code=err.code)
        finally:
            conn.close()
            self._slots.release()
