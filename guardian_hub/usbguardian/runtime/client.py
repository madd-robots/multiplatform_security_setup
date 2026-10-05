# SPDX-License-Identifier: GPL-3.0-or-later
"""Client for the broker socket (used by the CLI and, later, the UI)."""

from __future__ import annotations

import secrets
import socket
from pathlib import Path
from typing import Any, Dict, Optional

from ..common.errors import ProtocolError, error_from_wire
from . import ipc


class BrokerClient:
    def __init__(self, socket_path: Path, *, timeout: float = 60.0):
        ipc.check_socket_path(Path(socket_path))
        self.socket_path = Path(socket_path)
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    def __enter__(self) -> "BrokerClient":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            sock.settimeout(self.timeout)
            sock.connect(str(self.socket_path))
            sock.setblocking(True)
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def call(self, op: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if self._sock is None:
            self.connect()
        assert self._sock is not None
        request_id = secrets.token_hex(8)
        fd = self._sock.fileno()
        ipc.send_frame(fd, ipc.make_request(request_id, op, params or {}), timeout=self.timeout)
        message = ipc.recv_frame(fd, timeout=self.timeout, allow_eof=True)
        if message is None:
            raise ProtocolError("broker closed the connection")
        response = ipc.validate_response(message)
        if response["id"] not in (request_id, "connect", "invalid"):
            raise ProtocolError("response does not match the request")
        if not response["ok"]:
            raise error_from_wire(response["error"])
        if response["id"] != request_id:
            raise ProtocolError("response does not match the request")
        return response["result"]
