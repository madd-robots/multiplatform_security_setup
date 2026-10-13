# SPDX-License-Identifier: GPL-3.0-or-later
"""IPC wire protocol.

A frame is a 4-byte big-endian length followed by that many bytes of
canonical JSON.  The same framing is used on the client socket and on worker
pipes.  Peers are untrusted: frames are size-bounded, read against a
deadline, strictly decoded and must be canonical.

Request:   {"v": 1, "type": "request", "id": ID, "op": OP, "params": {...}}
Response:  {"v": 1, "type": "response", "id": ID, "ok": true, "result": ...}
           {"v": 1, "type": "response", "id": ID, "ok": false,
            "error": {"code": CODE, "message": TEXT}}
"""

from __future__ import annotations

import os
import select
import socket
import struct
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import (ConfigError, GuardianError, OperationTimeout, ProtocolError,
                             ResourceLimitExceeded, ValidationError)
from . import schema as S

PROTOCOL_VERSION = 1
MAX_FRAME = 1024 * 1024
HEADER = struct.Struct(">I")
REQUEST_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
OP_PATTERN = r"[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){1,3}"
# File descriptors (SCM_RIGHTS) a client may pass with one request, e.g. a
# file to take into custody. The broker uses them with the access the
# client opened them with, and never opens client-supplied paths itself.
MAX_FDS = 16

REQUEST_SPEC = S.Obj({
    "v": S.Const(PROTOCOL_VERSION),
    "type": S.Const("request"),
    "id": S.Str(pattern=REQUEST_ID_PATTERN, max_len=64),
    "op": S.Str(pattern=OP_PATTERN, max_len=130),
    "params": S.Obj({}, allow_extra=True),
    "fds": S.Int(min_value=1, max_value=MAX_FDS),
}, optional=["fds"])

ERROR_SPEC = S.Obj({
    "code": S.Str(pattern=r"[A-Z][A-Z0-9_]{2,63}", max_len=64),
    "message": S.Str(max_len=4000),
})

_RESPONSE_BASE = {
    "v": S.Const(PROTOCOL_VERSION),
    "type": S.Const("response"),
    "id": S.Str(pattern=REQUEST_ID_PATTERN, max_len=64),
}
OK_RESPONSE_SPEC = S.Obj(dict(_RESPONSE_BASE, ok=S.Const(True), result=S.Any_()))
ERR_RESPONSE_SPEC = S.Obj(dict(_RESPONSE_BASE, ok=S.Const(False), error=ERROR_SPEC))


# sun_path is 108 bytes on Linux, including the terminating NUL.
MAX_SOCKET_PATH = 107


def check_socket_path(path: "os.PathLike[str]") -> None:
    if len(os.fsencode(path)) > MAX_SOCKET_PATH:
        raise ConfigError("socket path is longer than %d bytes" % MAX_SOCKET_PATH)


class ConnectionClosed(GuardianError):
    code = "CONNECTION_CLOSED"


def _wait(fd: int, writable: bool, deadline: Optional[float]) -> None:
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OperationTimeout("IPC peer did not respond in time")
    poller = select.poll()
    poller.register(fd, select.POLLOUT if writable else select.POLLIN)
    if not poller.poll(int(remaining * 1000) + 1):
        raise OperationTimeout("IPC peer did not respond in time")


def _read_exact(fd: int, n: int, deadline: Optional[float], allow_eof: bool) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        _wait(fd, False, deadline)
        try:
            chunk = os.read(fd, min(65536, n - len(buf)))
        except BlockingIOError:
            continue
        except ConnectionResetError:
            chunk = b""
        if not chunk:
            if allow_eof and not buf:
                return None
            raise ProtocolError("peer closed the connection mid-frame")
        buf += chunk
    return bytes(buf)


def encode_frame(message: Any, max_frame: int = MAX_FRAME) -> bytes:
    payload = canonical_dumps(message)
    if len(payload) > max_frame:
        raise ResourceLimitExceeded("message larger than %d bytes" % max_frame)
    return HEADER.pack(len(payload)) + payload


def send_frame(fd: int, message: Any, *, timeout: Optional[float] = None, max_frame: int = MAX_FRAME) -> None:
    data = memoryview(encode_frame(message, max_frame))
    deadline = None if timeout is None else time.monotonic() + timeout
    while data:
        _wait(fd, True, deadline)
        try:
            written = os.write(fd, data)
        except BlockingIOError:
            continue
        except (BrokenPipeError, ConnectionResetError):
            raise ConnectionClosed("peer closed the connection") from None
        data = data[written:]


def decode_payload(payload: bytes) -> Any:
    try:
        return canonical_loads(payload, max_bytes=len(payload), require_canonical=True)
    except (ValidationError, ResourceLimitExceeded) as exc:
        raise ProtocolError("invalid frame: %s" % exc.message) from None


def recv_frame(fd: int, *, timeout: Optional[float] = None, max_frame: int = MAX_FRAME,
               allow_eof: bool = False) -> Any:
    """Read one frame.  Returns None only on clean EOF when ``allow_eof``."""
    deadline = None if timeout is None else time.monotonic() + timeout
    header = _read_exact(fd, HEADER.size, deadline, allow_eof)
    if header is None:
        return None
    (length,) = HEADER.unpack(header)
    if length == 0 or length > max_frame:
        raise ProtocolError("frame length %d outside 1..%d" % (length, max_frame))
    payload = _read_exact(fd, length, deadline, False)
    assert payload is not None
    return decode_payload(payload)


def make_request(request_id: str, op: str, params: Dict[str, Any], fds: int = 0) -> Dict[str, Any]:
    request = {"v": PROTOCOL_VERSION, "type": "request", "id": request_id, "op": op, "params": params}
    if fds:
        request["fds"] = fds
    return S.validate(REQUEST_SPEC, request)


def _close_all(fds: List[int]) -> None:
    for fd in fds:
        try:
            os.close(fd)
        except OSError:
            pass


def recv_frame_fds(sock: socket.socket, *, timeout: Optional[float] = None, max_frame: int = MAX_FRAME,
                   allow_eof: bool = False) -> Tuple[Any, List[int]]:
    """Read one frame plus any descriptors sent with its first bytes.

    Returns (None, []) on clean EOF when ``allow_eof``. Received descriptors
    are closed on every error path, so a malformed request cannot leak them.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    fd = sock.fileno()
    _wait(fd, False, deadline)
    try:
        head, fds, flags, _ = socket.recv_fds(sock, HEADER.size, MAX_FDS)
    except ConnectionResetError:
        head, fds, flags = b"", [], 0
    try:
        if flags & socket.MSG_CTRUNC:
            raise ProtocolError("too many file descriptors in one request")
        if not head:
            if allow_eof and not fds:
                return None, []
            raise ProtocolError("peer closed the connection mid-frame")
        rest = _read_exact(fd, HEADER.size - len(head), deadline, False) if len(head) < HEADER.size else b""
        (length,) = HEADER.unpack(head + (rest or b""))
        if length == 0 or length > max_frame:
            raise ProtocolError("frame length %d outside 1..%d" % (length, max_frame))
        payload = _read_exact(fd, length, deadline, False)
        assert payload is not None
        return decode_payload(payload), list(fds)
    except BaseException:
        _close_all(list(fds))
        raise


def send_frame_fds(sock: socket.socket, message: Any, fds: Sequence[int], *,
                   timeout: Optional[float] = None) -> None:
    if not fds:
        send_frame(sock.fileno(), message, timeout=timeout)
        return
    if len(fds) > MAX_FDS:
        raise ValidationError("too many file descriptors")
    data = encode_frame(message)
    deadline = None if timeout is None else time.monotonic() + timeout
    _wait(sock.fileno(), True, deadline)
    sent = socket.send_fds(sock, [data], list(fds))
    view = memoryview(data)[sent:]
    while view:
        _wait(sock.fileno(), True, deadline)
        view = view[os.write(sock.fileno(), view):]


def ok_response(request_id: str, result: Any) -> Dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "response", "id": request_id, "ok": True, "result": result}


def error_response(request_id: str, error: GuardianError) -> Dict[str, Any]:
    return {"v": PROTOCOL_VERSION, "type": "response", "id": request_id, "ok": False, "error": error.to_wire()}


def validate_response(message: Any) -> Dict[str, Any]:
    try:
        if isinstance(message, dict) and message.get("ok") is True:
            return S.validate(OK_RESPONSE_SPEC, message)
        return S.validate(ERR_RESPONSE_SPEC, message)
    except ValidationError as exc:
        raise ProtocolError("invalid response: %s" % exc.message) from None
