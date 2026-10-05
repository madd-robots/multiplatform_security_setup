# SPDX-License-Identifier: GPL-3.0-or-later
"""Misbehaving handlers used only by the test suite.

They are registered only when the broker-side launcher was created with
``enable_test_handlers=True`` (never by the CLI).  Each one simulates a
hostile or broken parser so the tests can show that the sandbox and the
broker contain it.
"""

from __future__ import annotations

import os
import struct
import time
from typing import Any, Dict

from . import schema as S
from .handlers import Handler, register

TEST_REGISTRY: Dict[str, Handler] = {}


@register("test.spin", S.EMPTY, TEST_REGISTRY)
def _spin(params: Dict[str, Any]) -> Any:
    while True:
        pass


@register("test.sleep", S.Obj({"seconds": S.Int(min_value=0, max_value=600)}), TEST_REGISTRY)
def _sleep(params: Dict[str, Any]) -> Any:
    time.sleep(params["seconds"])
    return {"slept": params["seconds"]}


@register("test.allocate", S.Obj({"mib": S.Int(min_value=1, max_value=65536)}), TEST_REGISTRY)
def _allocate(params: Dict[str, Any]) -> Any:
    block = bytearray(params["mib"] * 1024 * 1024)
    return {"allocated": len(block)}


@register("test.flood", S.Obj({"mib": S.Int(min_value=1, max_value=1024)}), TEST_REGISTRY)
def _flood(params: Dict[str, Any]) -> Any:
    chunk = b"A" * 65536
    for _ in range(params["mib"] * 16):
        os.write(1, chunk)
    return {}


@register("test.stderr_flood", S.Obj({"mib": S.Int(min_value=1, max_value=1024)}), TEST_REGISTRY)
def _stderr_flood(params: Dict[str, Any]) -> Any:
    chunk = b"\x1b[31mE" * 10000
    for _ in range(params["mib"] * 20):
        os.write(2, chunk)
    return {}


@register("test.write_file", S.Obj({"path": S.Str(min_len=1, max_len=4096)}), TEST_REGISTRY)
def _write_file(params: Dict[str, Any]) -> Any:
    with open(params["path"], "wb") as fh:
        fh.write(b"written by worker")
    return {"written": True}


@register("test.fork", S.EMPTY, TEST_REGISTRY)
def _fork(params: Dict[str, Any]) -> Any:
    try:
        pid = os.fork()
    except OSError as exc:
        return {"forked": False, "errno": exc.errno}
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    return {"forked": True}


@register("test.raise", S.EMPTY, TEST_REGISTRY)
def _raise(params: Dict[str, Any]) -> Any:
    raise KeyError("secret-internal-detail")


@register("test.garbage", S.EMPTY, TEST_REGISTRY)
def _garbage(params: Dict[str, Any]) -> Any:
    payload = b'{"ok":true,"result":1,"ok":false}'
    os.write(1, struct.pack(">I", len(payload)) + payload)
    os._exit(0)


@register("test.exit", S.Obj({"code": S.Int(min_value=0, max_value=255)}), TEST_REGISTRY)
def _exit(params: Dict[str, Any]) -> Any:
    os._exit(params["code"])


@register("test.extra_frame", S.EMPTY, TEST_REGISTRY)
def _extra_frame(params: Dict[str, Any]) -> Any:
    payload = b'{"ok":true,"result":"forged"}'
    os.write(1, struct.pack(">I", len(payload)) + payload)
    return "second"


@register("test.regain_root", S.EMPTY, TEST_REGISTRY)
def _regain_root(params: Dict[str, Any]) -> Any:
    try:
        os.setresuid(0, 0, 0)
    except PermissionError:
        return {"regained": False}
    return {"regained": True}
