# SPDX-License-Identifier: GPL-3.0-or-later
"""Worker handler registry.

Handlers run inside a sandboxed worker.  They are looked up by name in a
fixed table, never imported by a name taken from a request.  Later stages
(device analysis, vault parsing) register their parsers here.
"""

from __future__ import annotations

import os
import resource
from dataclasses import dataclass
from typing import Any, Callable, Dict

from . import schema as S
from .sandbox import PR_GET_DUMPABLE, PR_GET_NO_NEW_PRIVS, prctl


@dataclass(frozen=True)
class Handler:
    name: str
    params: S.Spec
    func: Callable[[Dict[str, Any]], Any]


REGISTRY: Dict[str, Handler] = {}


def register(name: str, params: S.Spec, registry: Dict[str, Handler] = REGISTRY) -> Callable[..., Any]:
    def wrap(func: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any]], Any]:
        if name in registry:
            raise ValueError("handler %s registered twice" % name)
        registry[name] = Handler(name, params, func)
        return func
    return wrap


@register("runtime.echo", S.Obj({"value": S.Str(max_len=4096)}))
def _echo(params: Dict[str, Any]) -> Any:
    return {"value": params["value"]}


def _status_field(name: str) -> str:
    try:
        with open("/proc/self/status", "rb") as fh:
            for line in fh.read(65536).decode("ascii", "replace").splitlines():
                key, _, value = line.partition(":")
                if key == name:
                    return value.strip()[:64]
    except OSError:
        pass
    return "unknown"


def _limit(which: int) -> Any:
    soft, hard = resource.getrlimit(which)
    norm = lambda v: None if v == resource.RLIM_INFINITY else int(v)  # noqa: E731
    return {"soft": norm(soft), "hard": norm(hard)}


@register("runtime.sandbox_report", S.EMPTY)
def _sandbox_report(params: Dict[str, Any]) -> Any:
    try:
        fds = len(os.listdir("/proc/self/fd"))
    except OSError:
        fds = -1
    return {
        "uid": list(os.getresuid()),
        "gid": list(os.getresgid()),
        "groups": sorted(os.getgroups()),
        "no_new_privs": prctl(PR_GET_NO_NEW_PRIVS),
        "dumpable": prctl(PR_GET_DUMPABLE),
        "seccomp": _status_field("Seccomp"),
        "cap_eff": _status_field("CapEff"),
        "umask": _current_umask(),
        "cwd": os.getcwd(),
        "env_keys": sorted(os.environ),
        "open_fds": fds,
        "limits": {
            "core": _limit(resource.RLIMIT_CORE),
            "cpu": _limit(resource.RLIMIT_CPU),
            "as": _limit(resource.RLIMIT_AS),
            "nofile": _limit(resource.RLIMIT_NOFILE),
            "fsize": _limit(resource.RLIMIT_FSIZE),
            "nproc": _limit(resource.RLIMIT_NPROC),
        },
    }


def _current_umask() -> int:
    mask = os.umask(0o077)
    os.umask(mask)
    return mask
