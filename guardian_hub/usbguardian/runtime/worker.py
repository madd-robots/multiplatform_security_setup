# SPDX-License-Identifier: GPL-3.0-or-later
"""Worker process main loop (runs inside the sandbox).

Started by ``workers.WorkerLauncher`` as

    python3 -I -B -S <package>/runtime/_worker_entry.py <profile-json>

It restricts itself, reads exactly one request frame from stdin, runs the
named handler and writes exactly one response frame to stdout.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, List

from ..common.canonical import canonical_loads
from ..common.errors import GuardianError, ProtocolError, as_guardian_error
from . import ipc
from . import schema as S
from . import sandbox

WORKER_REQUEST_SPEC = S.Obj({
    "handler": S.Str(pattern=ipc.OP_PATTERN, max_len=130),
    "params": S.Obj({}, allow_extra=True),
})

EXIT_OK = 0
EXIT_SANDBOX_FAILED = 70
EXIT_IO_FAILED = 71


def _registry(test_handlers: bool) -> Dict[str, Any]:
    from .handlers import REGISTRY
    registry = dict(REGISTRY)
    if test_handlers:
        from .testing_handlers import TEST_REGISTRY
        registry.update(TEST_REGISTRY)
    return registry


def _respond(message: Dict[str, Any]) -> int:
    try:
        ipc.send_frame(1, message)
    except GuardianError as exc:
        # Result not encodable (too large or non-canonical): report that instead.
        try:
            ipc.send_frame(1, {"ok": False, "error": exc.to_wire()})
        except Exception:
            return EXIT_IO_FAILED
    except Exception:
        return EXIT_IO_FAILED
    return EXIT_OK


def main(argv: List[str]) -> int:
    try:
        if len(argv) != 2:
            raise ProtocolError("usage: worker <profile-json>")
        profile = sandbox.SandboxProfile.from_document(
            canonical_loads(argv[1].encode("utf-8", "surrogateescape"), max_bytes=4096))
        sandbox.apply(profile)
    except Exception as exc:
        err = as_guardian_error(exc)
        os.write(2, ("sandbox setup failed: %s\n" % err.code).encode("ascii"))
        return EXIT_SANDBOX_FAILED

    # Everything below handles untrusted input and runs restricted.
    try:
        request = S.validate(WORKER_REQUEST_SPEC, ipc.recv_frame(0, timeout=profile.io_timeout))
        handler = _registry(profile.test_handlers).get(request["handler"])
        if handler is None:
            raise GuardianError("unknown handler", code="NOT_FOUND")
        params = S.validate(handler.params, request["params"], "$.params")
        result = handler.func(params)
        return _respond({"ok": True, "result": result})
    except BaseException as exc:  # noqa: B902 - report everything, including MemoryError
        if isinstance(exc, (SystemExit, KeyboardInterrupt)):
            raise
        return _respond({"ok": False, "error": as_guardian_error(exc).to_wire()})


if __name__ == "__main__":
    sys.exit(main(sys.argv))
