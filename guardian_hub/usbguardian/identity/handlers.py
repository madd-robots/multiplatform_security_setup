# SPDX-License-Identifier: GPL-3.0-or-later
"""Signature verification inside the sandboxed worker.

The signature (attacker-controllable on a transport USB) is handed to
``ssh-keygen`` only in a worker: unprivileged, resource-limited, no file
writes. The worker profile allows exactly that one subprocess.
"""

from __future__ import annotations

from typing import Any, Dict

from ..common.canonical import b64decode, b64encode
from ..common.errors import GuardianError, IntegrityError
from ..runtime import schema as S
from ..runtime.handlers import Handler, register
from ..runtime.workers import WorkerLauncher, WorkerProfile
from .sshkeys import SshPublicKey, parse_public_key
from .sshsig import MAX_SIGNATURE, NAMESPACES, tool_verify

IDENTITY_REGISTRY: Dict[str, Handler] = {}
VERIFY_PROFILE = WorkerProfile(name="sshsig", cpu_seconds=5, memory_bytes=256 * 1024 * 1024, max_open_files=64,
                               allow_subprocess=True, wall_timeout=30.0)

VERIFY_PARAMS = S.Obj({
    "key": S.Str(min_len=10, max_len=2048),
    "namespace": S.Enum(NAMESPACES),
    "message": S.Str(min_len=4, max_len=88),  # base64 of a 32-byte digest (or a little more)
    "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE),
})


@register("identity.verify_sshsig", VERIFY_PARAMS, IDENTITY_REGISTRY)
def _verify(params: Dict[str, Any]) -> Any:
    key = parse_public_key(params["key"])
    message = b64decode(params["message"], max_bytes=64)
    try:
        signature = params["signature"].encode("ascii")
    except UnicodeEncodeError:
        return {"valid": False}
    return {"valid": bool(tool_verify(key, params["namespace"], message, signature))}


class WorkerSigCheck:
    """SigCheck that runs every verification in a fresh sandboxed worker."""

    def __init__(self, launcher: WorkerLauncher):
        self.launcher = launcher

    def __call__(self, key: SshPublicKey, namespace: str, message: bytes, signature: bytes) -> bool:
        try:
            text = signature.decode("ascii")
        except UnicodeDecodeError:
            return False
        if len(text) > MAX_SIGNATURE:
            return False
        try:
            result = self.launcher.run(VERIFY_PROFILE, "identity.verify_sshsig",
                                       {"key": key.to_line(), "namespace": namespace,
                                        "message": b64encode(message), "signature": text})
        except IntegrityError:
            return False
        except GuardianError as exc:
            if exc.code == "VALIDATION_FAILED":
                return False  # malformed signature or key: simply not valid
            raise
        # Worker output is untrusted: only a literal True counts.
        return isinstance(result, dict) and result.get("valid") is True
