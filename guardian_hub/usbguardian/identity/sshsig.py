# SPDX-License-Identifier: GPL-3.0-or-later
"""SSHSIG signatures through ``ssh-keygen -Y``.

Signing (client side) runs ``ssh-keygen -Y sign`` with the key handle of a
YubiKey security key. The YubiKey signs only after a physical touch. No PIN
or passphrase is used (D2).

Verification runs ``ssh-keygen -Y verify`` against an allowed-signers entry
built from exactly one enrolled public key, restricted to one namespace.
Inputs are passed through pipes (``/dev/fd/N``), so the sandboxed worker
never writes a file. For security keys, OpenSSH requires the user-presence
flag unless the allowed-signers entry says ``no-touch-required``. Guardian
never writes that option, so an untouched signature does not verify.

The signed message is always a 32-byte domain-separated canonical digest.
Each purpose has its own namespace, so a signature made for one purpose
cannot be replayed for another.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import Callable

from ..common.errors import GuardianError, IntegrityError, OperationTimeout, ValidationError
from ..common.tools import SAFE_ENV, require_tool
from .sshkeys import SshPublicKey

NS_OWNER = "guardian-owner@v1"
NS_TRANSFER = "guardian-transfer@v1"
NS_TRUST = "guardian-trust@v1"
NS_ENROLL = "guardian-enroll@v1"
NS_DEPLOY = "guardian-deploy@v1"
NS_AUDIT = "guardian-audit@v1"
NS_LEASE = "guardian-lease@v1"
NS_SPINOFF = "guardian-spinoff@v1"  # signed by a spinoff's own (non-owner) key
NAMESPACES = frozenset({NS_OWNER, NS_TRANSFER, NS_TRUST, NS_ENROLL, NS_DEPLOY, NS_AUDIT, NS_LEASE, NS_SPINOFF})
SCHEME = "sshsig"
MAX_SIGNATURE = 16 * 1024
_BEGIN = b"-----BEGIN SSH SIGNATURE-----"
_END = b"-----END SSH SIGNATURE-----"
_B64_LINE = re.compile(rb"^[A-Za-z0-9+/=]{1,76}$")

SigCheck = Callable[[SshPublicKey, str, bytes, bytes], bool]


def check_armor(signature: bytes) -> bytes:
    """Accept only a well-formed, bounded SSHSIG armor before any tool sees it."""
    if not isinstance(signature, bytes) or not 0 < len(signature) <= MAX_SIGNATURE:
        raise ValidationError("signature missing or too large")
    lines = signature.rstrip(b"\n").split(b"\n")
    if len(lines) < 3 or lines[0] != _BEGIN or lines[-1] != _END:
        raise ValidationError("signature is not SSHSIG armor")
    if not all(_B64_LINE.match(line) for line in lines[1:-1]):
        raise ValidationError("signature armor contains invalid characters")
    return signature


def _check_namespace(namespace: str) -> None:
    if namespace not in NAMESPACES:
        raise ValidationError("unknown signature namespace")


def tool_verify(key: SshPublicKey, namespace: str, message: bytes, signature: bytes, *,
                timeout: float = 20.0) -> bool:
    """True only if ``ssh-keygen`` accepts the signature for this exact key and namespace."""
    _check_namespace(namespace)
    check_armor(signature)
    exe = require_tool("ssh-keygen")
    allowed = ('guardian namespaces="%s" %s\n' % (namespace, key.to_line())).encode("ascii")
    fds = []
    try:
        for content in (allowed, signature):
            r, w = os.pipe()
            fds.append(r)
            try:
                os.write(w, content)  # both fit the pipe buffer (< 64 KiB)
            finally:
                os.close(w)
        argv = [exe, "-Y", "verify", "-f", "/dev/fd/%d" % fds[0], "-I", "guardian", "-n", namespace,
                "-s", "/dev/fd/%d" % fds[1]]
        try:
            proc = subprocess.run(argv, input=message, capture_output=True, pass_fds=tuple(fds),
                                  env=dict(SAFE_ENV), timeout=timeout, shell=False, check=False)
        except subprocess.TimeoutExpired:
            raise OperationTimeout("signature verification timed out") from None
        return proc.returncode == 0
    finally:
        for fd in fds:
            os.close(fd)


class SshKeygenSigner:
    """Client-side signer: one YubiKey key handle, one namespace per call."""

    scheme = SCHEME

    def __init__(self, handle_path: str, key: SshPublicKey, *, timeout: float = 120.0):
        self.handle_path = str(handle_path)
        self.key = key
        self.key_id = key.key_id
        self.timeout = timeout

    def sign_ns(self, namespace: str, digest: bytes) -> bytes:
        _check_namespace(namespace)
        if len(digest) != 32:
            raise ValidationError("only 32-byte digests are signed")
        exe = require_tool("ssh-keygen")
        argv = [exe, "-Y", "sign", "-f", self.handle_path, "-n", namespace]
        try:
            proc = subprocess.run(argv, input=digest, capture_output=True, env=dict(SAFE_ENV),
                                  timeout=self.timeout, shell=False, check=False)
        except subprocess.TimeoutExpired:
            raise OperationTimeout("no touch on the security key in time") from None
        if proc.returncode != 0:
            raise GuardianError("signing failed (key missing, not touched, or wrong handle)", code="SIGNING_FAILED")
        signature = check_armor(proc.stdout)
        # Self-check: the handle really belongs to the expected public key.
        if not tool_verify(self.key, namespace, digest, signature):
            raise IntegrityError("signature does not verify against the expected key", code="SIGNING_FAILED")
        return signature

    def for_namespace(self, namespace: str) -> "NamespacedSigner":
        return NamespacedSigner(self, namespace)


class NamespacedSigner:
    """Adapter to the vault ``Signer`` interface (one fixed namespace)."""

    scheme = SCHEME

    def __init__(self, signer: SshKeygenSigner, namespace: str):
        self.signer = signer
        self.namespace = namespace
        self.key_id = signer.key_id

    def sign(self, digest: bytes) -> bytes:
        return self.signer.sign_ns(self.namespace, digest)
