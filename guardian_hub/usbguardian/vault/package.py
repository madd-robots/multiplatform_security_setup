# SPDX-License-Identifier: GPL-3.0-or-later
"""Transfer package format (version 1).

A package is one byte stream. It can be written to a file or to offset 0
of a raw device:

    prelude   "GUARDPKG"  u16 version=1  u16 flags=0  u32 manifest_len
    manifest  canonical JSON (custody identities and transfer metadata)
    auth      u32 auth_len, canonical JSON {scheme, key_id, signature}
    payload   each object's exact bytes, in manifest order, unmodified
    trailer   "GUARDEND"  SHA-256 of every preceding byte

The manifest binds each object's SHA-256 and exact length, the format
version, the transfer id and creation time, and the sender instance and key.
The signature covers a domain-separated digest of the canonical manifest,
so authenticating the manifest authenticates every payload byte.

The writer checks each object against its intake identity while streaming
it. It writes the trailer only after every object matched, so an
interrupted or failed write never leaves a package that verifies.

Verification order (fail closed at the first problem): prelude, manifest
(strict canonical decoding, bounded), signature, each object's digest and
length, trailer, then end of package. Payload bytes are delivered to the
caller's sink as they stream, so a sink must stage them and expose nothing
until verification has finished (see release.py).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import struct
from typing import Any, Dict, Iterable, Optional, Protocol

from ..common.canonical import b64decode, b64encode, canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, IntegrityError, ValidationError
from ..common.fsutil import write_all
from ..runtime import schema as S
from .auth import KEY_ID_RE, MAX_SIGNATURE, SCHEME_RE, Signer, Verifier
from .custody import (CHUNK, MAX_OBJECT_BYTES, MAX_SOURCE_NAME, SHA256_SPEC, TIMESTAMP_PATTERN, CustodyStore,
                      utc_timestamp)

MAGIC = b"GUARDPKG"
TRAILER_MAGIC = b"GUARDEND"
VERSION = 1
PRELUDE = struct.Struct(">8sHHI")
U32 = struct.Struct(">I")
TRAILER_SIZE = len(TRAILER_MAGIC) + 32
MAX_MANIFEST = 1024 * 1024
MAX_AUTH = 64 * 1024
MAX_OBJECTS = 4096
MANIFEST_DOMAIN = "guardian/transfer-manifest/v1"
MANIFEST_FORMAT = "guardian-transfer"

MANIFEST_SPEC = S.Obj({
    "format": S.Const(MANIFEST_FORMAT),
    "version": S.Const(VERSION),
    "transfer_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "created": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    "sender": S.Obj({
        "instance_id": S.Str(pattern=r"[a-z0-9][a-z0-9-]{0,63}", max_len=64),
        "scheme": S.Str(pattern=SCHEME_RE.pattern[1:-1], max_len=48),
        "key_id": S.Str(pattern=KEY_ID_RE.pattern[1:-1], max_len=128),
    }),
    "objects": S.List(S.Obj({
        "record_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
        "sha256": SHA256_SPEC,
        "length": S.Int(min_value=0, max_value=MAX_OBJECT_BYTES),
        "source_name": S.Str(max_len=MAX_SOURCE_NAME),
        "intake_time": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    }), min_items=1, max_items=MAX_OBJECTS),
    "total_length": S.Int(min_value=0, max_value=MAX_OBJECT_BYTES),
})
AUTH_SPEC = S.Obj({
    "scheme": S.Str(pattern=SCHEME_RE.pattern[1:-1], max_len=48),
    "key_id": S.Str(pattern=KEY_ID_RE.pattern[1:-1], max_len=128),
    "signature": S.Str(min_len=1, max_len=(MAX_SIGNATURE + 2) // 3 * 4),
})


class Sink(Protocol):
    def accept_manifest(self, manifest: Dict[str, Any]) -> None: ...
    def begin(self, index: int, obj: Dict[str, Any]) -> None: ...
    def write(self, data: bytes) -> None: ...
    def end(self, index: int) -> None: ...


def manifest_digest(manifest: Dict[str, Any]) -> bytes:
    return canonical_digest(MANIFEST_DOMAIN, manifest)


def build_manifest(records: Iterable[Dict[str, Any]], *, instance_id: str, scheme: str, key_id: str,
                   transfer_id: Optional[str] = None, created: Optional[str] = None) -> Dict[str, Any]:
    objects = [{k: r[k] for k in ("record_id", "sha256", "length", "source_name", "intake_time")} for r in records]
    manifest = {
        "format": MANIFEST_FORMAT,
        "version": VERSION,
        "transfer_id": transfer_id or secrets.token_hex(16),
        "created": created or utc_timestamp(),
        "sender": {"instance_id": instance_id, "scheme": scheme, "key_id": key_id},
        "objects": objects,
        "total_length": sum(o["length"] for o in objects),
    }
    return _check_manifest(manifest)


def _check_manifest(manifest: Any) -> Dict[str, Any]:
    manifest = S.validate(MANIFEST_SPEC, manifest, "$.manifest")
    if manifest["total_length"] != sum(o["length"] for o in manifest["objects"]):
        raise ValidationError("$.manifest.total_length does not match the objects")
    return manifest


def write_package(fd: int, store: CustodyStore, manifest: Dict[str, Any], signer: Signer) -> Dict[str, Any]:
    """Stream a signed package to ``fd`` at its current position."""
    manifest = _check_manifest(manifest)
    sender = manifest["sender"]
    if (signer.scheme, signer.key_id) != (sender["scheme"], sender["key_id"]):
        raise ValidationError("signer does not match the manifest sender")
    mbytes = canonical_dumps(manifest)
    digest = manifest_digest(manifest)
    signature = signer.sign(digest)
    if not isinstance(signature, bytes) or not 0 < len(signature) <= MAX_SIGNATURE:
        raise IntegrityError("signer returned an invalid signature")
    abytes = canonical_dumps({"scheme": signer.scheme, "key_id": signer.key_id, "signature": b64encode(signature)})
    if len(mbytes) > MAX_MANIFEST or len(abytes) > MAX_AUTH:
        raise ValidationError("manifest or signature block too large")

    h = hashlib.sha256()
    written = 0

    def emit(data: bytes) -> None:
        nonlocal written
        write_all(fd, data)
        h.update(data)
        written += len(data)

    emit(PRELUDE.pack(MAGIC, VERSION, 0, len(mbytes)))
    emit(mbytes)
    emit(U32.pack(len(abytes)))
    emit(abytes)
    for obj in manifest["objects"]:
        src = store.open_object(obj["sha256"])
        try:
            oh = hashlib.sha256()
            remaining = obj["length"]
            pos = 0
            while remaining:
                chunk = os.pread(src, min(CHUNK, remaining), pos)
                if not chunk:
                    break
                emit(chunk)
                oh.update(chunk)
                pos += len(chunk)
                remaining -= len(chunk)
            if remaining or os.pread(src, 1, pos) or oh.hexdigest() != obj["sha256"]:
                # No trailer is written, so this package can never verify.
                raise IntegrityError("custody object %s changed in the store" % obj["sha256"][:16])
        finally:
            os.close(src)
    package_sha256 = h.digest()
    write_all(fd, TRAILER_MAGIC + package_sha256)
    os.fsync(fd)
    return {"transfer_id": manifest["transfer_id"], "manifest_digest": digest.hex(),
            "package_sha256": package_sha256.hex(), "package_length": written + TRAILER_SIZE}


class _Reader:
    """Positional, hashing reader over an untrusted package."""

    def __init__(self, fd: int, start: int):
        self.fd = fd
        self.pos = start
        self.hash = hashlib.sha256()

    def read_exact(self, n: int, *, hashed: bool = True) -> bytes:
        parts = []
        remaining = n
        while remaining:
            chunk = os.pread(self.fd, min(CHUNK, remaining), self.pos)
            if not chunk:
                raise IntegrityError("package is truncated", code="PACKAGE_TRUNCATED")
            parts.append(chunk)
            self.pos += len(chunk)
            remaining -= len(chunk)
        data = b"".join(parts)
        if hashed:
            self.hash.update(data)
        return data


def _malformed(message: str) -> IntegrityError:
    return IntegrityError(message, code="PACKAGE_MALFORMED")


def _decode_block(raw: bytes, spec: S.Spec, what: str, limit: int) -> Dict[str, Any]:
    try:
        return S.validate(spec, canonical_loads(raw, max_bytes=limit, require_canonical=True), "$." + what)
    except GuardianError as exc:
        raise _malformed("%s is invalid: %s" % (what, exc.message)) from None


def verify_package(fd: int, verifier: Verifier, *, start: int = 0, sink: Optional[Sink] = None,
                   require_end: bool = True) -> Dict[str, Any]:
    """Verify a package read from ``fd`` at ``start``.  Raises IntegrityError on any problem.

    ``require_end`` demands that the package ends exactly at the end of a
    regular file. For a raw device it is False, because the device continues
    past the package.
    """
    if verifier is None:
        raise IntegrityError("no verifier: packages cannot be authenticated", code="PACKAGE_UNAUTHENTICATED")
    r = _Reader(fd, start)
    magic, version, flags, mlen = PRELUDE.unpack(r.read_exact(PRELUDE.size))
    if magic != MAGIC:
        raise _malformed("not a Guardian package")
    if version != VERSION or flags != 0:
        raise _malformed("unsupported package version %d" % version)
    if not 0 < mlen <= MAX_MANIFEST:
        raise _malformed("manifest length out of range")
    manifest = _decode_block(r.read_exact(mlen), MANIFEST_SPEC, "manifest", MAX_MANIFEST)
    if manifest["total_length"] != sum(o["length"] for o in manifest["objects"]):
        raise _malformed("manifest total_length does not match the objects")
    (alen,) = U32.unpack(r.read_exact(U32.size))
    if not 0 < alen <= MAX_AUTH:
        raise _malformed("signature block length out of range")
    auth = _decode_block(r.read_exact(alen), AUTH_SPEC, "auth", MAX_AUTH)
    sender = manifest["sender"]
    if (auth["scheme"], auth["key_id"]) != (sender["scheme"], sender["key_id"]):
        raise IntegrityError("signature key does not match the manifest sender", code="PACKAGE_UNAUTHENTICATED")
    try:
        signature = b64decode(auth["signature"], max_bytes=MAX_SIGNATURE)
    except GuardianError:
        raise _malformed("signature is not valid base64") from None
    digest = manifest_digest(manifest)
    try:
        verifier.verify(auth["scheme"], auth["key_id"], digest, signature)
    except GuardianError as exc:
        raise IntegrityError("manifest signature rejected: %s" % exc.message, code="PACKAGE_UNAUTHENTICATED") from None

    if sink is not None:
        sink.accept_manifest(manifest)
    for index, obj in enumerate(manifest["objects"]):
        if sink is not None:
            sink.begin(index, obj)
        oh = hashlib.sha256()
        remaining = obj["length"]
        while remaining:
            chunk = r.read_exact(min(CHUNK, remaining))
            oh.update(chunk)
            if sink is not None:
                sink.write(chunk)
            remaining -= len(chunk)
        if oh.hexdigest() != obj["sha256"]:
            raise IntegrityError("object %d differs from its custody identity" % index, code="PAYLOAD_MISMATCH")
        if sink is not None:
            sink.end(index)
    expected = r.hash.digest()
    trailer = r.read_exact(TRAILER_SIZE, hashed=False)
    if trailer[:len(TRAILER_MAGIC)] != TRAILER_MAGIC or not secrets.compare_digest(trailer[len(TRAILER_MAGIC):], expected):
        raise IntegrityError("package trailer does not match its contents", code="PACKAGE_MALFORMED")
    end = r.pos
    if require_end:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != end:
            raise IntegrityError("unexpected data after the package", code="PACKAGE_TRAILING_DATA")
    return {"transfer_id": manifest["transfer_id"], "manifest": manifest, "manifest_digest": digest.hex(),
            "package_sha256": expected.hex(), "package_length": end - start, "key_id": auth["key_id"]}


def readback_verify(fd: int, verifier: Verifier, written: Dict[str, Any], *, start: int = 0,
                    require_end: bool = True) -> Dict[str, Any]:
    """Verify what the medium actually stores after ``write_package``.

    Cached pages are dropped first, so the read comes from storage. The
    result must match what was written and verify against the intake
    identities in the manifest. A successful write call is not evidence.
    """
    os.fsync(fd)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except OSError:
        pass
    report = verify_package(fd, verifier, start=start, require_end=require_end)
    for key in ("transfer_id", "manifest_digest", "package_sha256", "package_length"):
        if report[key] != written[key]:
            raise IntegrityError("read-back differs from what was written (%s)" % key, code="READBACK_MISMATCH")
    return report


__all__ = ["build_manifest", "write_package", "verify_package", "readback_verify", "manifest_digest"]
