# SPDX-License-Identifier: GPL-3.0-or-later
"""Custody store: Guardian's private copy of accepted data.

Intake streams the source once, writing the bytes into the store and
hashing them in the same pass, so the stored copy is exactly what was
hashed. Later changes to the source make no difference. The stored copy is
then read back from disk and re-hashed before it is accepted. Objects are
content-addressed (SHA-256) and stored read-only. Each intake writes a
canonical, read-only record with the digest, exact length, source name (as
data) and intake time.

Payload bytes are opaque. Nothing here interprets, normalizes or converts
them.
"""

from __future__ import annotations

import datetime
import hashlib
import os
import re
import secrets
import select
import stat
from pathlib import Path
from typing import Any, Dict, Optional, Union

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import (GuardianError, IntegrityError, NotFound, ResourceLimitExceeded, SecurityViolation,
                             ValidationError)
from ..common.fsutil import atomic_write, ensure_private_dir, open_dir_nofollow, read_file_bounded, write_all
from ..common.space import DEFAULT_POLICY, SpaceGuard, SpacePolicy
from ..common.text import display_text
from ..runtime import schema as S

CHUNK = 1024 * 1024
MAX_OBJECT_BYTES = 2 ** 53 - 1
MAX_SOURCE_NAME = 1024
INVALID_UTF8_PREFIX = "invalid-utf8:"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RECORD_ID_RE = re.compile(r"^[0-9a-f]{32}$")
TIMESTAMP_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
RECORD_FORMAT = "guardian-custody-record"

SHA256_SPEC = S.Str(pattern=r"[0-9a-f]{64}", max_len=64)
RECORD_SPEC = S.Obj({
    "format": S.Const(RECORD_FORMAT),
    "version": S.Const(1),
    "record_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "sha256": SHA256_SPEC,
    "length": S.Int(min_value=0, max_value=MAX_OBJECT_BYTES),
    "source_name": S.Str(max_len=MAX_SOURCE_NAME),
    "intake_time": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
})


def utc_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_name_text(name: Union[str, bytes]) -> str:
    """Record a source name as data, losslessly.  It is never used as a path here."""
    if isinstance(name, bytes):
        try:
            text = name.decode("utf-8")
        except UnicodeDecodeError:
            text = INVALID_UTF8_PREFIX + name.hex()
    elif isinstance(name, str):
        try:
            name.encode("utf-8")
            text = name
        except UnicodeEncodeError:  # surrogate-escaped bytes from os.fsdecode
            text = source_name_text(os.fsencode(name))
    else:
        raise ValidationError("source name must be text or bytes")
    if len(text) > MAX_SOURCE_NAME:
        raise ValidationError("source name longer than %d characters" % MAX_SOURCE_NAME)
    return text


def hash_fd(fd: int, *, offset: int = 0, length: Optional[int] = None, drop_cache: bool = True) -> "tuple[str, int]":
    """Hash a file from storage (page cache dropped first) using positional reads."""
    if drop_cache:
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass
    h = hashlib.sha256()
    total = 0
    while length is None or total < length:
        want = CHUNK if length is None else min(CHUNK, length - total)
        chunk = os.pread(fd, want, offset + total)
        if not chunk:
            break
        h.update(chunk)
        total += len(chunk)
    return h.hexdigest(), total


class CustodyStore:
    def __init__(self, root: Path, *, space_policy: SpacePolicy = DEFAULT_POLICY):
        self.root = Path(root)
        self.space_policy = space_policy
        ensure_private_dir(self.root)
        for sub in ("objects", "records", "tmp"):
            ensure_private_dir(self.root / sub)

    def sweep_tmp(self) -> Dict[str, int]:
        """Remove partial intakes left by a broker that was killed mid-write (call at startup only).

        ``tmp/`` is private to the store and holds nothing but unfinished,
        unverified copies; nothing in it was ever accepted into custody.
        """
        removed = freed = 0
        dir_fd = open_dir_nofollow(self.root / "tmp")
        try:
            for name in os.listdir(dir_fd):
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                    os.unlink(name, dir_fd=dir_fd)
                    removed += 1
                    freed += st.st_size if stat.S_ISREG(st.st_mode) else 0
        finally:
            os.close(dir_fd)
        return {"removed": removed, "bytes": freed}

    def object_path(self, sha256: str) -> Path:
        if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
            raise ValidationError("invalid object digest")
        return self.root / "objects" / sha256[:2] / sha256

    def intake(self, source: Union[int, str, Path], source_name: Union[str, bytes], *,
               max_bytes: int = MAX_OBJECT_BYTES) -> Dict[str, Any]:
        """Accept data into custody.  ``source`` is an open readable fd or a regular-file path."""
        name = source_name_text(source_name)
        own_fd = not isinstance(source, int)
        if own_fd:
            try:
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            except OSError as exc:
                raise ValidationError("cannot open source %s: %s" % (display_text(source), exc.strerror),
                                      code="SOURCE_UNREADABLE") from None
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise SecurityViolation("source is not a regular file", code="NOT_REGULAR_FILE")
        else:
            fd = source
        tmp = self.root / "tmp" / secrets.token_hex(16)
        try:
            st = os.fstat(fd)
            size = st.st_size if stat.S_ISREG(st.st_mode) else None  # unknown for pipes
            if size is not None and size > max_bytes:
                raise ResourceLimitExceeded("source larger than %d bytes" % max_bytes)
            # Object plus record; re-checked while copying (the source may grow, or
            # someone may fill the disk meanwhile).
            guard = SpaceGuard(str(self.root), total=size, what="custody intake", policy=self.space_policy)
            guard.start(files=2)
            sha256, length = self._copy_in(fd, tmp, max_bytes, guard)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        finally:
            if own_fd:
                os.close(fd)
        self._commit(tmp, sha256, length)
        record = {"format": RECORD_FORMAT, "version": 1, "record_id": secrets.token_hex(16), "sha256": sha256,
                  "length": length, "source_name": name, "intake_time": utc_timestamp()}
        atomic_write(self.root / "records" / (record["record_id"] + ".json"), canonical_dumps(record), mode=0o400)
        return record

    def intake_bytes(self, data: bytes, source_name: Union[str, bytes]) -> Dict[str, Any]:
        """Take Guardian-generated bytes (descriptors, trust snapshots) into custody."""
        fd = os.memfd_create("guardian-intake", os.MFD_CLOEXEC)
        try:
            write_all(fd, data)
            os.lseek(fd, 0, os.SEEK_SET)
            return self.intake(fd, source_name)
        finally:
            os.close(fd)

    def _copy_in(self, fd: int, tmp: Path, max_bytes: int, guard: SpaceGuard) -> "tuple[str, int]":
        h = hashlib.sha256()
        length = 0
        out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            while True:
                try:
                    chunk = os.read(fd, CHUNK)
                except BlockingIOError:
                    select.select([fd], [], [])  # non-blocking pipe: wait instead of spinning
                    continue
                if not chunk:
                    break
                length += len(chunk)
                if length > max_bytes:
                    raise ResourceLimitExceeded("source larger than %d bytes" % max_bytes)
                guard.advance(len(chunk))
                h.update(chunk)
                write_all(out, chunk)
            os.fsync(out)
        finally:
            os.close(out)
        sha256 = h.hexdigest()
        # Read the stored copy back from disk before accepting it.
        check = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if hash_fd(check) != (sha256, length):
                raise IntegrityError("stored copy differs from the data read at intake", code="INTAKE_READBACK_FAILED")
        finally:
            os.close(check)
        return sha256, length

    def _commit(self, tmp: Path, sha256: str, length: int) -> None:
        final = self.object_path(sha256)
        ensure_private_dir(final.parent)
        if os.path.lexists(final):
            os.unlink(tmp)
            self.verify_object(sha256, length)  # deduplicated: the existing copy must still be intact
            return
        os.chmod(tmp, 0o400)
        os.rename(tmp, final)

    def open_object(self, sha256: str) -> int:
        path = self.object_path(sha256)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            raise NotFound("custody object not found") from None
        except OSError as exc:
            raise IntegrityError("custody object unreadable: %s" % exc.strerror) from None
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o277:
            os.close(fd)
            raise IntegrityError("custody object has unexpected type or permissions")
        return fd

    def verify_object(self, sha256: str, length: int) -> None:
        fd = self.open_object(sha256)
        try:
            actual = hash_fd(fd)
        finally:
            os.close(fd)
        if actual != (sha256, length):
            raise IntegrityError("custody object %s was altered in the store" % sha256[:16])

    def list_records(self, since: int, limit: int) -> Dict[str, Any]:
        """Custody records, oldest first by intake time; objects are not re-hashed here (verify does that)."""
        names = [n[:-5] for n in os.listdir(self.root / "records") if n.endswith(".json") and RECORD_ID_RE.match(n[:-5])]
        records = []
        for rid in names:
            try:
                records.append(self.load_record(rid, verify=False))
            except GuardianError:
                records.append({"record_id": rid, "source_name": "", "sha256": "", "length": 0,
                                "intake_time": "", "unreadable": True})
        records.sort(key=lambda r: (r["intake_time"], r["record_id"]))
        return {"total": len(records), "records": records[since:since + limit]}

    def load_record(self, record_id: str, *, verify: bool = True) -> Dict[str, Any]:
        """Load an intake record.  By default the stored object is re-verified against it."""
        if not isinstance(record_id, str) or not RECORD_ID_RE.match(record_id):
            raise ValidationError("invalid record id")
        path = self.root / "records" / (record_id + ".json")
        if not os.path.lexists(path):
            raise NotFound("custody record not found")
        raw = read_file_bounded(path, 64 * 1024, require_private=True)
        try:
            record = S.validate(RECORD_SPEC, canonical_loads(raw, require_canonical=True))
        except ValidationError as exc:
            raise IntegrityError("custody record is malformed: %s" % exc.message) from None
        if record["record_id"] != record_id:
            raise IntegrityError("custody record id does not match its file")
        if verify:
            self.verify_object(record["sha256"], record["length"])
        return record
