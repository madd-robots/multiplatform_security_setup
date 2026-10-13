# SPDX-License-Identifier: GPL-3.0-or-later
"""Hash-chained audit ledger.

Each entry is a canonical document, and each entry is linked to the
previous one by its digest. Entries are appended (O_APPEND, fsync) to
segment files in a private directory.

What this establishes, and what it does not:
- Any edit, deletion, reordering or truncation in the middle of the chain
  is detected by ``verify``.
- Someone with root on this host can rewrite the whole chain from some
  point onward. An owner-signed **checkpoint** (one touch) fixes the chain
  head at that moment. A rewrite of anything before a checkpoint is then
  detectable, and, for a host that may be compromised, best verified on a
  second instance from a copy of the segments (``verify_segments``).
- Removing entries after the last checkpoint, at the end of the chain,
  cannot be detected without an external copy.

Secrets are never recorded: fields pass through the same redaction as the
structured log, and binary values are reduced to their length.
"""

from __future__ import annotations

import datetime
import os
import re
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, IntegrityError, ValidationError
from ..common.fsutil import ensure_private_dir, fsync_dir, open_dir_nofollow, read_bounded, write_all
from ..common.log import EVENT_RE, sanitize_value

ENTRY_DOMAIN = "guardian/audit-entry/v1"
CHECKPOINT_DOMAIN = "guardian/audit-checkpoint/v1"
CHECKPOINT_EVENT = "audit.checkpoint"
ZERO = "0" * 64
SEGMENT_RE = re.compile(r"^ledger-(\d{6})\.jsonl$")
MAX_ENTRY_BYTES = 16 * 1024
DEFAULT_SEGMENT_BYTES = 8 * 1024 * 1024
MAX_SEGMENT_READ = 64 * 1024 * 1024


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def entry_hash(entry: Dict[str, Any]) -> str:
    return canonical_digest(ENTRY_DOMAIN, entry).hex()


def checkpoint_digest(seq: int, head: str) -> bytes:
    return canonical_digest(CHECKPOINT_DOMAIN, {"seq": seq, "hash": head})


CheckpointVerifier = Callable[[str, bytes, bytes], None]  # (key_id, digest, signature) -> raises


def verify_lines(segments: List[Tuple[str, bytes]], *,
                 checkpoint_verifier: Optional[CheckpointVerifier] = None) -> Dict[str, Any]:
    """Verify the chain across ordered segments.  Raises IntegrityError at the first break."""
    prev, seq, checkpoints = ZERO, -1, []
    hashes: Dict[int, str] = {}
    for name, data in segments:
        if data and not data.endswith(b"\n"):
            raise IntegrityError("audit segment %s ends with a partial entry" % name, code="AUDIT_BROKEN")
        for line in data.split(b"\n")[:-1] if data else []:
            try:
                record = canonical_loads(line, require_canonical=True, max_bytes=MAX_ENTRY_BYTES)
                entry, digest = record["entry"], record["hash"]
                if set(record) != {"entry", "hash"} or set(entry) != {"seq", "prev", "time", "event", "fields"}:
                    raise ValidationError("unexpected fields")
            except (GuardianError, KeyError, TypeError):
                raise IntegrityError("audit entry %d is malformed" % (seq + 1), code="AUDIT_BROKEN") from None
            if entry["seq"] != seq + 1 or entry["prev"] != prev or entry_hash(entry) != digest:
                raise IntegrityError("audit chain broken at entry %d" % (seq + 1), code="AUDIT_BROKEN")
            seq, prev = entry["seq"], digest
            hashes[seq] = digest
            if entry["event"] == CHECKPOINT_EVENT:
                f = entry["fields"]
                if not isinstance(f, dict) or hashes.get(f.get("seq")) != f.get("hash"):
                    raise IntegrityError("checkpoint %d names an entry that is not in the chain" % seq,
                                         code="AUDIT_BROKEN")
                if checkpoint_verifier is not None:
                    try:
                        checkpoint_verifier(f["key_id"], checkpoint_digest(f["seq"], f["hash"]),
                                            f["signature"].encode("ascii"))
                    except (GuardianError, KeyError, AttributeError, UnicodeEncodeError):
                        raise IntegrityError("checkpoint %d signature invalid" % seq, code="AUDIT_BROKEN") from None
                checkpoints.append({"at": seq, "seq": f["seq"], "key_id": f.get("key_id")})
    return {"entries": seq + 1, "head_seq": seq, "head": prev, "checkpoints": checkpoints,
            "signed_checkpoints_verified": checkpoint_verifier is not None}


class AuditLedger:
    def __init__(self, directory: Path, *, segment_bytes: int = DEFAULT_SEGMENT_BYTES,
                 clock: Callable[[], str] = _now):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.segment_bytes = segment_bytes
        self.clock = clock
        self._lock = threading.Lock()
        report = verify_lines(self._read_segments())  # a broken chain stops the broker (fail closed)
        self._seq = report["head_seq"]
        self._head = report["head"]

    def _segment_names(self) -> List[str]:
        names = sorted(n for n in os.listdir(self.directory) if SEGMENT_RE.match(n))
        expected = ["ledger-%06d.jsonl" % (i + 1) for i in range(len(names))]
        if names != expected:
            raise IntegrityError("audit segments are missing or out of order", code="AUDIT_BROKEN")
        return names

    def _read_segments(self) -> List[Tuple[str, bytes]]:
        out = []
        dir_fd = open_dir_nofollow(self.directory)
        try:
            for name in self._segment_names():
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                        raise IntegrityError("audit segment %s has unsafe type or permissions" % name,
                                             code="AUDIT_BROKEN")
                    out.append((name, read_bounded(fd, MAX_SEGMENT_READ)))
                finally:
                    os.close(fd)
        finally:
            os.close(dir_fd)
        return out

    def head(self) -> Tuple[int, str]:
        with self._lock:
            return self._seq, self._head

    def append(self, event: str, *, exact: Optional[Dict[str, Any]] = None, **fields: Any) -> str:
        """Append an event.  ``fields`` are redacted and escaped like log fields.

        ``exact`` is for Guardian-generated values that must be stored
        byte-for-byte (signatures, digests); they are canonical-encoded,
        never redacted, and must not come from untrusted input.
        """
        if not EVENT_RE.match(event):
            raise ValueError("invalid audit event name")
        recorded = sanitize_value(fields)
        if exact:
            if set(exact) & set(recorded):
                raise ValueError("field given twice")
            canonical_dumps(exact)  # must be canonical-encodable
            recorded.update(exact)
        with self._lock:
            entry = {"seq": self._seq + 1, "prev": self._head, "time": self.clock(), "event": event,
                     "fields": recorded}
            digest = entry_hash(entry)
            line = canonical_dumps({"entry": entry, "hash": digest}) + b"\n"
            if len(line) > MAX_ENTRY_BYTES:
                raise ValidationError("audit entry too large")
            self._write(line)
            self._seq, self._head = entry["seq"], digest
            return digest

    def _write(self, line: bytes) -> None:
        names = self._segment_names()
        dir_fd = open_dir_nofollow(self.directory)
        try:
            name = names[-1] if names else "ledger-000001.jsonl"
            if names:
                st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                if st.st_size + len(line) > self.segment_bytes:
                    name = "ledger-%06d.jsonl" % (len(names) + 1)
            fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=dir_fd)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    raise IntegrityError("audit segment has unsafe type or permissions", code="AUDIT_BROKEN")
                write_all(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_dir(dir_fd)
        finally:
            os.close(dir_fd)

    def verify(self, checkpoint_verifier: Optional[CheckpointVerifier] = None) -> Dict[str, Any]:
        with self._lock:
            return verify_lines(self._read_segments(), checkpoint_verifier=checkpoint_verifier)

    def find_fields(self, event: str) -> List[Dict[str, Any]]:
        """The fields of every entry with this event name, oldest first (verifies the chain while reading)."""
        with self._lock:
            segments = self._read_segments()
        verify_lines(segments)
        out = []
        for _, data in segments:
            for line in data.split(b"\n")[:-1] if data else []:
                entry = canonical_loads(line, require_canonical=True, max_bytes=MAX_ENTRY_BYTES)["entry"]
                if entry["event"] == event:
                    out.append(entry["fields"])
        return out

    def entries(self, since: int, limit: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        with self._lock:
            for _, data in self._read_segments():
                for line in data.split(b"\n")[:-1] if data else []:
                    record = canonical_loads(line, require_canonical=True, max_bytes=MAX_ENTRY_BYTES)
                    if record["entry"]["seq"] >= since:
                        out.append(record)
                        if len(out) >= limit:
                            return out
        return out

    def add_checkpoint(self, seq: int, head: str, key_id: str, signature: bytes,
                       verifier: CheckpointVerifier) -> str:
        """Record an owner-signed checkpoint over an existing (seq, hash) of this chain."""
        verifier(key_id, checkpoint_digest(seq, head), signature)
        known = {r["entry"]["seq"]: r["hash"] for r in self.entries(seq, 1)}
        if known.get(seq) != head:
            raise ValidationError("checkpoint does not name an entry of this ledger")
        return self.append(CHECKPOINT_EVENT, exact={"seq": seq, "hash": head, "key_id": key_id,
                                                     "signature": signature.decode("ascii")})


def verify_segments(paths: List[Path], checkpoint_verifier: Optional[CheckpointVerifier] = None) -> Dict[str, Any]:
    """Verify exported segment files on another instance."""
    segments = []
    for path in paths:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            segments.append((Path(path).name, read_bounded(fd, MAX_SEGMENT_READ)))
        finally:
            os.close(fd)
    return verify_lines(segments, checkpoint_verifier=checkpoint_verifier)
