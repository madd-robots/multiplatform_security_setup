# SPDX-License-Identifier: GPL-3.0-or-later
"""Full-surface write and read-back verification (D4 step 2). DESTRUCTIVE.

Every byte of the logical address space is overwritten with a pattern
derived from a fresh random key and the chunk index, then read back and
compared. This:

* destroys all previous partitions, boot records, hidden partitions and
  stale data in the logical address space
* proves real capacity: a counterfeit drive that wraps or drops writes
  returns the wrong pattern, and the key is fresh for each run, so the
  firmware cannot predict or replay it
* finds bad regions and read errors

Reads bypass the page cache (O_DIRECT on block devices) so the comparison
sees what the device stores, not what the kernel remembers writing.

It cannot reach the controller firmware or spare flash outside the logical
address space (see ROADMAP D4).
"""

from __future__ import annotations

import hashlib
import mmap
import os
import secrets
import stat
from typing import Any, Callable, Dict, List, Optional

from ..common.errors import SecurityViolation, ValidationError

PATTERN_DOMAIN = b"usbguardian-surface-v1\x00"
DEFAULT_CHUNK = 1024 * 1024
ALIGNMENT = 4096
MAX_RANGES = 64

ProgressFn = Callable[[str, int, int], None]


def pattern(key: bytes, index: int, length: int) -> bytes:
    """Unique, unpredictable bytes for one chunk of one run."""
    return hashlib.shake_256(PATTERN_DOMAIN + key + index.to_bytes(8, "big")).digest(length)


class FdBlockIO:
    """Positional I/O on an open device or file descriptor."""

    def __init__(self, fd: int, size: int, *, direct: bool):
        self.fd = fd
        self.size = size
        self.direct = direct

    def write(self, offset: int, data: memoryview) -> None:
        done = 0
        while done < len(data):
            n = os.pwrite(self.fd, data[done:], offset + done)
            if n <= 0:
                raise OSError(5, "short write")
            done += n

    def read_into(self, offset: int, buf: memoryview) -> int:
        done = 0
        while done < len(buf):
            n = os.preadv(self.fd, [buf[done:]], offset + done)
            if n <= 0:
                break
            done += n
        return done

    def flush(self) -> None:
        os.fsync(self.fd)
        if not self.direct:
            # Without O_DIRECT, drop cached pages so read-back hits storage.
            os.posix_fadvise(self.fd, 0, 0, os.POSIX_FADV_DONTNEED)


def _add_range(ranges: List[List[int]], start: int, end: int) -> bool:
    if ranges and ranges[-1][1] == start:
        ranges[-1][1] = end
        return False
    if len(ranges) < MAX_RANGES:
        ranges.append([start, end])
        return False
    return True


def surface_test(io: Any, size: int, *, chunk_size: int = DEFAULT_CHUNK, key: Optional[bytes] = None,
                 progress: Optional[ProgressFn] = None,
                 should_stop: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """Overwrite and verify ``size`` bytes through ``io``.  Returns a result document."""
    if size <= 0 or size % 512:
        raise ValidationError("size must be a positive multiple of 512")
    if chunk_size <= 0 or chunk_size % ALIGNMENT:
        raise ValidationError("chunk size must be a positive multiple of %d" % ALIGNMENT)
    key = key if key is not None else secrets.token_bytes(32)
    if len(key) != 32:
        raise ValidationError("pattern key must be 32 bytes")
    chunks = (size + chunk_size - 1) // chunk_size
    # mmap buffers are page-aligned, as O_DIRECT requires.
    wbuf = mmap.mmap(-1, chunk_size)
    rbuf = mmap.mmap(-1, chunk_size)
    result: Dict[str, Any] = {
        "size_bytes": size, "chunk_size": chunk_size, "chunks": chunks, "direct_io": bool(io.direct),
        "bytes_written": 0, "write_error_offset": None, "bad_chunks": 0, "unreadable_chunks": 0,
        "bad_ranges": [], "bad_ranges_truncated": False, "first_bad_offset": None, "verified_bytes": 0,
        "cancelled": False, "passed": False,
    }
    try:
        wview = memoryview(wbuf)
        for i in range(chunks):
            if should_stop is not None and should_stop():
                result["cancelled"] = True
                return result
            offset = i * chunk_size
            n = min(chunk_size, size - offset)
            wbuf[:n] = pattern(key, i, n)
            try:
                io.write(offset, wview[:n])
            except OSError:
                result["write_error_offset"] = offset
                break
            result["bytes_written"] = offset + n
            if progress is not None:
                progress("write", offset + n, size)
        io.flush()

        rview = memoryview(rbuf)
        for i in range(chunks):
            if should_stop is not None and should_stop():
                result["cancelled"] = True
                return result
            offset = i * chunk_size
            n = min(chunk_size, size - offset)
            try:
                got = io.read_into(offset, rview[:n])
                good = got == n and rbuf[:n] == pattern(key, i, n)
            except OSError:
                result["unreadable_chunks"] += 1
                good = False
            if not good:
                result["bad_chunks"] += 1
                if result["first_bad_offset"] is None:
                    result["first_bad_offset"] = offset
                if _add_range(result["bad_ranges"], offset, offset + n):
                    result["bad_ranges_truncated"] = True
            if progress is not None:
                progress("verify", offset + n, size)
    finally:
        wview = rview = None  # release exports before closing the maps
        wbuf.close()
        rbuf.close()
    first_bad = result["first_bad_offset"]
    result["verified_bytes"] = size if first_bad is None else first_bad
    result["passed"] = (first_bad is None and result["write_error_offset"] is None
                        and result["bytes_written"] == size)
    return result


def open_block_device(path: str, expected_dev: str) -> int:
    """Open a whole block device exclusively for the surface test.

    O_EXCL makes the kernel refuse the open while anything (a mount, device
    mapper, RAID) holds the device. The opened node must be the expected
    major:minor, so a path swapped after inspection is refused.
    """
    direct = getattr(os, "O_DIRECT", 0)
    if not direct:
        raise SecurityViolation("O_DIRECT is unavailable; read-back would not be trustworthy",
                                code="DIRECT_IO_UNAVAILABLE")
    flags = os.O_RDWR | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW | direct
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SecurityViolation("cannot open the device exclusively: %s" % exc.strerror,
                                code="DEVICE_BUSY") from None
    try:
        st = os.fstat(fd)
        actual = "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev))
        if not stat.S_ISBLK(st.st_mode) or actual != expected_dev:
            raise SecurityViolation("opened node is not the inspected device", code="DEVICE_IDENTITY_CHANGED")
    except BaseException:
        os.close(fd)
        raise
    return fd
