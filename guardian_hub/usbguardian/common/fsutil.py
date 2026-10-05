# SPDX-License-Identifier: GPL-3.0-or-later
"""Private, symlink-safe file I/O (POSIX).

State, keys, logs and reports live in owner-only directories.  Files are
opened with O_NOFOLLOW, type- and owner-checked through the open descriptor,
read with a size bound, and replaced atomically (temp file, fsync, rename,
directory fsync) so an interruption leaves either the old or the new file.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import Optional

from .errors import ResourceLimitExceeded, SecurityViolation, ValidationError
from .names import validate_component
from .text import display_text


def read_bounded(fd: int, limit: int) -> bytes:
    chunks = []
    remaining = limit
    while remaining > 0:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def fsync_dir(dir_fd: int) -> None:
    # Directory fsync is unsupported on some filesystems (EINVAL); the data
    # file itself has already been fsynced.
    try:
        os.fsync(dir_fd)
    except OSError:
        pass


def open_dir_nofollow(path: "os.PathLike[str] | str", dir_fd: Optional[int] = None) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def _check_private_stat(st: os.stat_result, what: str) -> None:
    if st.st_uid != os.geteuid():
        raise SecurityViolation("%s is not owned by the current user" % what, code="NOT_PRIVATE")
    if st.st_mode & 0o077:
        raise SecurityViolation("%s is accessible by other users (mode %o)" % (what, st.st_mode & 0o777),
                                code="NOT_PRIVATE")


def ensure_private_dir(path: Path, *, create: bool = True) -> None:
    """Create or validate a 0700 directory owned by the effective user."""
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise SecurityViolation("cannot create %s: %s" % (display_text(path), exc.strerror),
                                    code="NOT_PRIVATE") from None
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SecurityViolation("cannot access %s: %s" % (display_text(path), exc.strerror),
                                code="NOT_PRIVATE") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SecurityViolation("%s is not a real directory" % display_text(path), code="NOT_PRIVATE")
    _check_private_stat(st, display_text(path))


def read_file_bounded(path: Path, limit: int, *, require_private: bool = False) -> bytes:
    """Read a regular file without following a final symlink, up to ``limit`` bytes."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValidationError("cannot open %s: %s" % (display_text(path), exc.strerror),
                              code="FILE_UNREADABLE") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SecurityViolation("%s is not a regular file" % display_text(path), code="NOT_REGULAR_FILE")
        if require_private:
            _check_private_stat(st, display_text(path))
        if st.st_size > limit:
            raise ResourceLimitExceeded("%s is larger than %d bytes" % (display_text(path), limit))
        data = read_bounded(fd, limit + 1)
        if len(data) > limit:
            raise ResourceLimitExceeded("%s grew beyond %d bytes while reading" % (display_text(path), limit))
        return data
    finally:
        os.close(fd)


def check_trusted_file(path: Path, *, allowed_owners: "tuple[int, ...]" = (0,)) -> os.stat_result:
    """Validate a configuration file another principal could otherwise plant.

    The file and every parent directory must be owned by an allowed owner
    and not writable by group or others.
    """
    p = Path(os.path.abspath(path))
    for current in [p] + list(p.parents):
        try:
            st = os.lstat(current)
        except OSError as exc:
            raise SecurityViolation("cannot access %s: %s" % (display_text(current), exc.strerror),
                                    code="UNTRUSTED_PATH") from None
        if stat.S_ISLNK(st.st_mode):
            raise SecurityViolation("%s is a symlink" % display_text(current), code="UNTRUSTED_PATH")
        if st.st_uid not in allowed_owners:
            raise SecurityViolation("%s is owned by uid %d" % (display_text(current), st.st_uid),
                                    code="UNTRUSTED_PATH")
        writable_by_others = st.st_mode & 0o022
        sticky_dir = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
        if writable_by_others and not (sticky_dir and current != p):
            raise SecurityViolation("%s is writable by other users" % display_text(current), code="UNTRUSTED_PATH")
    return os.lstat(p)


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically replace ``path`` with ``data`` inside an existing directory."""
    path = Path(path)
    name = validate_component(path.name, allow_leading_dash=True)
    dir_fd = open_dir_nofollow(path.parent if str(path.parent) else ".")
    tmp_name = ".%s.tmp-%s" % (name[:100], secrets.token_hex(8))
    try:
        fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=dir_fd)
        try:
            os.fchmod(fd, mode)
            write_all(fd, bytes(data))
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            existing = os.lstat(name, dir_fd=dir_fd)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise SecurityViolation("refusing to replace non-regular file %s" % display_text(path),
                                    code="NOT_REGULAR_FILE")
        os.replace(tmp_name, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        tmp_name = ""
        fsync_dir(dir_fd)
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)
