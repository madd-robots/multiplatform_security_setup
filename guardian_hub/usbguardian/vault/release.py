# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify-then-release.

Payload bytes stream into a private staging directory inside the
destination (same filesystem, so the final step is a rename). Nothing
appears under a final name until the whole package has verified: signature,
every object digest and length, the trailer and the end of the package. On
any failure the staging directory is removed and the destination is left
exactly as it was.

Released bytes are the custody bytes, unchanged. Only the names can
differ: an original name that is unsafe for the destination is refused
(policy "strict", the default) or replaced with a Guardian-generated name
(policy "generate"). The receipt always keeps the original name, so the
mapping is recorded.
"""

from __future__ import annotations

import errno
import os
import secrets
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..common.errors import SecurityViolation, ValidationError
from ..common.fsutil import fsync_dir, open_dir_nofollow, write_all
from ..common.names import check_component
from .auth import Verifier
from .package import verify_package

NAME_POLICIES = ("strict", "generate")


def plan_names(objects: List[Dict[str, Any]], policy: str) -> List[Tuple[str, bool]]:
    """Final (name, renamed) per object.  Case-insensitive uniqueness for FAT/NTFS targets."""
    if policy not in NAME_POLICIES:
        raise ValidationError("unknown name policy")
    planned: List[Tuple[str, bool]] = []
    seen = set()
    for index, obj in enumerate(objects):
        name = obj["source_name"]
        if not check_component(name) and name.lower() not in seen:
            final, renamed = name, False
        elif policy == "generate":
            final, renamed = "guardian-object-%04d-%s" % (index, obj["sha256"][:16]), True
        else:
            raise ValidationError("object %d has a name that is unsafe or duplicated at the destination" % index,
                                  code="UNSAFE_RELEASE_NAME")
        seen.add(final.lower())
        planned.append((final, renamed))
    return planned


class _StagingSink:
    def __init__(self, dest_fd: int, policy: str, file_mode: int, owner: Optional[Tuple[int, int]]):
        self.dest_fd = dest_fd
        self.policy = policy
        self.file_mode = file_mode
        self.owner = owner
        self.staging = ".guardian-staging-" + secrets.token_hex(8)
        os.mkdir(self.staging, 0o700, dir_fd=dest_fd)
        try:
            self.staging_fd = open_dir_nofollow(self.staging, dir_fd=dest_fd)
            st = os.fstat(self.staging_fd)
        except OSError:
            raise SecurityViolation("staging directory was replaced", code="UNTRUSTED_PATH") from None
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
            # Someone who can write the destination swapped our directory.
            os.close(self.staging_fd)
            raise SecurityViolation("staging directory was replaced", code="UNTRUSTED_PATH")
        self.names: List[Tuple[str, bool]] = []
        self.manifest: Optional[Dict[str, Any]] = None
        self._out = -1

    def accept_manifest(self, manifest: Dict[str, Any]) -> None:
        # Names are decided and checked against the destination before any payload byte is written.
        self.manifest = manifest
        self.names = plan_names(manifest["objects"], self.policy)
        for final, _ in self.names:
            if _exists(final, self.dest_fd):
                raise SecurityViolation("destination already contains %s; nothing is overwritten" % final,
                                        code="DESTINATION_EXISTS")

    def begin(self, index: int, obj: Dict[str, Any]) -> None:
        self._out = os.open("obj-%d" % index, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                            0o600, dir_fd=self.staging_fd)
        if self.owner is not None:
            os.fchown(self._out, self.owner[0], self.owner[1])  # released files belong to the requester
        os.fchmod(self._out, self.file_mode)

    def write(self, data: bytes) -> None:
        write_all(self._out, data)

    def end(self, index: int) -> None:
        os.fsync(self._out)
        os.close(self._out)
        self._out = -1

    def publish(self) -> List[str]:
        """Move every staged object to its final name; undo all of them if one fails."""
        published: List[str] = []
        try:
            for index, (final, _) in enumerate(self.names):
                staged = "obj-%d" % index
                _move_no_replace(self.staging_fd, staged, self.dest_fd, final)
                published.append(final)
            fsync_dir(self.dest_fd)
        except BaseException:
            for name in published:
                try:
                    os.unlink(name, dir_fd=self.dest_fd)
                except OSError:
                    pass
            raise
        return published

    def cleanup(self) -> None:
        if self._out >= 0:
            os.close(self._out)
            self._out = -1
        for name in os.listdir(self.staging_fd):
            os.unlink(name, dir_fd=self.staging_fd)
        os.close(self.staging_fd)
        os.rmdir(self.staging, dir_fd=self.dest_fd)


def _exists(name: str, dir_fd: int) -> bool:
    try:
        os.lstat(name, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    return True


def _move_no_replace(src_dir: int, src: str, dst_dir: int, dst: str) -> None:
    try:
        # link() fails if the target exists, so a racing file is never replaced.
        os.link(src, dst, src_dir_fd=src_dir, dst_dir_fd=dst_dir, follow_symlinks=False)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise SecurityViolation("destination already contains %s" % dst, code="DESTINATION_EXISTS") from None
        if exc.errno not in (errno.EPERM, errno.EOPNOTSUPP, errno.ENOTSUP, errno.EXDEV):
            raise
        # Filesystem without hard links (FAT/exFAT): check, then rename.
        if _exists(dst, dst_dir):
            raise SecurityViolation("destination already contains %s" % dst, code="DESTINATION_EXISTS") from None
        os.rename(src, dst, src_dir_fd=src_dir, dst_dir_fd=dst_dir)
        return
    os.unlink(src, dir_fd=src_dir)


def _open_destination(dest_dir: Optional[Path], dest_fd: Optional[int], owner_uid: int) -> int:
    try:
        fd = os.dup(dest_fd) if dest_fd is not None else open_dir_nofollow(dest_dir)  # type: ignore[arg-type]
    except OSError as exc:
        raise SecurityViolation("cannot open destination: %s" % exc.strerror, code="UNTRUSTED_PATH") from None
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner_uid or st.st_mode & 0o022:
        os.close(fd)
        raise SecurityViolation("destination must be a directory owned by the requester and not writable by others",
                                code="UNTRUSTED_PATH")
    return fd


def release_package(fd: int, verifier: Verifier, dest_dir: Optional[Path] = None, *, dest_fd: Optional[int] = None,
                    owner: Optional[Tuple[int, int]] = None, start: int = 0, require_end: bool = True,
                    name_policy: str = "strict", file_mode: int = 0o600) -> Dict[str, Any]:
    """Verify a package and, only if every check passes, release its objects into the destination.

    The destination is a path or an open directory fd (from a broker client).
    With ``owner`` (uid, gid), released files are owned by that user and the
    destination must belong to them.
    """
    if (dest_dir is None) == (dest_fd is None):
        raise ValidationError("give exactly one of dest_dir or dest_fd")
    if file_mode & ~0o644 or not file_mode & 0o400:
        raise ValidationError("file mode must be readable by the owner and not writable by others")
    if name_policy not in NAME_POLICIES:
        raise ValidationError("unknown name policy")
    dest_fd = _open_destination(None if dest_dir is None else Path(dest_dir), dest_fd,
                                owner[0] if owner is not None else os.geteuid())
    try:
        sink = _StagingSink(dest_fd, name_policy, file_mode, owner)
        try:
            report = verify_package(fd, verifier, start=start, sink=sink, require_end=require_end)
            sink.publish()
        finally:
            sink.cleanup()
        manifest = report["manifest"]
        released = []
        for index, (obj, (final, renamed)) in enumerate(zip(manifest["objects"], sink.names)):
            released.append({"index": index, "name": final, "renamed": renamed, "source_name": obj["source_name"],
                             "sha256": obj["sha256"], "length": obj["length"]})
        return {"transfer_id": report["transfer_id"], "manifest_digest": report["manifest_digest"],
                "package_sha256": report["package_sha256"], "key_id": report["key_id"], "released": released}
    finally:
        os.close(dest_fd)
