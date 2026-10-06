# SPDX-License-Identifier: GPL-3.0-or-later
"""USB Airlock (ROADMAP D10): RED -> quarantine -> inspection -> approval -> GREEN.

    airlock.inspect   (airlock.read)            RED device identity, BadUSB findings, storage structure
    airlock.acquire   (airlock.acquire, touch)  mount one RED volume read-only (ro,noexec,nodev,nosuid),
                                                copy regular files into a private quarantine, unmount,
                                                then inspect every file in sandboxed workers
    airlock.sessions  (airlock.read)            list quarantine sessions
    airlock.session   (airlock.read)            one session's items, findings and states (paged)
    airlock.export    (airlock.export, touch)   approve exact items by hash and write them to a GREEN
                                                directory (passed fd), with read-back verification
    airlock.discard   (airlock.acquire, touch)  delete a session's quarantine copies

Rules that hold throughout:
- RED is never copied to GREEN directly, and RED must be detached before
  an export. Only approved regular files reach GREEN: no partition table,
  boot sector, EFI partition or image of the volume.
- Nothing from RED is executed. Quarantine copies get Guardian-generated
  names and no execute bits; source paths are kept as data only.
- Only PASS and (with acknowledgement) REVIEW_REQUIRED items can be
  exported. BLOCKED, MALWARE_DETECTED_BY_SCANNER, STRUCTURAL_ANOMALY and
  UNSUPPORTED_FILE_TYPE never can. A missing or failing scanner blocks.
- The owner's touch for an export is bound to the item ids, their hashes
  and the GREEN device identity (the request digest covers all of them).
- Each item is re-hashed before export; the destination copy is read back
  (page cache dropped first) and must match, or the export stops with
  TRANSFER_INTEGRITY_FAILURE and the partial copy is removed.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

from .. import APP_VERSION
from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import (GuardianError, IntegrityError, NotFound, ResourceLimitExceeded, SecurityViolation,
                             ValidationError)
from ..common.fsutil import atomic_write, ensure_private_dir, fsync_dir, open_dir_nofollow, read_file_bounded, \
    write_all
from ..common.names import check_component, sanitize_component
from ..common.space import DEFAULT_POLICY, SpaceGuard, SpacePolicy
from ..common.text import display_text
from ..common.tools import SAFE_ENV, require_tool
from ..devices.assess import SEV_BLOCKING, SEV_REVIEW
from ..devices.handlers import KNAME_PATTERN
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.workers import WorkerLauncher
from ..vault.custody import utc_timestamp
from ..vault.operations import _check_fd
from . import content as C
from .handlers import CONTENT_PROFILE, MAX_BATCH, SCAN_PROFILE, STRUCTURE_PROFILE
from .structure import SUPPORTED_FILESYSTEMS

POLICY_VERSION = "airlock-policy/1"
EXPORTABLE = ("PASS", "REVIEW_REQUIRED")
SESSION_ID = r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}"
SKIP_DIRS = frozenset({"system volume information", "$recycle.bin", "recycler", "recycled", "lost+found",
                       "found.000", "$extend", "msocache", ".trashes", ".spotlight-v100", ".fseventsd"})
AUTORUN_NAMES = frozenset({"autorun.inf", "desktop.ini", ".autorun", "autorun.sh", ".directory"})
CHUNK = 1024 * 1024
SESSION_LIMIT = 8 * 1024 * 1024


class Limits:
    def __init__(self, *, max_files: int = 2048, max_entries: int = 20000, max_depth: int = 16,
                 max_file_bytes: int = 512 * 1024 ** 2, max_total_bytes: int = 4 * 1024 ** 3):
        self.max_files = max_files
        self.max_entries = max_entries
        self.max_depth = max_depth
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes


class Mounter(Protocol):
    def mount(self, device: str, fstype: str, target: Path, expected_dev: str) -> None: ...
    def unmount(self, target: Path) -> None: ...


class SystemMounter:
    """mount(8)/umount(8) from trusted system directories.  Options are fixed here."""

    KERNEL_TYPES = {"vfat": "vfat", "exfat": "exfat", "ntfs": "ntfs3", "ext2": "ext4", "ext3": "ext4", "ext4": "ext4"}

    def mount(self, device: str, fstype: str, target: Path, expected_dev: str) -> None:
        options = "ro,noexec,nodev,nosuid,noatime"
        if fstype.startswith("ext"):
            options += ",noload"  # never replay a journal from hostile media
        argv = [require_tool("mount"), "-t", self.KERNEL_TYPES[fstype], "-o", options, "--", device, str(target)]
        proc = subprocess.run(argv, env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                              check=False)
        if proc.returncode != 0:
            raise GuardianError("read-only mount failed: %s" % display_text(proc.stderr[:300], 300),
                                code="MOUNT_FAILED")
        if not _mounted_readonly(target, expected_dev):
            self.unmount(target)
            raise SecurityViolation("the mount is not the expected read-only volume", code="MOUNT_UNEXPECTED")

    def unmount(self, target: Path) -> None:
        proc = subprocess.run([require_tool("umount"), "--", str(target)], env=dict(SAFE_ENV),
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=120, check=False)
        if proc.returncode != 0:
            raise GuardianError("unmount failed; the RED volume may still be mounted at %s" % target,
                                code="UNMOUNT_FAILED")


def _mounted_readonly(target: Path, expected_dev: str, mountinfo: str = "/proc/self/mountinfo") -> bool:
    with open(mountinfo, "rb") as fh:
        for line in fh.read(4 * 1024 * 1024).decode("utf-8", "replace").splitlines():
            fields = line.split()
            if len(fields) > 6 and fields[4] == str(target):
                opts = fields[5].split(",")
                return fields[2] == expected_dev and "ro" in opts and {"nodev", "noexec", "nosuid"} <= set(opts)
    return False


def open_device_readonly(path: str, expected_dev: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISBLK(st.st_mode) or "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev)) != expected_dev:
            raise SecurityViolation("opened node is not the inspected device", code="DEVICE_IDENTITY_CHANGED")
    except BaseException:
        os.close(fd)
        raise
    return fd


def disk_of_fd(fd: int, sysfs_root: str = "/sys") -> Optional[str]:
    """Kernel name of the whole disk holding the filesystem of ``fd`` (None if not a block device)."""
    st = os.fstat(fd)
    link = os.path.join(sysfs_root, "dev", "block", "%d:%d" % (os.major(st.st_dev), os.minor(st.st_dev)))
    try:
        real = os.path.realpath(link)
    except OSError:
        return None
    if not os.path.isdir(real):
        return None
    if os.path.exists(os.path.join(real, "partition")):
        real = os.path.dirname(real)
    name = os.path.basename(real)
    return name if re.fullmatch(KNAME_PATTERN, name) else None


Scanner = Callable[[List[int]], Dict[str, Any]]  # read-only fds -> {available, version, results}


class AirlockService:
    def __init__(self, directory: Path, launcher: WorkerLauncher, *, worker_gid: Optional[int] = None,
                 inspect_device: Optional[Callable[[str], Dict[str, Any]]] = None,
                 list_devices: Optional[Callable[[], List[Dict[str, Any]]]] = None,
                 open_device: Callable[[str, str], int] = open_device_readonly,
                 mounter: Optional[Mounter] = None, scanner: Optional[Scanner] = None,
                 device_of_fd: Callable[[int], Optional[str]] = disk_of_fd, dev_root: str = "/dev",
                 mount_root: Path = Path("/run/usbguardian/airlock"), limits: Limits = Limits(),
                 space_policy: SpacePolicy = DEFAULT_POLICY, audit: Optional[Any] = None):
        from ..devices.operations import DEVICE_PROFILE
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.launcher = launcher
        self.worker_gid = worker_gid
        self.inspect_device = inspect_device or (
            lambda kname: launcher.run(DEVICE_PROFILE, "devices.inspect", {"kname": kname}))
        self.list_devices = list_devices or (lambda: launcher.run(DEVICE_PROFILE, "devices.scan", {})["devices"])
        self.open_device = open_device
        self.mounter = mounter or SystemMounter()
        self.scanner = scanner or (lambda fds: launcher.run(SCAN_PROFILE, "airlock.clamscan", {"fds": fds},
                                                            fds=tuple(fds)))
        self.device_of_fd = device_of_fd
        self.dev_root = dev_root
        self.mount_root = Path(mount_root)
        self.limits = limits
        self.space_policy = space_policy
        self.audit = audit
        self._busy = threading.Lock()

    # -- RED inspection --------------------------------------------------------------------------

    def _structure(self, report: Dict[str, Any]) -> Dict[str, Any]:
        dev = report["device"]
        fd = self.open_device(os.path.join(self.dev_root, dev["kname"]), dev["dev"])
        try:
            return self.launcher.run(STRUCTURE_PROFILE, "airlock.structure",
                                     {"fd": fd, "size": dev["size_bytes"],
                                      "logical_block_size": dev.get("logical_block_size") or 512}, fds=(fd,))
        finally:
            os.close(fd)

    def _red_report(self, kname: str) -> Dict[str, Any]:
        report = self.inspect_device(kname)
        structure = self._structure(report)
        findings = list(report["findings"]) + list(structure["findings"])
        codes = {f["severity"] for f in findings}
        verdict = "BLOCKED" if SEV_BLOCKING in codes else "REVIEW_REQUIRED" if SEV_REVIEW in codes else "PASS"
        dev = report["device"]
        usb = dev.get("usb") or {}
        return {"kname": kname, "fingerprint": report["fingerprint"], "verdict": verdict,
                "device": {"dev": dev["dev"], "size_bytes": dev["size_bytes"], "transport": dev.get("transport"),
                           "vendor_id": usb.get("vendor_id"), "product_id": usb.get("product_id"),
                           "manufacturer": display_text(usb.get("manufacturer"), 64),
                           "product": display_text(usb.get("product"), 64),
                           "serial": display_text(usb.get("serial"), 64),
                           "interfaces": usb.get("interfaces", []),
                           "logical_block_size": dev.get("logical_block_size"),
                           "physical_block_size": dev.get("physical_block_size"),
                           "partitions": dev.get("partitions", [])},
                "structure": {k: structure[k] for k in ("scheme", "whole_filesystem", "partitions")},
                "findings": findings}

    def inspect(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return self._red_report(params["kname"])

    # -- acquisition -----------------------------------------------------------------------------

    def _volume(self, red: Dict[str, Any], index: int) -> Tuple[str, str, str]:
        """(device node name, expected dev, fstype) of the volume to mount."""
        st = red["structure"]
        if index == 0:
            if st["scheme"] != "superfloppy":
                raise ValidationError("the device has a partition table; choose a partition")
            return red["kname"], red["device"]["dev"], st["whole_filesystem"]
        part = next((p for p in st["partitions"] if p["index"] == index), None)
        if part is None:
            raise NotFound("no such partition")
        if part["type"] in ("efi_system", "bios_boot"):
            raise SecurityViolation("boot partitions are not acquired in data-transfer mode", code="BOOT_PARTITION")
        kernel = [p for p in red["device"]["partitions"] if p.get("start_sectors") is not None
                  and p["start_sectors"] * 512 == part["start"]]
        if len(kernel) != 1:
            raise IntegrityError("kernel partition list disagrees with the partition table", code="LAYOUT_MISMATCH")
        return kernel[0]["kname"], kernel[0]["dev"], part.get("filesystem")

    def acquire(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        if not self._busy.acquire(blocking=False):
            raise ResourceLimitExceeded("another airlock acquisition is running")
        try:
            return self._acquire(principal, params)
        finally:
            self._busy.release()

    def _acquire(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        red = self._red_report(params["kname"])
        if red["fingerprint"] != params["fingerprint"]:
            raise SecurityViolation("RED device identity differs from the one inspected (removed or reassigned)",
                                    code="DEVICE_IDENTITY_CHANGED")
        if red["verdict"] == "BLOCKED":
            raise SecurityViolation("RED device is BLOCKED: %s" % ", ".join(
                sorted({f["code"] for f in red["findings"] if f["severity"] == SEV_BLOCKING})), code="RED_BLOCKED")
        if red["verdict"] == "REVIEW_REQUIRED" and not params["accept_review"]:
            raise ValidationError("RED device needs review; acquire again with accept_review after checking "
                                  "the findings", code="RED_REVIEW_REQUIRED")
        node, devnum, fstype = self._volume(red, params["partition"])
        if fstype not in SUPPORTED_FILESYSTEMS:
            raise ValidationError("filesystem %s is not supported for acquisition" % fstype,
                                  code="UNSUPPORTED_FILESYSTEM")
        sid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
        sdir = self.directory / sid
        ensure_private_dir(sdir)
        ensure_private_dir(sdir / "q")
        session: Dict[str, Any] = {
            "version": 1, "session_id": sid, "created": utc_timestamp(), "guardian_version": APP_VERSION,
            "policy_version": POLICY_VERSION, "principal": principal.name, "state": "acquiring",
            "red": {"kname": red["kname"], "fingerprint": red["fingerprint"], "volume": node, "dev": devnum,
                    "filesystem": fstype, "partition": params["partition"], "verdict": red["verdict"],
                    "identity": red["device"], "findings": red["findings"]},
            "items": [], "skipped": [], "scanner_version": "", "exports": []}
        self._save(session)
        target = self.mount_root / sid
        os.makedirs(self.mount_root, mode=0o700, exist_ok=True)
        os.mkdir(target, 0o700)
        try:
            self.mounter.mount(os.path.join(self.dev_root, node), fstype, target, devnum)
            try:
                self._copy_tree(target, sdir / "q", session)
            finally:
                self.mounter.unmount(target)
        except BaseException:
            session["state"] = "failed"
            self._save(session)
            raise
        finally:
            try:
                os.rmdir(target)
            except OSError:
                pass
        after = self.inspect_device(params["kname"])
        if after["fingerprint"] != params["fingerprint"]:
            session["state"] = "failed"
            self._save(session)
            raise IntegrityError("RED device changed during acquisition", code="DEVICE_IDENTITY_CHANGED")
        self._inspect_items(sdir, session)
        session["state"] = "inspected"
        self._save(session)
        if self.audit is not None:
            self.audit.append("airlock.acquired", session=sid, red=red["fingerprint"], items=len(session["items"]),
                              skipped=len(session["skipped"]))
        return self._summary(session)

    def _copy_tree(self, root: Path, qdir: Path, session: Dict[str, Any]) -> None:
        counters = {"entries": 0, "bytes": 0}
        guard = SpaceGuard(str(qdir), total=None, what="airlock quarantine", policy=self.space_policy)
        guard.start(files=1)
        root_fd = open_dir_nofollow(root)
        q_fd = open_dir_nofollow(qdir)
        try:
            self._walk(root_fd, "", 0, q_fd, session, counters, guard)
        finally:
            os.close(root_fd)
            os.close(q_fd)

    def _skip(self, session: Dict[str, Any], path: str, reason: str) -> None:
        if len(session["skipped"]) < 1000:
            session["skipped"].append({"source_path": display_text(path, 300), "reason": reason})

    def _walk(self, dir_fd: int, prefix: str, depth: int, q_fd: int, session: Dict[str, Any],
              counters: Dict[str, int], guard: SpaceGuard) -> None:
        lim = self.limits
        with os.scandir(dir_fd) as it:
            entries = sorted(it, key=lambda e: e.name)
        for entry in entries:
            counters["entries"] += 1
            if counters["entries"] > lim.max_entries:
                raise ResourceLimitExceeded("RED volume has more than %d entries" % lim.max_entries)
            name = entry.name
            path = prefix + name
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                self._skip(session, path, "SYMLINK_NOT_FOLLOWED")
            elif stat.S_ISDIR(st.st_mode):
                if name.lower() in SKIP_DIRS:
                    self._skip(session, path + "/", "SYSTEM_DIRECTORY")
                elif depth + 1 > lim.max_depth:
                    self._skip(session, path + "/", "TOO_DEEP")
                else:
                    sub = open_dir_nofollow(name, dir_fd=dir_fd)
                    try:
                        self._walk(sub, path + "/", depth + 1, q_fd, session, counters, guard)
                    finally:
                        os.close(sub)
            elif not stat.S_ISREG(st.st_mode):
                self._skip(session, path, "SPECIAL_FILE")
            elif st.st_size > lim.max_file_bytes:
                self._skip(session, path, "TOO_LARGE")
            elif len(session["items"]) >= lim.max_files:
                self._skip(session, path, "TOO_MANY_FILES")
            elif counters["bytes"] + st.st_size > lim.max_total_bytes:
                self._skip(session, path, "TOTAL_LIMIT")
            else:
                counters["bytes"] += self._copy_file(dir_fd, name, path, st, q_fd, session, guard)

    def _copy_file(self, dir_fd: int, name: str, path: str, st: os.stat_result, q_fd: int,
                   session: Dict[str, Any], guard: SpaceGuard) -> int:
        item = len(session["items"]) + 1
        qname = "%06d" % item
        src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            fst = os.fstat(src)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                raise SecurityViolation("file changed while acquiring", code="SOURCE_CHANGED")
            dst = os.open(qname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                          dir_fd=q_fd)
            try:
                h = hashlib.sha256()
                total = 0
                while True:
                    chunk = os.read(src, CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.limits.max_file_bytes:
                        raise ResourceLimitExceeded("file grew beyond the limit while acquiring")
                    guard.advance(len(chunk))
                    write_all(dst, chunk)
                    h.update(chunk)
                os.fsync(dst)
                self._share_with_worker(dst)
            finally:
                os.close(dst)
        finally:
            os.close(src)
        findings: List[Dict[str, Any]] = []
        for component in path.split("/"):
            reasons = check_component(component, max_len=255, allow_non_ascii=True, allow_leading_dash=True)
            if reasons:
                findings.append(C.finding("UNSAFE_SOURCE_NAME", SEV_REVIEW, "source name: %s" % ", ".join(reasons)))
                break
        if path.rsplit("/", 1)[-1].lower() in AUTORUN_NAMES:
            findings.append(C.finding("AUTORUN_FILE", SEV_REVIEW, "auto-run or shell metadata file"))
        if fst.st_nlink > 1:
            findings.append(C.finding("HARDLINKED_FILE", SEV_REVIEW, "file has %d hard links" % fst.st_nlink))
        if fst.st_mode & 0o111:
            findings.append(C.finding("SOURCE_EXECUTABLE_BIT", "INFO", "execute bits on RED are not carried over"))
        session["items"].append({"item": item, "quarantine": qname, "source_path": display_text(path, 1000),
                                 "size": total, "sha256": h.hexdigest(), "type": None, "findings": findings,
                                 "scanner": None, "state": "PENDING", "acquired": utc_timestamp()})
        return total

    def _share_with_worker(self, fd: int) -> None:
        """Quarantine copies: never executable; readable by the worker group so the scanner can reopen them."""
        if os.geteuid() == 0 and self.worker_gid is not None:
            os.fchown(fd, 0, self.worker_gid)
            os.fchmod(fd, 0o640)
        else:
            os.fchmod(fd, 0o600)

    # -- inspection ------------------------------------------------------------------------------

    def _open_items(self, sdir: Path, items: List[Dict[str, Any]]) -> List[int]:
        fds = []
        try:
            for it in items:
                fds.append(os.open(sdir / "q" / it["quarantine"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC))
        except BaseException:
            for fd in fds:
                os.close(fd)
            raise
        return fds

    def _inspect_items(self, sdir: Path, session: Dict[str, Any]) -> None:
        items = session["items"]
        for start in range(0, len(items), MAX_BATCH):
            batch = items[start:start + MAX_BATCH]
            fds = self._open_items(sdir, batch)
            try:
                try:
                    out = self.launcher.run(CONTENT_PROFILE, "airlock.inspect_files",
                                            {"files": [{"fd": fd, "name": it["source_path"][-255:]}
                                                       for fd, it in zip(fds, batch)]}, fds=tuple(fds))
                    results = S.validate(CONTENT_RESULTS, out, "$.inspection")["results"]
                    if len(results) != len(batch):
                        raise ValidationError("inspection result count mismatch")
                except GuardianError as exc:
                    results = [{"type": "unknown_binary", "details": {}, "findings": [
                        C.finding("TYPE_DETECTION_FAILED", SEV_BLOCKING, "inspection failed: %s" % exc.code)]}
                        for _ in batch]
                try:
                    scan = S.validate(SCAN_RESULTS, self.scanner(fds), "$.scan")
                    scans = scan["results"] if len(scan["results"]) == len(batch) else None
                    session["scanner_version"] = scan["version"] or ("unavailable" if not scan["available"] else "")
                except GuardianError:
                    scans = None
                if scans is None:
                    scans = [{"status": "error", "signature": "scanner failed"} for _ in batch]
            finally:
                for fd in fds:
                    os.close(fd)
            for it, res, sc in zip(batch, results, scans):
                it["type"] = res["type"]
                it["findings"] = it["findings"] + [dict(f, detail=display_text(f["detail"], 300)) for f in
                                                   res["findings"]]
                it["scanner"] = {"status": sc["status"], "signature": display_text(sc["signature"], 120)}
                it["state"] = C.item_state(res["type"], it["findings"], it["scanner"])

    # -- sessions --------------------------------------------------------------------------------

    def _path(self, sid: str) -> Path:
        if not re.fullmatch(SESSION_ID, sid):
            raise ValidationError("invalid session id")
        return self.directory / sid

    def _save(self, session: Dict[str, Any]) -> None:
        atomic_write(self._path(session["session_id"]) / "session.json", canonical_dumps(session))

    def _load(self, sid: str) -> Dict[str, Any]:
        path = self._path(sid) / "session.json"
        if not path.exists():
            raise NotFound("no such airlock session")
        return canonical_loads(read_file_bounded(path, SESSION_LIMIT, require_private=True),
                               require_canonical=True, max_bytes=SESSION_LIMIT)

    @staticmethod
    def _summary(session: Dict[str, Any]) -> Dict[str, Any]:
        states: Dict[str, int] = {}
        for it in session["items"]:
            states[it["state"]] = states.get(it["state"], 0) + 1
        return {"session_id": session["session_id"], "state": session["state"], "created": session["created"],
                "red": {k: session["red"][k] for k in ("kname", "fingerprint", "filesystem", "verdict")},
                "items": len(session["items"]), "skipped": len(session["skipped"]), "states": states,
                "scanner_version": session["scanner_version"], "exports": len(session["exports"])}

    def sessions(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        out = []
        for name in sorted(os.listdir(self.directory))[-64:]:
            if re.fullmatch(SESSION_ID, name):
                try:
                    out.append(self._summary(self._load(name)))
                except GuardianError:
                    out.append({"session_id": name, "state": "unreadable"})
        return {"sessions": out}

    def session(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        s = self._load(params["session_id"])
        start, limit = params["since"], params["limit"]
        return dict(self._summary(s), red=s["red"], items_page=s["items"][start:start + limit],
                    skipped_page=s["skipped"][:64], export_log=s["exports"][-8:])

    def discard(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        sdir = self._path(params["session_id"])
        self._load(params["session_id"])
        shutil.rmtree(sdir / "q")
        s = self._load(params["session_id"])
        s["state"] = "discarded"
        self._save(s)
        return {"session_id": s["session_id"], "state": "discarded"}

    # -- export ----------------------------------------------------------------------------------

    def _check_green(self, params: Dict[str, Any], session: Dict[str, Any], dest_fd: int) -> Dict[str, Any]:
        green = self.inspect_device(params["green_kname"])
        if green["fingerprint"] != params["green_fingerprint"]:
            raise SecurityViolation("GREEN device identity differs from the one approved", code="DESTINATION_MISMATCH")
        if green["fingerprint"] == session["red"]["fingerprint"] or params["green_kname"] == session["red"]["kname"]:
            raise SecurityViolation("GREEN is the RED device", code="GREEN_IS_RED")
        bad = sorted({f["code"] for f in green["findings"] if f["severity"] == SEV_BLOCKING} - {"MOUNTED"})
        if bad:
            raise SecurityViolation("GREEN device is not eligible: %s" % ", ".join(bad), code="DESTINATION_MISMATCH")
        if self.device_of_fd(dest_fd) != params["green_kname"]:
            raise SecurityViolation("the destination directory is not on the approved GREEN device",
                                    code="DESTINATION_MISMATCH")
        for dev in self.list_devices():
            if dev.get("fingerprint") == session["red"]["fingerprint"]:
                raise SecurityViolation("detach the RED device before exporting", code="RED_STILL_ATTACHED")
        return green

    def export(self, principal: authz.Principal, params: Dict[str, Any], session_ctx: Any) -> Any:
        assert session_ctx is not None
        fds = session_ctx.take_fds()
        try:
            dest_fd = fds[0]
            _check_fd(dest_fd, "dir")
            return self._export(principal, params, dest_fd)
        finally:
            for fd in fds:
                os.close(fd)

    def _export(self, principal: authz.Principal, params: Dict[str, Any], dest_fd: int) -> Any:
        sid = params["session_id"]
        session = self._load(sid)
        if session["state"] not in ("inspected", "exported"):
            raise ValidationError("session is %s" % session["state"])
        by_id = {it["item"]: it for it in session["items"]}
        chosen = []
        for req in params["items"]:
            it = by_id.get(req["item"])
            if it is None:
                raise NotFound("no item %d in this session" % req["item"])
            if it["sha256"] != req["sha256"]:
                raise IntegrityError("item %d hash differs from the approved one" % it["item"], code="APPROVAL_MISMATCH")
            if it["state"] not in EXPORTABLE:
                raise SecurityViolation("item %d is %s and cannot be exported" % (it["item"], it["state"]),
                                        code="ITEM_NOT_EXPORTABLE")
            if it["state"] == "REVIEW_REQUIRED" and not params["acknowledge_review"]:
                raise ValidationError("item %d needs review; export with acknowledge_review after checking it"
                                      % it["item"], code="REVIEW_NOT_ACKNOWLEDGED")
            chosen.append(it)
        green = self._check_green(params, session, dest_fd)
        sdir = self._path(sid)
        folder = "GUARDIAN-AIRLOCK-" + sid
        guard = SpaceGuard(dest_fd, total=sum(it["size"] for it in chosen) + 64 * 1024, what="airlock export",
                           policy=self.space_policy)
        guard.start(files=len(chosen) + 2)
        os.mkdir(folder, 0o755, dir_fd=dest_fd)  # fails if it exists: never overwrite
        out_fd = open_dir_nofollow(folder, dir_fd=dest_fd)
        record = {"export_id": secrets.token_hex(8), "started": utc_timestamp(), "principal": principal.name,
                  "green": {"kname": params["green_kname"], "fingerprint": green["fingerprint"]},
                  "folder": folder, "review_acknowledged": params["acknowledge_review"], "files": [],
                  "result": "incomplete"}
        try:
            used: set = set()
            for it in chosen:
                name = self._dest_name(it, used)
                dest_hash = self._export_one(sdir, it, out_fd, name, guard)
                record["files"].append({
                    "item": it["item"], "source_name": it["source_path"], "destination_name": name,
                    "size": it["size"], "detected_type": it["type"], "inspection_state": it["state"],
                    "scanner": it["scanner"], "quarantine_sha256": it["sha256"], "approved_sha256": it["sha256"],
                    "destination_sha256": dest_hash, "approval": "approved by owner touch",
                    "acquired": it["acquired"], "exported": utc_timestamp()})
            record["result"] = "verified"
            manifest = {"format": "guardian-airlock-manifest", "version": 1, "session_id": sid,
                        "guardian_version": APP_VERSION, "policy_version": POLICY_VERSION,
                        "scanner_version": session["scanner_version"],
                        "source_device": {k: session["red"][k] for k in ("kname", "fingerprint", "volume",
                                                                         "filesystem", "verdict")},
                        "export": record}
            fd = os.open("airlock-manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o644, dir_fd=out_fd)
            try:
                write_all(fd, canonical_dumps(manifest) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            fsync_dir(out_fd)
        except BaseException:
            record["result"] = "failed"
            raise
        finally:
            os.close(out_fd)
            session["exports"].append(record)
            if record["result"] == "verified":
                session["state"] = "exported"
            self._save(session)
            if self.audit is not None:
                self.audit.append("airlock.export", session=sid, result=record["result"],
                                  green=green["fingerprint"], files=len(record["files"]))
        return {"session_id": sid, "folder": folder, "files": len(record["files"]), "result": record["result"],
                "manifest": "airlock-manifest.json"}

    @staticmethod
    def _dest_name(it: Dict[str, Any], used: set) -> str:
        base = sanitize_component(it["source_path"].rsplit("/", 1)[-1], fallback="item-%06d" % it["item"])
        name, n = base, 1
        while name.lower() in used or name.lower() == "airlock-manifest.json":
            n += 1
            stem, dot, ext = base.rpartition(".")
            name = ("%s-%d.%s" % (stem, n, ext)) if dot and stem else "%s-%d" % (base, n)
        used.add(name.lower())
        return name

    def _export_one(self, sdir: Path, it: Dict[str, Any], out_fd: int, name: str, guard: SpaceGuard) -> str:
        src = os.open(sdir / "q" / it["quarantine"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        tmp = ".partial-" + secrets.token_hex(8)
        try:
            data_hash = hashlib.sha256()
            dst = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644,
                          dir_fd=out_fd)
            try:
                while True:
                    chunk = os.read(src, CHUNK)
                    if not chunk:
                        break
                    data_hash.update(chunk)
                    guard.advance(len(chunk))
                    write_all(dst, chunk)
                os.fsync(dst)
            finally:
                os.close(dst)
            if data_hash.hexdigest() != it["sha256"]:
                raise IntegrityError("item %d changed in quarantine after inspection" % it["item"],
                                     code="FILE_CHANGED_AFTER_INSPECTION")
            back = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=out_fd)
            try:
                if hasattr(os, "posix_fadvise"):
                    os.posix_fadvise(back, 0, 0, os.POSIX_FADV_DONTNEED)  # read the medium, not the cache
                rb = hashlib.sha256()
                while True:
                    chunk = os.read(back, CHUNK)
                    if not chunk:
                        break
                    rb.update(chunk)
            finally:
                os.close(back)
            if rb.hexdigest() != it["sha256"]:
                raise IntegrityError("destination copy of item %d does not match" % it["item"],
                                     code="TRANSFER_INTEGRITY_FAILURE")
            try:
                os.stat(name, dir_fd=out_fd, follow_symlinks=False)
                raise ValidationError("destination name exists", code="DESTINATION_EXISTS")
            except FileNotFoundError:
                pass
            os.rename(tmp, name, src_dir_fd=out_fd, dst_dir_fd=out_fd)
            tmp = ""
            return rb.hexdigest()
        finally:
            os.close(src)
            if tmp:
                try:
                    os.unlink(tmp, dir_fd=out_fd)
                except OSError:
                    pass

    # -- table -----------------------------------------------------------------------------------

    def operations(self) -> Iterable[Operation]:
        kname = S.Str(pattern=KNAME_PATTERN, max_len=32)
        fp = S.Str(pattern=r"[0-9a-f]{64}", max_len=64)
        sid = S.Str(pattern=SESSION_ID, max_len=32)
        return (
            Operation("airlock.inspect", "airlock.read", S.Obj({"kname": kname}), inline=self.inspect),
            Operation("airlock.acquire", "airlock.acquire",
                      S.Obj({"kname": kname, "fingerprint": fp, "partition": S.Int(min_value=0, max_value=16),
                             "accept_review": S.Bool()}),
                      inline=self.acquire, requires_active=True, pause_class="intake"),
            Operation("airlock.sessions", "airlock.read", S.EMPTY, inline=self.sessions),
            Operation("airlock.session", "airlock.read",
                      S.Obj({"session_id": sid, "since": S.Int(min_value=0, max_value=100000),
                             "limit": S.Int(min_value=1, max_value=128)}), inline=self.session),
            Operation("airlock.export", "airlock.export",
                      S.Obj({"session_id": sid, "green_kname": kname, "green_fingerprint": fp,
                             "acknowledge_review": S.Bool(),
                             "items": S.List(S.Obj({"item": S.Int(min_value=1, max_value=100000),
                                                    "sha256": S.Str(pattern=r"[0-9a-f]{64}", max_len=64)}),
                                             min_items=1, max_items=1024)}),
                      inline=self.export, session_aware=True, fds=(1, 1), requires_active=True,
                      pause_class="transfer_write"),
            Operation("airlock.discard", "airlock.acquire", S.Obj({"session_id": sid}), inline=self.discard),
        )


FINDING_SPEC = S.Obj({"code": S.Str(pattern=r"[A-Z][A-Z0-9_]{1,63}", max_len=64),
                      "severity": S.Enum(("INFO", "REVIEW", "BLOCKING")), "detail": S.Str(max_len=1024),
                      "lines": S.List(S.Int(min_value=0, max_value=2 ** 31), max_items=20)}, optional=("lines",))
# Worker output is untrusted: types and codes are checked before the broker uses them.
CONTENT_RESULTS = S.Obj({"results": S.List(S.Obj({
    "type": S.Enum(tuple(C.TYPE_POLICY)), "findings": S.List(FINDING_SPEC, max_items=256),
    "details": S.Obj({}, allow_extra=True)}), max_items=MAX_BATCH)})
SCAN_RESULTS = S.Obj({"available": S.Bool(), "version": S.Str(max_len=200),
                      "results": S.List(S.Obj({"status": S.Enum(("clean", "found", "error", "unavailable")),
                                               "signature": S.Str(max_len=200)}), max_items=MAX_BATCH)})
