# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only block device collection from sysfs and mountinfo.

Everything read here is reported by the device or the kernel on the
device's behalf (USB descriptors, SCSI INQUIRY, MMC CID), so it is untrusted
data. Reads are bounded, symlinks are resolved only when they stay inside
the sysfs root, and values are kept as reported (never cleaned up) so the
identity fingerprint reflects exactly what the device presented. Rendering
for display is the caller's job (``display_text``).

No external tools are run: workers cannot fork (RLIMIT_NPROC 0).
"""

from __future__ import annotations

import os
import re
import stat
from typing import Any, Dict, List, Optional, Tuple

from ..common.errors import NotFound, ValidationError
from ..common.fsutil import read_bounded

KNAME_RE = re.compile(r"^[a-z][a-z0-9]{0,31}$")
PART_KNAME_RE = re.compile(r"^[a-z][a-z0-9]{0,31}$")
HOLDER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")  # dm-0, md127
USB_INTERFACE_RE = re.compile(r"^\d{1,3}-[\d.]{1,32}:\d{1,3}\.\d{1,3}$")
SKIPPED_PREFIXES = ("loop", "ram", "zram", "dm-", "md", "nbd", "sr", "fd", "mtdblock", "zd")
MAX_ATTR = 4096
MAX_DEVICES = 256
MAX_PARTITIONS = 128
MAX_INTERFACES = 32
MAX_MOUNTS = 4096
MAX_MOUNTINFO = 4 * 1024 * 1024
INVALID_UTF8_PREFIX = "invalid-utf8:"

USB_DEVICE_ATTRS = {
    "vendor_id": "idVendor", "product_id": "idProduct", "bcd_device": "bcdDevice",
    "manufacturer": "manufacturer", "product": "product", "serial": "serial", "speed": "speed",
    "usb_version": "version", "device_class": "bDeviceClass",
}
MMC_ATTRS = ("cid", "csd", "name", "manfid", "oemid", "serial", "date", "type", "fwrev", "hwrev")


def decode_attr(data: bytes) -> str:
    """Keep valid UTF-8 as text; represent anything else losslessly as hex."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return INVALID_UTF8_PREFIX + data.hex()


def read_attr(directory: str, name: str, limit: int = MAX_ATTR) -> Optional[str]:
    try:
        fd = os.open(os.path.join(directory, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = read_bounded(fd, limit + 1)
    except OSError:
        return None  # some sysfs attributes fail on read (EIO, EINVAL)
    finally:
        os.close(fd)
    if len(data) > limit:
        return None
    if data.endswith(b"\n"):
        data = data[:-1]
    return decode_attr(data)


def _int_attr(directory: str, name: str) -> Optional[int]:
    value = read_attr(directory, name, 32)
    if value is None or not re.fullmatch(r"\d{1,20}", value.strip()):
        return None
    return int(value.strip())


def _bool_attr(directory: str, name: str) -> Optional[bool]:
    value = _int_attr(directory, name)
    return None if value is None else value != 0


class SysfsScanner:
    def __init__(self, sysfs_root: str = "/sys", mountinfo_path: str = "/proc/self/mountinfo"):
        self.root = os.path.realpath(sysfs_root)
        self.mountinfo_path = mountinfo_path

    # -- path helpers -----------------------------------------------------

    def _resolve(self, path: str) -> Optional[str]:
        """Resolve a sysfs link, refusing anything that leaves the sysfs root."""
        real = os.path.realpath(path)
        if real == self.root or real.startswith(self.root + os.sep):
            return real
        return None

    def _ancestors(self, path: str) -> List[str]:
        out = []
        stop = os.path.join(self.root, "devices")
        current = os.path.dirname(path)
        while current.startswith(stop + os.sep):
            out.append(current)
            current = os.path.dirname(current)
        return out

    # -- collection -------------------------------------------------------

    def block_names(self) -> List[str]:
        try:
            names = sorted(os.listdir(os.path.join(self.root, "block")))
        except OSError:
            return []
        return [n for n in names if KNAME_RE.match(n) and not n.startswith(SKIPPED_PREFIXES)][:MAX_DEVICES]

    def scan(self) -> List[Dict[str, Any]]:
        mounts = self.read_mounts()
        devices = []
        for name in self.block_names():
            dev = self._collect(name, mounts)
            if dev is not None:
                devices.append(dev)
        return devices

    def inspect(self, kname: str) -> Dict[str, Any]:
        if not isinstance(kname, str) or not KNAME_RE.match(kname) or kname.startswith(SKIPPED_PREFIXES):
            raise ValidationError("invalid device name")
        if kname not in self.block_names():
            raise NotFound("no such block device")
        dev = self._collect(kname, self.read_mounts())
        if dev is None:
            raise NotFound("block device could not be read")
        return dev

    def kernel_facts(self, kname: str) -> Dict[str, Any]:
        """Kernel-side facts: device number, bus topology, holders and size.

        The device number, topology and holders are produced by the kernel,
        and the size is a plain number the kernel parsed. The broker reads
        these itself, without parsing any device-supplied strings, and uses
        them to cross-check a worker's report before a destructive operation.
        """
        if not isinstance(kname, str) or not KNAME_RE.match(kname) or kname not in self.block_names():
            raise NotFound("no such block device")
        dev_dir = self._resolve(os.path.join(self.root, "block", kname))
        if dev_dir is None:
            raise NotFound("no such block device")
        sectors = _int_attr(dev_dir, "size")
        _, transport = self._transport(dev_dir, self._resolve(os.path.join(dev_dir, "device")))
        held = bool(self._holders(dev_dir)) or any(p["_holders"] for p in self._partitions(dev_dir))
        return {"dev": read_attr(dev_dir, "dev", 32), "size_bytes": None if sectors is None else sectors * 512,
                "transport": transport, "holders": held}

    def _collect(self, kname: str, mounts: List[Dict[str, str]]) -> Optional[Dict[str, Any]]:
        dev_dir = self._resolve(os.path.join(self.root, "block", kname))
        if dev_dir is None or not os.path.isdir(dev_dir):
            return None
        sectors = _int_attr(dev_dir, "size")
        devnum = read_attr(dev_dir, "dev", 32)
        device_link = self._resolve(os.path.join(dev_dir, "device"))
        usb_dir, transport = self._transport(dev_dir, device_link)
        partitions = self._partitions(dev_dir)
        holders = self._holders(dev_dir) + [h for p in partitions for h in p.pop("_holders")]
        own_devs = {devnum} | {p["dev"] for p in partitions}
        own_sources = {"/dev/" + kname} | {"/dev/" + p["kname"] for p in partitions}
        return {
            "kname": kname,
            "dev": devnum,
            "size_bytes": None if sectors is None else sectors * 512,  # sysfs size is in 512-byte units
            "logical_block_size": _int_attr(os.path.join(dev_dir, "queue"), "logical_block_size"),
            "physical_block_size": _int_attr(os.path.join(dev_dir, "queue"), "physical_block_size"),
            "removable": _bool_attr(dev_dir, "removable"),
            "read_only": _bool_attr(dev_dir, "ro"),
            "rotational": _bool_attr(os.path.join(dev_dir, "queue"), "rotational"),
            "transport": transport,
            "scsi": self._scsi(device_link) if transport == "usb" else None,
            "mmc": self._mmc(device_link) if transport == "mmc" else None,
            "usb": self._usb(usb_dir) if usb_dir else None,
            "partitions": partitions,
            "holders": sorted(set(holders)),
            "mounts": [m for m in mounts if m["device"] in own_devs or m["source"] in own_sources],
        }

    def _transport(self, dev_dir: str, device_link: Optional[str]) -> Tuple[Optional[str], str]:
        for ancestor in self._ancestors(dev_dir):
            if os.path.isfile(os.path.join(ancestor, "idVendor")):
                return ancestor, "usb"
        if device_link and os.path.isfile(os.path.join(device_link, "cid")):
            return None, "mmc"
        rel = dev_dir[len(self.root):]
        for marker, name in (("/nvme", "nvme"), ("/virtio", "virtio"), ("/ata", "ata")):
            if marker in rel:
                return None, name
        return None, "other"

    def _scsi(self, device_link: Optional[str]) -> Optional[Dict[str, Optional[str]]]:
        if not device_link:
            return None
        return {k: read_attr(device_link, k, 256) for k in ("vendor", "model", "rev")}

    def _mmc(self, device_link: Optional[str]) -> Optional[Dict[str, Optional[str]]]:
        if not device_link:
            return None
        return {k: read_attr(device_link, k, 256) for k in MMC_ATTRS}

    def _usb(self, usb_dir: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {k: read_attr(usb_dir, attr, 512) for k, attr in USB_DEVICE_ATTRS.items()}
        info["port"] = os.path.basename(usb_dir)
        info["num_configurations"] = _int_attr(usb_dir, "bNumConfigurations")
        info["configuration"] = _int_attr(usb_dir, "bConfigurationValue")
        info["authorized"] = _bool_attr(usb_dir, "authorized")
        interfaces = []
        try:
            children = sorted(os.listdir(usb_dir))
        except OSError:
            children = []
        for child in children:
            path = os.path.join(usb_dir, child)
            if not USB_INTERFACE_RE.match(child) or not os.path.isfile(os.path.join(path, "bInterfaceClass")):
                continue
            driver = None
            driver_link = os.path.join(path, "driver")
            if os.path.islink(driver_link):
                driver = os.path.basename(os.readlink(driver_link))[:64]
            interfaces.append({
                "name": child,
                "class": read_attr(path, "bInterfaceClass", 8),
                "subclass": read_attr(path, "bInterfaceSubClass", 8),
                "protocol": read_attr(path, "bInterfaceProtocol", 8),
                "driver": driver,
                "authorized": _bool_attr(path, "authorized"),
            })
        info["interfaces"] = interfaces[:MAX_INTERFACES]
        info["interfaces_truncated"] = len(interfaces) > MAX_INTERFACES
        return info

    def _holders(self, directory: str) -> List[str]:
        try:
            return [h for h in os.listdir(os.path.join(directory, "holders")) if HOLDER_RE.match(h)]
        except OSError:
            return []

    def _partitions(self, dev_dir: str) -> List[Dict[str, Any]]:
        parts = []
        try:
            children = sorted(os.listdir(dev_dir))
        except OSError:
            return parts
        for child in children:
            path = os.path.join(dev_dir, child)
            if not PART_KNAME_RE.match(child) or not os.path.isfile(os.path.join(path, "partition")):
                continue
            parts.append({
                "kname": child,
                "number": _int_attr(path, "partition"),
                "start_sectors": _int_attr(path, "start"),
                "size_sectors": _int_attr(path, "size"),
                "dev": read_attr(path, "dev", 32),
                "read_only": _bool_attr(path, "ro"),
                "_holders": self._holders(path),
            })
            if len(parts) >= MAX_PARTITIONS:
                break
        return parts

    def read_mounts(self) -> List[Dict[str, str]]:
        try:
            fd = os.open(self.mountinfo_path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError:
            return []
        try:
            data = read_bounded(fd, MAX_MOUNTINFO)
        finally:
            os.close(fd)
        return parse_mountinfo(data)


def _unescape_mount_field(raw: bytes) -> str:
    unescaped = re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8) & 0xFF]), raw)
    return unescaped.decode("utf-8", "replace")


def parse_mountinfo(data: bytes) -> List[Dict[str, str]]:
    """Parse /proc/<pid>/mountinfo into device, mount point and source."""
    mounts = []
    for line in data.split(b"\n"):
        if not line:
            continue
        head, sep, tail = line.partition(b" - ")
        fields = head.split(b" ")
        if not sep or len(fields) < 5:
            continue
        tail_fields = tail.split(b" ")
        majmin = fields[2].decode("ascii", "replace")
        mounts.append({
            "device": majmin if re.fullmatch(r"\d{1,5}:\d{1,7}", majmin) else "",
            "mountpoint": _unescape_mount_field(fields[4]),
            "source": _unescape_mount_field(tail_fields[1]) if len(tail_fields) > 1 else "",
        })
        if len(mounts) >= MAX_MOUNTS:
            break
    return mounts
