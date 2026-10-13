# SPDX-License-Identifier: GPL-3.0-or-later
"""Device assessment: may Guardian use this device as Guardian media?

A BLOCKING finding means Guardian will not prepare, write or trust the
device. REVIEW means the device is usable but something is weaker than
expected. INFO is informational. The USB interface rules implement D4
step 1: a Guardian drive presents exactly one mass-storage interface and
nothing else, because extra interfaces (keyboard, network, serial) are how
BadUSB-style firmware attacks show up.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .scanner import INVALID_UTF8_PREFIX

SEV_INFO = "INFO"
SEV_REVIEW = "REVIEW"
SEV_BLOCKING = "BLOCKING"

GUARDIAN_TRANSPORTS = ("usb", "mmc")
MASS_STORAGE_CLASS = "08"
SCSI_TRANSPARENT = "06"
STORAGE_PROTOCOLS = {"50": "bulk-only", "62": "UAS"}
USB_CLASS_NAMES = {
    "01": "audio", "02": "communications", "03": "HID (keyboard/mouse)", "05": "physical", "06": "image",
    "07": "printer", "08": "mass storage", "09": "hub", "0a": "CDC data", "0b": "smart card",
    "0d": "content security", "0e": "video", "0f": "healthcare", "10": "audio/video", "11": "billboard",
    "12": "USB-C bridge", "dc": "diagnostic", "e0": "wireless controller", "ef": "miscellaneous",
    "fe": "application specific", "ff": "vendor specific",
}
SYSTEM_MOUNTPOINTS = frozenset({
    "/", "/boot", "/boot/efi", "/efi", "/home", "/usr", "/usr/local", "/var", "/var/log", "/var/lib",
    "/opt", "/srv", "/tmp", "/root",
})
LIVE_MOUNT_PREFIXES = ("/live", "/run/live", "/lib/live/mount", "/cdrom", "/run/initramfs/live",
                       "/run/initramfs/isoscan", "/run/archiso", "/isodevice", "/run/rootfsbase")
HEX_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def _finding(code: str, severity: str, detail: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def _hex(value: Optional[str]) -> Optional[str]:
    return value.lower() if isinstance(value, str) and HEX_BYTE_RE.match(value) else None


def _printable(value: Optional[str]) -> bool:
    if value is None:
        return True
    return not value.startswith(INVALID_UTF8_PREFIX) and all(0x20 <= ord(c) < 0x7F for c in value)


def _usb_findings(usb: Dict[str, Any]) -> List[Dict[str, str]]:
    out = []
    interfaces = usb.get("interfaces") or []
    if not interfaces:
        out.append(_finding("USB_NO_INTERFACES", SEV_BLOCKING, "no USB interfaces could be read"))
    if usb.get("interfaces_truncated"):
        out.append(_finding("USB_TOO_MANY_INTERFACES", SEV_BLOCKING, "device presents an excessive number of interfaces"))
    storage = 0
    for iface in interfaces:
        cls, sub, proto = _hex(iface.get("class")), _hex(iface.get("subclass")), _hex(iface.get("protocol"))
        if cls == MASS_STORAGE_CLASS and sub == SCSI_TRANSPARENT and proto in STORAGE_PROTOCOLS:
            storage += 1
        elif cls == MASS_STORAGE_CLASS:
            out.append(_finding("USB_STORAGE_VARIANT", SEV_BLOCKING,
                                "mass-storage interface with unsupported subclass/protocol %s/%s" % (sub, proto)))
        else:
            out.append(_finding("USB_EXTRA_INTERFACE", SEV_BLOCKING,
                                "device also presents a %s interface (class %s)"
                                % (USB_CLASS_NAMES.get(cls or "", "unknown"), cls or "unreadable")))
        if iface.get("authorized") is False:
            out.append(_finding("USB_INTERFACE_NOT_AUTHORIZED", SEV_INFO, "an interface is not authorized"))
    if storage > 1:
        out.append(_finding("USB_MULTIPLE_STORAGE_INTERFACES", SEV_BLOCKING, "more than one storage interface"))
    if _hex(usb.get("device_class")) not in ("00", MASS_STORAGE_CLASS):
        out.append(_finding("USB_DEVICE_CLASS", SEV_BLOCKING,
                            "unexpected device class %s" % (_hex(usb.get("device_class")) or "unreadable")))
    if usb.get("num_configurations") != 1:
        # A second configuration can switch the device into another role.
        out.append(_finding("USB_CONFIGURATIONS", SEV_BLOCKING,
                            "device offers %s configurations; exactly 1 expected" % usb.get("num_configurations")))
    if not usb.get("serial"):
        out.append(_finding("USB_NO_SERIAL", SEV_REVIEW,
                            "no USB serial number; identical devices cannot be told apart"))
    if not all(_printable(usb.get(k)) for k in ("manufacturer", "product", "serial")):
        out.append(_finding("USB_STRING_ANOMALY", SEV_REVIEW, "USB strings contain non-printable characters"))
    if usb.get("authorized") is False:
        out.append(_finding("USB_NOT_AUTHORIZED", SEV_INFO, "device is not authorized by the kernel"))
    return out


def assess(dev: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    transport = dev.get("transport")
    if transport not in GUARDIAN_TRANSPORTS:
        out.append(_finding("INTERNAL_DEVICE", SEV_BLOCKING, "transport %s is not removable media" % transport))
    size = dev.get("size_bytes")
    if not size:
        out.append(_finding("NO_MEDIA", SEV_BLOCKING, "device reports no capacity"))
    if dev.get("logical_block_size") not in (512, 4096):
        out.append(_finding("UNUSUAL_BLOCK_SIZE", SEV_REVIEW,
                            "logical block size %s" % dev.get("logical_block_size")))
    if dev.get("read_only"):
        out.append(_finding("WRITE_PROTECTED", SEV_INFO, "device is read-only (write-protect switch or kernel)"))
    for m in dev.get("mounts", []):
        mp = m.get("mountpoint", "")
        if mp in SYSTEM_MOUNTPOINTS or mp.startswith(LIVE_MOUNT_PREFIXES):
            out.append(_finding("SYSTEM_DISK", SEV_BLOCKING, "holds a system or live-media mount"))
            break
    if dev.get("mounts"):
        out.append(_finding("MOUNTED", SEV_BLOCKING, "device or a partition is mounted"))
    if dev.get("holders"):
        out.append(_finding("HAS_HOLDERS", SEV_BLOCKING, "device or a partition is in use (device mapper, RAID)"))
    if size:
        for p in dev.get("partitions", []):
            start, length = p.get("start_sectors"), p.get("size_sectors")
            if start is None or length is None or (start + length) * 512 > size:
                out.append(_finding("PARTITION_TABLE_INCONSISTENT", SEV_REVIEW,
                                    "partition %s lies outside the reported capacity" % p.get("kname")))
    if transport == "usb":
        if dev.get("usb") is None:
            out.append(_finding("USB_UNREADABLE", SEV_BLOCKING, "USB descriptors could not be read"))
        else:
            out.extend(_usb_findings(dev["usb"]))
    if transport == "mmc" and not (dev.get("mmc") or {}).get("cid"):
        out.append(_finding("MMC_NO_CID", SEV_REVIEW, "card identification register unreadable"))
    return out


def is_candidate(findings: List[Dict[str, str]]) -> bool:
    return not any(f["severity"] == SEV_BLOCKING for f in findings)
