# SPDX-License-Identifier: GPL-3.0-or-later
"""What a device exposes, what cannot be verified, and where its claims disagree (D4, design review 7).

Input is a device report from the sandboxed scanner (devices/handlers.py),
already validated by the caller. Everything here is analysis of strings
the device chose to present: a finding says the device's claims are
inconsistent or weak, never that the device is clean.

USB sticks and SD cards do not expose their flash controller or its
firmware through standard interfaces. The firmware *indicators* below
(bcdDevice, SCSI revision, MMC fwrev) are labels the firmware reports
about itself; Guardian records them and notices when they change, and
claims nothing more.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ..devices.assess import SEV_INFO, SEV_REVIEW
from ..devices.scanner import INVALID_UTF8_PREFIX

NOT_VERIFIABLE = (
    "controller firmware contents (not readable through USB mass storage, SCSI or MMC)",
    "spare and over-provisioned flash outside the logical address space",
    "whether the device returns the same data to other hosts",
)
JUNK_SERIAL = re.compile(r"^(?:0+|f+|1234567890abcdef?|0123456789abcdef?|(.)\1{5,}|[0-9a-f]{0,3})$", re.I)
CAPACITY_RE = re.compile(r"(?<![\d.])(\d{1,4})\s?(GB|G|TB|T)\b", re.I)


def _finding(code: str, severity: str, detail: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "detail": detail}


def _text(value: Any) -> Optional[str]:
    return value.strip() if isinstance(value, str) and value.strip() else None


def firmware_indicators(dev: Dict[str, Any]) -> Dict[str, Optional[str]]:
    usb, scsi, mmc = dev.get("usb") or {}, dev.get("scsi") or {}, dev.get("mmc") or {}
    return {"usb_bcd_device": _text(usb.get("bcd_device")), "scsi_revision": _text(scsi.get("rev")),
            "mmc_fwrev": _text(mmc.get("fwrev")), "mmc_hwrev": _text(mmc.get("hwrev"))}


def advertised_capacity(*labels: Optional[str]) -> Optional[int]:
    """Capacity in bytes stated in model or product strings (decimal units, as vendors use)."""
    for label in labels:
        if not label:
            continue
        m = CAPACITY_RE.search(label)
        if m:
            factor = 10 ** 12 if m.group(2).upper().startswith("T") else 10 ** 9
            return int(m.group(1)) * factor
    return None


def analyse(dev: Dict[str, Any]) -> Dict[str, Any]:
    usb, scsi, mmc = dev.get("usb") or {}, dev.get("scsi") or {}, dev.get("mmc") or {}
    findings: List[Dict[str, str]] = []
    size = dev.get("size_bytes") or 0
    strings = [usb.get("manufacturer"), usb.get("product"), usb.get("serial"), scsi.get("vendor"),
               scsi.get("model"), mmc.get("name")]
    if any(isinstance(s, str) and s.startswith(INVALID_UTF8_PREFIX) for s in strings):
        findings.append(_finding("DESCRIPTOR_NOT_TEXT", SEV_REVIEW, "a descriptor string is not valid text"))
    if dev.get("transport") == "usb":
        serial = _text(usb.get("serial"))
        if serial is None or JUNK_SERIAL.match(serial):
            findings.append(_finding("WEAK_SERIAL", SEV_REVIEW, "no usable USB serial number: two such drives "
                                                                "cannot be told apart by identity"))
        maker, vendor = _text(usb.get("manufacturer")), _text(scsi.get("vendor"))
        if maker and vendor:
            words = {w.lower() for w in re.findall(r"[A-Za-z]{3,}", maker)}
            if not any(w.lower() in words for w in re.findall(r"[A-Za-z]{3,}", vendor)):
                findings.append(_finding("VENDOR_STRINGS_DIFFER", SEV_INFO, "USB manufacturer and SCSI vendor "
                                                                           "strings differ (common, but noted)"))
        version, speed = _text(usb.get("usb_version")), _text(usb.get("speed"))
        if version and speed and version.startswith("3") and speed in ("480", "12", "1.5"):
            findings.append(_finding("RUNNING_BELOW_USB3", SEV_INFO, "USB %s device linked at %s Mbit/s" %
                                     (version, speed)))
        elif speed in ("12", "1.5"):
            findings.append(_finding("UNUSUAL_LINK_SPEED", SEV_REVIEW, "storage at %s Mbit/s" % speed))
        if dev.get("removable") is False:
            findings.append(_finding("NOT_REMOVABLE_FLAG", SEV_INFO, "reports itself as non-removable "
                                                                     "(typical of SSD enclosures)"))
    advertised = advertised_capacity(scsi.get("model"), usb.get("product"), mmc.get("name"))
    if advertised and size and not 0.85 * advertised <= size <= 1.10 * advertised:
        findings.append(_finding("CAPACITY_DISAGREES_WITH_LABEL", SEV_REVIEW,
                                 "label says about %d GB, the device reports %d bytes; fake capacity is "
                                 "possible, and an erase-verification proves the real capacity"
                                 % (advertised // 10 ** 9, size)))
    lbs, pbs = dev.get("logical_block_size"), dev.get("physical_block_size")
    if lbs and size % lbs:
        findings.append(_finding("SIZE_NOT_BLOCK_ALIGNED", SEV_REVIEW, "capacity is not a multiple of the "
                                                                       "logical block size"))
    if lbs and pbs and pbs < lbs:
        findings.append(_finding("BLOCK_SIZES_INCONSISTENT", SEV_REVIEW, "physical block smaller than logical"))
    return {"firmware_indicators": firmware_indicators(dev), "advertised_capacity": advertised,
            "findings": findings, "not_verifiable": list(NOT_VERIFIABLE)}
