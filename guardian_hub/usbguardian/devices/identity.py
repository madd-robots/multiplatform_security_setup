# SPDX-License-Identifier: GPL-3.0-or-later
"""Device identity: what a device says it is, fixed into one fingerprint.

The identity keeps only what should not change while the same physical
device stays plugged in or is re-inserted: USB descriptors and interface
layout, SCSI INQUIRY strings, the MMC CID, capacity and block sizes.
Volatile state (bus address, port, speed, mounts, partitions, driver
binding) is left out. Partitions are left out because Guardian rewrites
them during preparation.

Every value is reported by the device, so a fingerprint match is not proof
of physical identity: a malicious device can copy another's descriptors.
What it does catch is any device whose presented identity changes between
steps or insertions (D4), which Guardian treats as a hard failure.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..common.canonical import canonical_digest

IDENTITY_DOMAIN = "guardian/device-identity/v1"


def identity_document(dev: Dict[str, Any]) -> Dict[str, Any]:
    usb = dev.get("usb")
    usb_doc = None
    if usb is not None:
        usb_doc = {
            "vendor_id": usb.get("vendor_id"),
            "product_id": usb.get("product_id"),
            "bcd_device": usb.get("bcd_device"),
            "manufacturer": usb.get("manufacturer"),
            "product": usb.get("product"),
            "serial": usb.get("serial"),
            "device_class": usb.get("device_class"),
            "num_configurations": usb.get("num_configurations"),
            "interfaces": sorted(([i.get("class"), i.get("subclass"), i.get("protocol")]
                                  for i in usb.get("interfaces", [])),
                                 key=lambda t: [x or "" for x in t]),
        }
    mmc = dev.get("mmc")
    mmc_doc = None
    if mmc is not None:
        mmc_doc = {k: mmc.get(k) for k in ("cid", "csd", "name", "manfid", "oemid", "serial", "date", "type")}
    return {
        "transport": dev.get("transport"),
        "size_bytes": dev.get("size_bytes"),
        "logical_block_size": dev.get("logical_block_size"),
        "physical_block_size": dev.get("physical_block_size"),
        "scsi": dev.get("scsi"),
        "mmc": mmc_doc,
        "usb": usb_doc,
    }


def fingerprint(dev: Dict[str, Any]) -> str:
    return canonical_digest(IDENTITY_DOMAIN, identity_document(dev)).hex()


def identity_changes(old: Any, new: Any, path: str = "") -> List[str]:
    """Dotted paths whose values differ between two identity documents."""
    if isinstance(old, dict) and isinstance(new, dict):
        out: List[str] = []
        for key in sorted(set(old) | set(new)):
            out.extend(identity_changes(old.get(key), new.get(key), "%s.%s" % (path, key) if path else key))
        return out
    return [] if old == new else [path or "$"]
