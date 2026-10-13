# SPDX-License-Identifier: GPL-3.0-or-later
"""Worker handlers for read-only device analysis.

They run in the sandboxed worker: sysfs and mountinfo content is
device-controlled and is parsed only there.
"""

from __future__ import annotations

from typing import Any, Dict

from ..runtime import schema as S
from ..runtime.handlers import Handler, register
from .assess import SEV_BLOCKING, assess, is_candidate
from .identity import fingerprint, identity_document
from .scanner import SysfsScanner

KNAME_PATTERN = r"[a-z][a-z0-9]{0,31}"
DEVICE_REGISTRY: Dict[str, Handler] = {}


def build_report(dev: Dict[str, Any]) -> Dict[str, Any]:
    findings = assess(dev)
    return {
        "device": dev,
        "identity": identity_document(dev),
        "fingerprint": fingerprint(dev),
        "findings": findings,
        "candidate": is_candidate(findings),
    }


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    dev = report["device"]
    usb = dev.get("usb") or {}
    scsi = dev.get("scsi") or {}
    mmc = dev.get("mmc") or {}
    return {
        "kname": dev["kname"],
        "transport": dev["transport"],
        "size_bytes": dev["size_bytes"],
        "vendor": usb.get("manufacturer") or scsi.get("vendor") or mmc.get("manfid"),
        "model": usb.get("product") or scsi.get("model") or mmc.get("name"),
        "usb_id": ("%s:%s" % (usb.get("vendor_id"), usb.get("product_id"))) if usb else None,
        "fingerprint": report["fingerprint"],
        "candidate": report["candidate"],
        "blocking": [f["code"] for f in report["findings"] if f["severity"] == SEV_BLOCKING],
    }


@register("devices.scan", S.EMPTY, DEVICE_REGISTRY)
def _scan(params: Dict[str, Any]) -> Any:
    return {"devices": [summarize(build_report(d)) for d in SysfsScanner().scan()]}


@register("devices.inspect", S.Obj({"kname": S.Str(pattern=KNAME_PATTERN, max_len=32)}), DEVICE_REGISTRY)
def _inspect(params: Dict[str, Any]) -> Any:
    return build_report(SysfsScanner().inspect(params["kname"]))
