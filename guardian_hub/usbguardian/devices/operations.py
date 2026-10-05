# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for the device engine.

device.list and device.inspect are read-only (capability device.inspect)
and run in workers. device.surface_test is destructive (capability
device.modify, which needs the owner_key factor), so it stays unreachable
until Stage 5. It runs in the broker because it needs root to open the raw
device. It only writes generated patterns and compares bytes; it never
parses device-controlled data.

The surface test is bound to the identity the owner approved: the caller
passes the fingerprint it was shown, and the test refuses to start, or
fails, if the device's identity differs before, during or after.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, Iterable, Optional

from ..common.errors import IntegrityError, SecurityViolation
from ..common.log import get_logger, log_event
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.workers import WorkerLauncher, WorkerProfile
from .assess import GUARDIAN_TRANSPORTS, SEV_BLOCKING
from .handlers import KNAME_PATTERN
from .scanner import SysfsScanner
from .surface import FdBlockIO, open_block_device, surface_test

DEVICE_PROFILE = WorkerProfile(name="devices", cpu_seconds=5, memory_bytes=256 * 1024 * 1024,
                               max_open_files=64, wall_timeout=20.0)
KNAME_SPEC = S.Str(pattern=KNAME_PATTERN, max_len=32)
FINGERPRINT_SPEC = S.Str(pattern=r"[0-9a-f]{64}", max_len=64)

InspectFn = Callable[[str], Dict[str, Any]]

# The report comes from a worker that parsed device-controlled data, so it
# is validated before the broker relies on any field of it.
REPORT_SPEC = S.Obj({
    "device": S.Obj({
        "dev": S.Str(pattern=r"\d{1,5}:\d{1,7}", max_len=16),
        "size_bytes": S.Int(min_value=512, max_value=2 ** 53 - 1),
        "read_only": S.Nullable(S.Bool()),
    }, allow_extra=True),
    "fingerprint": FINGERPRINT_SPEC,
    "findings": S.List(S.Obj({"code": S.Str(max_len=64), "severity": S.Str(max_len=16),
                              "detail": S.Str(max_len=512)}), max_items=512),
}, allow_extra=True)


class SurfaceTestRunner:
    def __init__(self, inspect: InspectFn, *, open_device: Callable[[str, str], int] = open_block_device,
                 io_factory: Callable[..., Any] = FdBlockIO, dev_root: str = "/dev", sysfs_root: str = "/sys",
                 logger: Optional[logging.Logger] = None):
        self.inspect = inspect
        self.sysfs_root = sysfs_root
        self.open_device = open_device
        self.io_factory = io_factory
        self.dev_root = dev_root
        self.logger = logger or get_logger("devices")

    def __call__(self, principal: authz.Principal, params: Dict[str, Any]) -> Dict[str, Any]:
        kname, expected = params["kname"], params["fingerprint"]
        before = S.validate(REPORT_SPEC, self.inspect(kname), "$.report")
        if before["fingerprint"] != expected:
            raise SecurityViolation("device identity differs from the one approved", code="DEVICE_IDENTITY_CHANGED")
        blocking = sorted({f["code"] for f in before["findings"] if f["severity"] == SEV_BLOCKING})
        if blocking:
            raise SecurityViolation("device is not eligible: %s" % ", ".join(blocking), code="DEVICE_NOT_ELIGIBLE")
        dev = before["device"]
        if dev["read_only"]:
            raise SecurityViolation("device is write-protected", code="DEVICE_READ_ONLY")
        size = dev["size_bytes"]
        kernel = SysfsScanner(self.sysfs_root).kernel_facts(kname)
        if kernel["transport"] not in GUARDIAN_TRANSPORTS or kernel["holders"]:
            raise SecurityViolation("kernel topology says this is not free removable media",
                                    code="DEVICE_NOT_ELIGIBLE")
        if kernel["dev"] != dev["dev"] or kernel["size_bytes"] != size:
            raise SecurityViolation("worker report disagrees with the kernel", code="DEVICE_IDENTITY_CHANGED")
        log_event(self.logger, logging.WARNING, "device.surface_test.start", principal=principal.name,
                  kname=kname, fingerprint=expected, size_bytes=size)
        fd = self.open_device(os.path.join(self.dev_root, kname), dev["dev"])
        try:
            if os.lseek(fd, 0, os.SEEK_END) != size:
                raise SecurityViolation("device size changed", code="DEVICE_IDENTITY_CHANGED")
            result = surface_test(self.io_factory(fd, size, direct=True), size)
        finally:
            os.close(fd)
        after = S.validate(REPORT_SPEC, self.inspect(kname), "$.report")
        if after["fingerprint"] != expected:
            raise IntegrityError("device identity changed during the surface test", code="DEVICE_IDENTITY_CHANGED")
        log_event(self.logger, logging.WARNING, "device.surface_test.done", kname=kname, fingerprint=expected,
                  passed=result["passed"], bad_chunks=result["bad_chunks"],
                  verified_bytes=result["verified_bytes"])
        return {"kname": kname, "fingerprint": expected, "result": result}


def device_operations(launcher: WorkerLauncher,
                      surface_runner: Optional[SurfaceTestRunner] = None) -> Iterable[Operation]:
    if surface_runner is None:
        surface_runner = SurfaceTestRunner(
            lambda kname: launcher.run(DEVICE_PROFILE, "devices.inspect", {"kname": kname}))
    return (
        Operation("device.list", "device.inspect", S.EMPTY, worker_handler="devices.scan", profile=DEVICE_PROFILE),
        Operation("device.inspect", "device.inspect", S.Obj({"kname": KNAME_SPEC}),
                  worker_handler="devices.inspect", profile=DEVICE_PROFILE),
        Operation("device.surface_test", "device.modify", S.Obj({"kname": KNAME_SPEC, "fingerprint": FINGERPRINT_SPEC}),
                  inline=surface_runner),
    )
