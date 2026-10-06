# SPDX-License-Identifier: GPL-3.0-or-later
"""Spinoff platforms and capability profiles."""

from __future__ import annotations

from typing import Dict, FrozenSet, List

from ..common.errors import ValidationError
from ..runtime.authz import CAPABILITIES

# Platforms Forge can build for. A platform is available only once its
# runtime exists. Building for an unavailable platform is refused instead
# of producing a deployment that cannot run.
PLATFORMS: Dict[str, Dict[str, object]] = {
    "debian-mx": {"available": True, "description": "Debian/MX Linux, SysVinit (Stage 7)"},
    "rescue-usb": {"available": True, "description": "Guardian Rescue USB, same Linux runtime, run from read-only media"},
    "termux": {"available": False, "reason": "Termux runtime not implemented (see ROADMAP Stage 7 notes)"},
    "windows": {"available": False, "reason": "Windows needs its own service implementation (see ROADMAP Stage 7 notes)"},
}

# Spinoffs never become authorities (build guide rule): Forge stays on Guardian Main.
FORGE_ONLY: FrozenSet[str] = frozenset({"forge.build", "forge.prepare"})

_BASE = {"runtime.status", "auth.assert", "trust.read", "lease.read", "lease.manage"}
PROFILES: Dict[str, FrozenSet[str]] = {
    "full": frozenset(set(CAPABILITIES) - FORGE_ONLY),
    "recovery": frozenset(_BASE | {"runtime.diagnostics", "device.inspect", "device.modify", "vault.verify",
                                   "vault.read", "keys.manage"}),
    "storage": frozenset(_BASE | {"vault.prepare", "vault.verify", "vault.read", "vault.write", "keys.manage"}),
    "diagnostic": frozenset(_BASE | {"runtime.diagnostics", "device.inspect", "vault.verify"}),
}

for _name, _caps in PROFILES.items():
    assert not _caps & FORGE_ONLY and _caps <= set(CAPABILITIES), _name


def check_platform(platform: str) -> None:
    info = PLATFORMS.get(platform)
    if info is None:
        raise ValidationError("unknown platform")
    if not info["available"]:
        raise ValidationError("platform %s is not available yet: %s" % (platform, info["reason"]),
                              code="PLATFORM_UNAVAILABLE")


def profile_capabilities(profile: str) -> List[str]:
    caps = PROFILES.get(profile)
    if caps is None:
        raise ValidationError("unknown profile")
    return sorted(caps)
