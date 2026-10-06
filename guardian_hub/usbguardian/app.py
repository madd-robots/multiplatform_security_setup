# SPDX-License-Identifier: GPL-3.0-or-later
"""Assembles the broker from its services (used by guardian.py and the tests)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, Optional

from .common.fsutil import ensure_private_dir
from .common.space import DEFAULT_POLICY, SpacePolicy
from .devices.operations import device_operations
from .forge.registry import DeploymentRegistry
from .forge.service import ForgeService
from .identity.handlers import WorkerSigCheck
from .identity.operations import TrustService
from .identity.owner import OwnerAuthority
from .identity.sshkeys import HARDWARE_KEY_TYPES
from .identity.sshsig import SigCheck
from .identity.trust import TrustStore
from .runtime.broker import Broker, default_operations
from .runtime.workers import WorkerLauncher
from .vault.custody import CustodyStore
from .vault.operations import VaultService


@dataclass
class GuardianServices:
    broker: Broker
    trust: TrustStore
    store: CustodyStore
    owner: OwnerAuthority


def build_services(launcher: WorkerLauncher, state_dir: Path, *, instance_id: str = "guardian-main",
                   sig_check: Optional[SigCheck] = None,
                   allowed_key_types: FrozenSet[str] = HARDWARE_KEY_TYPES,
                   space_policy: SpacePolicy = DEFAULT_POLICY) -> GuardianServices:
    """``allowed_key_types`` stays at hardware security keys outside the test suite."""
    state_dir = Path(state_dir)
    ensure_private_dir(state_dir)
    ensure_private_dir(state_dir / "trust")
    check = sig_check or WorkerSigCheck(launcher)
    trust = TrustStore(state_dir / "trust", check, allowed_types=allowed_key_types)
    store = CustodyStore(state_dir / "custody", space_policy=space_policy)
    owner = OwnerAuthority(trust, check, instance_id)
    operations = (list(default_operations()) + list(device_operations(launcher)) + list(owner.operations())
                  + list(TrustService(trust).operations())
                  + list(VaultService(store, trust, check, instance_id, space_policy=space_policy).operations())
                  + list(ForgeService(store, trust, check, DeploymentRegistry(state_dir / "forge"), instance_id,
                                      space_policy=space_policy).operations()))
    return GuardianServices(Broker(operations, launcher), trust, store, owner)
