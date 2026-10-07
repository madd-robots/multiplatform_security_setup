# SPDX-License-Identifier: GPL-3.0-or-later
"""Assembles the broker from its services (used by guardian.py and the tests).

The role follows from the state directory, never from a flag alone:

    main     no ``deployment.json``: Guardian Main. Forge and lease issuing are
             available; there is no lease gate (Main is the authority).
    spinoff  ``deployment.json`` written by the installer: the instance id must
             match it, Forge and lease issuing are absent, and operations that
             need ACTIVE authority pass through the lease gate (D5).

A state directory with spinoff lease state but no deployment descriptor is
refused, so deleting the descriptor does not turn a spinoff into Main.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, List, Optional

from .airlock.service import AirlockService
from .assurance.service import AssuranceService
from .audit.ledger import AuditLedger
from .audit.operations import AuditService
from .common.canonical import canonical_loads
from .common.errors import ConfigError
from .common.fsutil import ensure_private_dir, read_file_bounded
from .common.space import DEFAULT_POLICY, SpacePolicy
from .devices.operations import DEVICE_PROFILE, device_operations
from .forge.descriptor import check_descriptor
from .forge.registry import DeploymentRegistry
from .forge.service import ForgeService
from .identity.handlers import WorkerSigCheck
from .identity.operations import TrustService
from .identity.owner import OwnerAuthority
from .identity.sshkeys import HARDWARE_KEY_TYPES
from .identity.sshsig import SigCheck
from .identity.trust import TrustStore
from .lease.issuer import LeaseIssuer
from .lease.records import DEFAULT_LEASE_DAYS
from .lease.spinoff import LeaseAuthority
from .runtime.broker import Broker, Operation, default_operations
from .runtime.workers import WorkerLauncher
from .vault.custody import CustodyStore
from .vault.operations import VaultService
from .watchdog.adapter import WatchdogAdapter
from .watchdog.pause import PauseController


@dataclass
class GuardianServices:
    broker: Broker
    trust: TrustStore
    store: CustodyStore
    owner: OwnerAuthority
    audit: AuditLedger
    role: str
    lease: Optional[LeaseAuthority] = None
    watchdog: Optional[PauseController] = None


def build_services(launcher: WorkerLauncher, state_dir: Path, *, instance_id: str = "guardian-main",
                   sig_check: Optional[SigCheck] = None,
                   allowed_key_types: FrozenSet[str] = HARDWARE_KEY_TYPES,
                   space_policy: SpacePolicy = DEFAULT_POLICY, lease_days: int = DEFAULT_LEASE_DAYS,
                   machine_root: Path = Path("/"),
                   watchdog_adapter: Optional[WatchdogAdapter] = None,
                   airlock: Optional[AirlockService] = None) -> GuardianServices:
    """``allowed_key_types`` stays at hardware security keys outside the test suite.

    ``watchdog_adapter`` is None (disabled) until a real adapter exists for a reviewed watchdog.
    """
    state_dir = Path(state_dir)
    ensure_private_dir(state_dir)
    ensure_private_dir(state_dir / "trust")
    descriptor_path = state_dir / "deployment.json"
    descriptor = None
    if descriptor_path.exists():
        descriptor = check_descriptor(canonical_loads(read_file_bounded(descriptor_path, 1024 * 1024,
                                                                        require_private=True),
                                                      require_canonical=True))
        if descriptor["instance_id"] != instance_id:
            raise ConfigError("instance id %s does not match this spinoff's deployment (%s)"
                              % (instance_id, descriptor["instance_id"]), code="ROLE_MISMATCH")
    elif (state_dir / "lease").exists():
        raise ConfigError("lease state exists but the deployment descriptor is missing; refusing to run as Main",
                          code="ROLE_MISMATCH")
    check = sig_check or WorkerSigCheck(launcher)
    trust = TrustStore(state_dir / "trust", check, allowed_types=allowed_key_types)
    store = CustodyStore(state_dir / "custody", space_policy=space_policy)
    owner = OwnerAuthority(trust, check, instance_id)
    audit = AuditLedger(state_dir / "audit")
    swept = store.sweep_tmp()
    if swept["removed"]:
        audit.append("custody.startup_cleanup", removed=swept["removed"], bytes=swept["bytes"])
    watchdog = PauseController(state_dir / "watchdog", adapter=watchdog_adapter, audit=audit)
    assurance = AssuranceService(
        state_dir / "assurance", trust, check, instance_id, audit=audit,
        inspect_device=lambda kname: launcher.run(DEVICE_PROFILE, "devices.inspect", {"kname": kname}))
    operations: List[Operation] = (
        list(default_operations()) + list(device_operations(launcher, on_result=assurance.erase_hook))
        + list(assurance.operations()) + list(owner.operations())
        + list(TrustService(trust).operations())
        + list(VaultService(store, trust, check, instance_id, space_policy=space_policy).operations())
        + list(AuditService(audit, trust, check).operations()) + list(watchdog.operations()))
    if airlock is None:
        airlock = AirlockService(state_dir / "airlock", launcher, worker_gid=launcher.worker_gid, audit=audit,
                                 space_policy=space_policy)
    operations += list(airlock.operations())
    lease: Optional[LeaseAuthority] = None
    if descriptor is None:
        role = "main"
        registry = DeploymentRegistry(state_dir / "forge")
        operations += list(ForgeService(store, trust, check, registry, instance_id,
                                        space_policy=space_policy).operations())
        operations += list(LeaseIssuer(trust, check, registry, instance_id, default_days=lease_days).operations())
    else:
        role = "spinoff"
        lease = LeaseAuthority(state_dir / "lease", trust, check, instance_id=instance_id,
                               deployment_id=descriptor["deployment_id"], machine_root=machine_root, audit=audit)
        operations += list(lease.operations())
    gates = (watchdog,) + ((lease,) if lease is not None else ())
    broker = Broker(operations, launcher, audit=audit, gates=gates)
    return GuardianServices(broker, trust, store, owner, audit, role, lease, watchdog)
