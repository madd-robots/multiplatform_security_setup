# SPDX-License-Identifier: GPL-3.0-or-later
"""Install a verified Guardian deployment on Debian/MX (SysVinit).

Run as root from known-good media (the Rescue USB), with the deployment
package, the owner's trust log and the pinned trust anchor (``trust.log``
and ``trust.anchor`` copied from Guardian Main's state directory).

    /opt/usbguardian/releases/<deployment_id>/   verified code, root-owned, read-only
    /opt/usbguardian/current -> releases/<id>     switched atomically after verification
    /var/lib/usbguardian/                         private state: trust log + anchor, deployment.json
    /etc/usbguardian/policy.json                  owner uid -> the deployment's capabilities
    /etc/usbguardian/usbguard-rules.suggested     USB interface allowlist to review (not applied)
    /etc/init.d/usbguardian                       SysVinit service (enabled only on request)

Nothing is placed under a final path before the package has fully
verified. A failed install leaves the previous installation untouched.
"""

from __future__ import annotations

import os
import pwd
import secrets
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import ConfigError, GuardianError, IntegrityError, SecurityViolation, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..common.tools import SAFE_ENV, require_tool
from ..forge.install import parse_trust_log, verify_deployment
from ..identity.sshkeys import HARDWARE_KEY_TYPES
from ..identity.sshsig import SigCheck
from ..identity.trust import check_extension
from ..runtime.workers import verify_code_tree

SUPPORTED_PLATFORMS = ("debian-mx", "rescue-usb")
SERVICE_NAME = "usbguardian"


@dataclass(frozen=True)
class InstallLayout:
    prefix: Path = Path("/opt/usbguardian")
    state_dir: Path = Path("/var/lib/usbguardian")
    etc_dir: Path = Path("/etc/usbguardian")
    initd_dir: Path = Path("/etc/init.d")
    run_dir: Path = Path("/run/usbguardian")
    log_file: Path = Path("/var/log/usbguardian-broker.log")

    @property
    def releases(self) -> Path:
        return self.prefix / "releases"

    @property
    def current(self) -> Path:
        return self.prefix / "current"


def read_anchor(path: Path) -> str:
    """Accept Guardian Main's ``trust.anchor`` file ({"anchor": hex})."""
    try:
        doc = canonical_loads(read_file_bounded(Path(path), 1024).strip(), require_canonical=True)
    except GuardianError as exc:
        raise ConfigError("trust anchor file is malformed: %s" % exc.message) from None
    if not isinstance(doc, dict) or set(doc) != {"anchor"} or not isinstance(doc["anchor"], str) \
            or len(doc["anchor"]) != 64 or doc["anchor"].strip("0123456789abcdef"):
        raise ConfigError("trust anchor file is malformed")
    return doc["anchor"]


def _root_dir(path: Path, mode: int = 0o755) -> None:
    """Create or validate a root-owned directory that only root can write."""
    try:
        os.mkdir(path, mode)
    except FileExistsError:
        pass
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise SecurityViolation("%s must be a root-owned directory not writable by others" % path,
                                code="UNTRUSTED_PATH")
    os.chmod(path, mode)


def _normalize_tree(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        os.chown(dirpath, 0, 0)
        os.chmod(dirpath, 0o755)
        for name in filenames:
            path = os.path.join(dirpath, name)
            os.lchown(path, 0, 0)
            os.chmod(path, 0o644, follow_symlinks=False)


def _merge_trust(state_trust: Path, provided: List[Any], anchor: str) -> List[Any]:
    """Keep the longer of the installed and the provided log; any divergence is a fork."""
    log_path = state_trust / "trust.log"
    if not log_path.exists():
        return provided
    existing_anchor = read_anchor(state_trust / "trust.anchor")
    if existing_anchor != anchor:
        raise IntegrityError("this machine is pinned to a different trust anchor", code="TRUST_ANCHOR_MISMATCH")
    existing = parse_trust_log(read_file_bounded(log_path, 8 * 1024 * 1024, require_private=True))
    shorter, longer = sorted((existing, provided), key=len)
    check_extension(shorter, longer)
    return longer


def init_script(layout: InstallLayout, *, python: str, worker_user: str, instance_id: str) -> str:
    args = " ".join([
        "-I", "-B", str(layout.current / "guardian.py"), "broker",
        "--policy", str(layout.etc_dir / "policy.json"), "--socket", str(layout.run_dir / "broker.sock"),
        "--socket-mode", "600", "--state-dir", str(layout.state_dir), "--worker-user", worker_user,
        "--instance-id", instance_id, "--log-file", str(layout.log_file)])
    return """#!/bin/sh
### BEGIN INIT INFO
# Provides:          {name}
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Guardian USB Encryption Hub broker
### END INIT INFO
# Generated by the Guardian installer. Regenerate it after a Python upgrade.

PIDFILE=/run/{name}.pid
PYTHON={python}
ARGS="{args}"

case "$1" in
  start)
    install -d -m 0755 -o root -g root {run_dir}
    start-stop-daemon --start --quiet --background --make-pidfile --pidfile "$PIDFILE" \\
        --startas "$PYTHON" -- $ARGS
    ;;
  stop)
    start-stop-daemon --stop --quiet --retry TERM/10/KILL/5 --pidfile "$PIDFILE" --remove-pidfile
    ;;
  restart|force-reload)
    "$0" stop
    "$0" start
    ;;
  status)
    start-stop-daemon --status --pidfile "$PIDFILE" && echo "{name} is running" || {{ echo "{name} is not running"; exit 3; }}
    ;;
  *)
    echo "Usage: $0 {{start|stop|restart|force-reload|status}}" >&2
    exit 2
    ;;
esac
exit 0
""".format(name=SERVICE_NAME, python=python, args=args, run_dir=layout.run_dir)


USBGUARD_SUGGESTION = """# Guardian: suggested USBGuard rules (ROADMAP D4 step 1). NOT applied automatically.
# Review before use. A wrong rule set can lock out your keyboard. Install
# usbguard, then merge these into /etc/usbguard/rules.conf.
#
# Hubs, so devices behind them can be evaluated:
allow with-interface equals { 09:00:* }
# YubiKeys (Yubico, vendor 1050), needed for owner authentication:
allow id 1050:*
# Guardian media: exactly one mass-storage interface, bulk-only or UAS:
allow with-interface equals { 08:06:50 }
allow with-interface equals { 08:06:62 }
# Your own keyboard and mouse: replace with their exact ids
# (usbguard list-devices), never a class-wide HID rule:
# allow id XXXX:YYYY serial "..." with-interface equals { 03:01:01 }
# Everything else, including storage that also presents HID or network
# interfaces (BadUSB), is blocked:
block
"""


def install_debian(package: Path, trust_log: Path, anchor_file: Path, *, owner_uid: int, worker_user: str,
                   sig_check: SigCheck, layout: InstallLayout = InstallLayout(), platform: str = "debian-mx",
                   allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES, replace_policy: bool = False,
                   enable_service: bool = False, dry_run: bool = False, python: Optional[str] = None) -> Dict[str, Any]:
    if os.geteuid() != 0:
        raise SecurityViolation("the installer must run as root", code="NOT_ROOT")
    if platform not in SUPPORTED_PLATFORMS:
        raise ValidationError("this installer supports %s" % ", ".join(SUPPORTED_PLATFORMS))
    try:
        worker = pwd.getpwnam(worker_user)
    except KeyError:
        raise ConfigError("worker user %s does not exist; create it with: adduser --system --group "
                          "--no-create-home --home /nonexistent --shell /usr/sbin/nologin %s"
                          % (worker_user, worker_user)) from None
    if worker.pw_uid == 0 or worker.pw_gid == 0 or worker.pw_uid == owner_uid:
        raise ConfigError("the worker user must be a dedicated unprivileged account")
    anchor = read_anchor(anchor_file)
    provided = parse_trust_log(read_file_bounded(Path(trust_log), 8 * 1024 * 1024))
    interpreter = os.path.realpath(python or require_tool("python3"))

    _root_dir(layout.prefix)
    _root_dir(layout.releases)
    staging = layout.releases / (".staging-" + secrets.token_hex(8))
    os.mkdir(staging, 0o700)
    try:
        fd = os.open(package, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            result = verify_deployment(fd, provided, anchor, sig_check, allowed_types=allowed_types,
                                       expected_platform=platform, extract_to=staging)
        finally:
            os.close(fd)
        descriptor = result["descriptor"]
        _normalize_tree(staging)
        verify_code_tree(staging / "usbguardian")
        state_trust = layout.state_dir / "trust"
        trust_entries = _merge_trust(state_trust, provided, anchor)
        release = layout.releases / descriptor["deployment_id"]
        if os.path.lexists(release):
            raise ValidationError("this deployment is already installed", code="ALREADY_INSTALLED")
        plan = {"deployment_id": descriptor["deployment_id"], "instance_id": descriptor["instance_id"],
                "platform": descriptor["platform"], "profile": descriptor["profile"],
                "capabilities": descriptor["capabilities"], "release": str(release),
                "trust_seq": len(trust_entries) - 1, "anchor": anchor}
        if dry_run:
            return dict(plan, dry_run=True)
        os.chmod(staging, 0o755)
        os.rename(staging, release)
        staging = None  # type: ignore[assignment]
    finally:
        if staging is not None and os.path.lexists(staging):
            shutil.rmtree(staging)

    # Switch "current" atomically.
    link_tmp = layout.prefix / (".current-" + secrets.token_hex(8))
    os.symlink(os.path.join("releases", descriptor["deployment_id"]), link_tmp)
    os.replace(link_tmp, layout.current)

    ensure_private_dir(layout.state_dir)
    ensure_private_dir(state_trust)
    atomic_write(state_trust / "trust.log", b"".join(canonical_dumps(e) + b"\n" for e in trust_entries))
    atomic_write(state_trust / "trust.anchor", canonical_dumps({"anchor": anchor}))
    atomic_write(layout.state_dir / "deployment.json", canonical_dumps(descriptor))

    _root_dir(layout.etc_dir)
    policy_path = layout.etc_dir / "policy.json"
    policy_written = False
    if replace_policy or not policy_path.exists():
        policy = {"version": 1, "principals": [{"name": "owner", "uid": owner_uid,
                                                 "capabilities": descriptor["capabilities"]}]}
        atomic_write(policy_path, canonical_dumps(policy), mode=0o644)
        policy_written = True
    atomic_write(layout.etc_dir / "usbguard-rules.suggested", USBGUARD_SUGGESTION.encode("ascii"), mode=0o644)

    _root_dir(layout.initd_dir)
    script = layout.initd_dir / SERVICE_NAME
    atomic_write(script, init_script(layout, python=interpreter, worker_user=worker_user,
                                     instance_id=descriptor["instance_id"]).encode("ascii"), mode=0o755)
    service_enabled = False
    if enable_service:
        subprocess.run([require_tool("update-rc.d"), SERVICE_NAME, "defaults"], env=dict(SAFE_ENV), check=True,
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        service_enabled = True
    return dict(plan, dry_run=False, current=str(layout.current), policy_written=policy_written,
                init_script=str(script), service_enabled=service_enabled,
                usbguard_suggestion=str(layout.etc_dir / "usbguard-rules.suggested"))
