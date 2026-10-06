# SPDX-License-Identifier: GPL-3.0-or-later
"""Installer v2 (ROADMAP D9, D11): unprivileged plan, narrow privileged apply, validation, uninstall.

Phase 1, ``plan_install`` (no root needed): verify the offline bundle,
detect the platform and refuse a bundle for another target, run the
SysVinit preflight, check package and account state, detect an existing
installation and choose a mode, check disk space, and produce a plan. The
plan has an id; phase 2 runs only for the same id.

Phase 2, ``apply_install`` (root): re-verifies everything (nothing from
phase 1 is trusted across the gap), then only:
- installs packages from the bundle that are missing (``apt-get install
  --no-install-recommends --no-upgrade`` with the verified files). Never
  an upgrade of the system, never a removal, never an unauthenticated
  repository package.
- creates the dedicated worker account if it is missing
- installs or updates Guardian's own files (deploy/debian.py), or repairs
  them from the bundle; a damaged release is moved aside as evidence
- registers the SysVinit service with update-rc.d when asked and not yet
  registered
- records an install record, a report and audit ledger entries

Modes: INSTALL, VERIFY (same deployment, files intact: no changes),
REPAIR (same deployment, Guardian files differ: restored from the
bundle), UPDATE (newer deployment for the same instance). A bundle for a
different instance on an installed machine is refused: identity, keys and
enrollment are never overwritten. Operating-system or SysVinit damage is
reported and stops the installer; it is never "repaired" here.

Nothing here reboots the machine. ``validate_install`` is the
post-install and post-reboot check.
"""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, SecurityViolation
from ..common.fsutil import atomic_write, check_trusted_file, ensure_private_dir, read_file_bounded
from ..common.space import InsufficientSpace, require_space
from ..common.tools import SAFE_ENV, require_tool
from ..identity.sshkeys import HARDWARE_KEY_TYPES
from ..identity.sshsig import SigCheck
from .bundle import check_target, manifest_digest, verify_bundle
from .debian import SERVICE_NAME, InstallLayout, init_script, install_debian
from .inventory import REQUIRED_INSTALLER, REQUIRED_RUNTIME, TOOLS, package_state
from .preflight import MISMATCH, systemd_active, sysvinit_preflight
from .system import InstallerError, Runner, detect_platform, read_small, system_runner

RECORD_NAME = "install.json"
PLAN_DOMAIN = "guardian/install-plan/v1"
NONE = "NONE"


# -- existing installation -------------------------------------------------------------------------

def _descriptor(layout: InstallLayout) -> Optional[Dict[str, Any]]:
    path = layout.state_dir / "deployment.json"
    if not path.exists():
        return None
    return canonical_loads(read_file_bounded(path, 1024 * 1024), require_canonical=True)


def _record(layout: InstallLayout) -> Optional[Dict[str, Any]]:
    path = layout.state_dir / RECORD_NAME
    if not path.exists():
        return None
    return canonical_loads(read_file_bounded(path, 64 * 1024), require_canonical=True)


def installed_code_problems(layout: InstallLayout, descriptor: Dict[str, Any]) -> List[str]:
    """Compare the active release with the deployment's code inventory (hash, owner, mode, extras)."""
    problems: List[str] = []
    if not os.path.islink(layout.current):
        return ["current release link missing"]
    release = Path(os.path.realpath(layout.current))
    if release.name != descriptor["deployment_id"] or release.parent != Path(os.path.realpath(layout.releases)):
        return ["current release is not the recorded deployment"]
    expected = {c["path"]: c for c in descriptor["code"]}
    seen = set()
    for dirpath, dirnames, filenames in os.walk(release, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in dirnames + filenames:
            path = Path(dirpath) / name
            st = os.lstat(path)
            rel = path.relative_to(release).as_posix()
            if stat.S_ISLNK(st.st_mode):
                problems.append("symlink in release: %s" % rel)
            elif st.st_uid != 0 or st.st_mode & 0o022:
                problems.append("not root-owned and protected: %s" % rel)
            if name in filenames:
                if rel not in expected:
                    problems.append("unexpected file: %s" % rel)
                    continue
                seen.add(rel)
                h = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                        h.update(chunk)
                if h.hexdigest() != expected[rel]["sha256"]:
                    problems.append("modified: %s" % rel)
    problems += ["missing: %s" % p for p in sorted(set(expected) - seen)]
    return problems


def rc_links(fs_root: Path) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for d in ("rc0.d", "rc1.d", "rc2.d", "rc3.d", "rc4.d", "rc5.d", "rc6.d", "rcS.d"):
        try:
            names = os.listdir(Path(fs_root) / "etc" / d)
        except OSError:
            continue
        hits = [n for n in names if re.fullmatch(r"[SK][0-9]{2}" + SERVICE_NAME, n)]
        if hits:
            out[d] = sorted(hits)
    return out


def existing_install(layout: InstallLayout, fs_root: Path) -> Dict[str, Any]:
    desc = _descriptor(layout)
    return {"installed": desc is not None or os.path.lexists(layout.current),
            "instance_id": desc["instance_id"] if desc else None,
            "deployment_id": desc["deployment_id"] if desc else None,
            "init_script": (layout.initd_dir / SERVICE_NAME).exists(),
            "service_registered": bool(rc_links(fs_root)),
            "state_dir": layout.state_dir.exists()}


def yubikeys_present(sysfs_root: Path = Path("/sys")) -> int:
    """Number of attached Yubico USB devices (vendor 1050), from sysfs; no secrets are read."""
    count = 0
    base = Path(sysfs_root) / "bus/usb/devices"
    try:
        names = os.listdir(base)
    except OSError:
        return 0
    for name in names:
        if (read_small(base / name / "idVendor", 16) or "").strip() == "1050":
            count += 1
    return count


# -- phase 1: plan ---------------------------------------------------------------------------------

def plan_install(bundle: Path, *, layout: InstallLayout = InstallLayout(), owner_uid: int, worker_user: str,
                 enable_service: bool, sig_check: SigCheck, allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES,
                 expected_anchor: Optional[str] = None, fs_root: Path = Path("/"), proc_root: Path = Path("/proc"),
                 sysfs_root: Path = Path("/sys"), run: Runner = system_runner) -> Dict[str, Any]:
    manifest = verify_bundle(bundle, sig_check, allowed_types=allowed_types, expected_anchor=expected_anchor)
    platform = detect_platform(fs_root, run)
    check_target(manifest, platform)
    blocked: List[str] = []
    preflight = sysvinit_preflight(proc_root=proc_root, fs_root=fs_root, run=run)
    if preflight["result"] in ("BLOCKED", "UNKNOWN"):
        blocked.append("SysVinit preflight %s" % preflight["result"])
    bundled = {p["name"]: p for p in manifest["packages"]}
    required = sorted({pkg for pkg, cls, _u in TOOLS.values() if cls in (REQUIRED_RUNTIME, REQUIRED_INSTALLER)})
    states = package_state(sorted(set(bundled) | set(required)), run)
    to_install = [bundled[n] for n in sorted(bundled) if not states[n]["installed"]]
    unavailable = [n for n in required if not states[n]["installed"] and n not in bundled]
    if unavailable:
        blocked.append("required packages neither installed nor in the bundle: %s" % ", ".join(unavailable))
    try:
        worker = pwd.getpwnam(worker_user)
        account = "present"
        if worker.pw_uid == 0 or worker.pw_gid == 0 or worker.pw_uid == owner_uid:
            blocked.append("worker account %s is not a dedicated unprivileged account" % worker_user)
    except KeyError:
        account = "to create"
    existing = existing_install(layout, fs_root)
    damaged: List[str] = []
    if not existing["installed"]:
        mode = "INSTALL"
    elif existing["instance_id"] not in (None, manifest["deployment"]["instance_id"]):
        mode = "BLOCKED"
        blocked.append("this machine is instance %s; the bundle is for %s (identity is never overwritten)"
                       % (existing["instance_id"], manifest["deployment"]["instance_id"]))
    elif existing["deployment_id"] == manifest["deployment"]["deployment_id"]:
        damaged = installed_code_problems(layout, _descriptor(layout) or {})
        mode = "REPAIR" if damaged else "VERIFY"
    else:
        mode = "UPDATE"
    total = sum(f["size"] for f in manifest["files"])
    space_target = next((p for p in [layout.prefix] + list(layout.prefix.parents) if p.exists()), Path("/"))
    try:
        require_space(str(space_target), total * 2, files=4096, what="installation")
        space = "ok"
    except InsufficientSpace as exc:
        space = exc.message
        blocked.append("disk space: %s" % exc.message)
    register = enable_service and not existing["service_registered"]
    plan = {
        "bundle": manifest_digest(manifest).hex(), "mode": mode,
        "platform": platform, "target": manifest["target"], "active_init": preflight["pid1"]["comm"],
        "sysvinit_preflight": preflight["result"],
        "existing": existing, "damaged_guardian_files": damaged[:50],
        "deployment": manifest["deployment"],
        "packages_satisfied": sorted(n for n in states if states[n]["installed"]),
        "packages_to_install": [{"name": p["name"], "version": p["version"], "file": p["file"]} for p in to_install],
        "packages_to_upgrade": NONE, "packages_to_remove": NONE, "broad_os_upgrades": NONE,
        "bootloader_changes": NONE, "init_system_conversion": NONE, "systemd_installation": NONE,
        "worker_account": {"name": worker_user, "state": account},
        "files_to_create_or_update": [] if mode in ("VERIFY", "BLOCKED") else [
            str(layout.releases / manifest["deployment"]["deployment_id"]), str(layout.current),
            str(layout.state_dir), str(layout.etc_dir / "policy.json"), str(layout.initd_dir / SERVICE_NAME)],
        "service_actions": (["update-rc.d %s defaults" % SERVICE_NAME] if register else []),
        "optional_features": {"airlock_scanner": "installed" if states.get("clamav", {}).get("installed") else
                              ("in bundle" if "clamav" in bundled else "absent: Airlock blocks every file")},
        "yubikey": {"attached": yubikeys_present(sysfs_root), "note": "presence only; nothing is read or changed"},
        "watchdog_adapter": "disabled (no adapter integrated)",
        "disk_space": space,
        "status": "BLOCKED" if blocked else "READY", "blocked_reasons": blocked,
        "preflight": preflight,
    }
    plan["plan_id"] = canonical_digest(PLAN_DOMAIN, {
        "bundle": plan["bundle"], "mode": mode, "install": plan["packages_to_install"], "account": account,
        "layout": [str(layout.prefix), str(layout.state_dir), str(layout.etc_dir), str(layout.initd_dir)],
        "register": register, "owner_uid": owner_uid, "worker_user": worker_user}).hex()[:24]
    return plan


# -- phase 2: apply --------------------------------------------------------------------------------

def apply_install(bundle: Path, *, confirm: str, layout: InstallLayout = InstallLayout(), owner_uid: int,
                  worker_user: str, enable_service: bool, sig_check: SigCheck,
                  allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES, expected_anchor: Optional[str] = None,
                  fs_root: Path = Path("/"), proc_root: Path = Path("/proc"), sysfs_root: Path = Path("/sys"),
                  run: Runner = system_runner, python: Optional[str] = None,
                  audit_factory: Any = None) -> Dict[str, Any]:
    if os.geteuid() != 0:
        raise SecurityViolation("phase 2 needs root; run the plan first without it", code="NOT_ROOT")
    plan = plan_install(bundle, layout=layout, owner_uid=owner_uid, worker_user=worker_user,
                        enable_service=enable_service, sig_check=sig_check, allowed_types=allowed_types,
                        expected_anchor=expected_anchor, fs_root=fs_root, proc_root=proc_root,
                        sysfs_root=sysfs_root, run=run)
    if plan["status"] != "READY":
        raise InstallerError("INSTALLATION BLOCKED: %s" % "; ".join(plan["blocked_reasons"]))
    if plan["plan_id"] != confirm:
        raise InstallerError("the plan changed since it was shown (now %s); review it again" % plan["plan_id"],
                             code="PLAN_CHANGED")
    actions: List[str] = []
    if plan["packages_to_install"]:
        argv = ["apt-get", "install", "-y", "--no-install-recommends", "--no-upgrade"] + [
            str(Path(bundle).resolve() / p["file"]) for p in plan["packages_to_install"]]
        rc, out, err = run(argv)
        if rc != 0:
            raise InstallerError("package installation failed (status %d): %s" % (rc, err.strip()[-300:]),
                                 code="INSTALLATION_FAILED")
        actions.append("installed packages: %s" % ", ".join(p["name"] for p in plan["packages_to_install"]))
    if plan["worker_account"]["state"] == "to create":
        rc, _out, err = run(["adduser", "--system", "--group", "--no-create-home", "--home", "/nonexistent",
                             "--shell", "/usr/sbin/nologin", worker_user])
        if rc != 0:
            raise InstallerError("could not create the worker account: %s" % err.strip()[:200],
                                 code="INSTALLATION_FAILED")
        actions.append("created worker account %s" % worker_user)
    if plan["mode"] == "REPAIR":
        release = layout.releases / plan["deployment"]["deployment_id"]
        evidence = layout.releases / (".damaged-%s-%d" % (release.name, int(time.time())))
        os.rename(release, evidence)
        actions.append("moved damaged release aside: %s" % evidence)
    if plan["mode"] in ("INSTALL", "UPDATE", "REPAIR"):
        report = install_debian(Path(bundle) / "deployment.gpkg", Path(bundle) / "trust.log",
                                Path(bundle) / "trust.anchor", owner_uid=owner_uid, worker_user=worker_user,
                                sig_check=sig_check, layout=layout, platform=plan["deployment"]["platform"],
                                allowed_types=allowed_types, enable_service=False, python=python,
                                proc_root=proc_root, fs_root=fs_root)
        actions.append("%s Guardian release %s" % (plan["mode"].lower(), report["deployment_id"]))
        interpreter = os.path.realpath(python or require_tool("python3"))
        atomic_write(layout.state_dir / RECORD_NAME, canonical_dumps({
            "version": 1, "python": interpreter, "worker_user": worker_user, "owner_uid": owner_uid,
            "instance_id": plan["deployment"]["instance_id"], "enable_service": enable_service,
            "bundle": plan["bundle"], "installed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))
    if plan["service_actions"]:
        if systemd_active(proc_root, fs_root):
            raise InstallerError(MISMATCH, code="ENVIRONMENT_MISMATCH")
        rc, _out, err = run(["update-rc.d", SERVICE_NAME, "defaults"])
        if rc != 0:
            raise InstallerError("service registration failed: %s" % err.strip()[:200], code="INSTALLATION_FAILED")
        actions.append("registered SysVinit service (update-rc.d defaults)")
    validation = validate_install(layout, fs_root=fs_root, proc_root=proc_root, run=run)
    report_doc = {"plan_id": plan["plan_id"], "mode": plan["mode"], "actions": actions, "validation": validation,
                  "preflight": plan["sysvinit_preflight"], "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    reports = layout.state_dir / "install-reports"
    ensure_private_dir(reports)
    atomic_write(reports / ("%s-%s.json" % (report_doc["time"].replace(":", ""), plan["plan_id"][:8])),
                 canonical_dumps(report_doc))
    _audit(layout, audit_factory, "installer.apply", plan_id=plan["plan_id"], mode=plan["mode"], actions=actions,
           preflight=plan["sysvinit_preflight"], validation=validation["result"])
    return dict(report_doc, plan=plan)


def _audit(layout: InstallLayout, factory: Any, event: str, **fields: Any) -> None:
    from ..audit.ledger import AuditLedger
    ledger = (factory or AuditLedger)(layout.state_dir / "audit")
    ledger.append(event, **fields)


# -- validation ------------------------------------------------------------------------------------

def broker_processes(layout: InstallLayout, proc_root: Path = Path("/proc")) -> List[Dict[str, int]]:
    marker = str(layout.current / "guardian.py")
    out = []
    for name in os.listdir(proc_root):
        if not name.isdigit():
            continue
        raw = read_small(Path(proc_root) / name / "cmdline", 8192) or ""
        args = raw.split("\x00")
        if marker in args and "broker" in args:
            status = read_small(Path(proc_root) / name / "status", 8192) or ""
            m = re.search(r"^Uid:\s+(\d+)", status, re.M)
            out.append({"pid": int(name), "uid": int(m.group(1)) if m else -1})
    return out


def validate_install(layout: InstallLayout = InstallLayout(), *, fs_root: Path = Path("/"),
                     proc_root: Path = Path("/proc"), run: Runner = system_runner, post_reboot: bool = False,
                     exercise_service: bool = False) -> Dict[str, Any]:
    checks: List[Dict[str, str]] = []

    def check(name: str, ok: Optional[bool], detail: str) -> None:
        checks.append({"check": name, "status": "ok" if ok else ("blocked" if ok is None else "failed"),
                       "detail": detail})

    if systemd_active(proc_root, fs_root):
        check("init", None, MISMATCH)
    else:
        pre = sysvinit_preflight(proc_root=proc_root, fs_root=fs_root, run=run) if post_reboot else None
        check("init", pre is None or pre["result"] in ("PASS", "PASS WITH FINDINGS"),
              "SysVinit is PID 1" + (" (preflight %s)" % pre["result"] if pre else ""))
        if pre:
            rl = next((c for c in pre["checks"] if c["check"] == "runlevel"), None)
            check("runlevel", rl is not None and rl["status"] == "ok", rl["detail"] if rl else "unknown")
    desc, record = _descriptor(layout), _record(layout)
    if desc is None or record is None:
        check("installation", False, "no Guardian installation record")
        return {"result": _result(checks), "checks": checks}
    problems = installed_code_problems(layout, desc)
    check("guardian_files", not problems, "; ".join(problems[:10]) or "all %d files match" % len(desc["code"]))
    for path, mode, private in ((layout.state_dir, 0o700, True), (layout.etc_dir / "policy.json", 0o644, False),
                                (layout.initd_dir / SERVICE_NAME, 0o755, False)):
        try:
            st = os.lstat(path)
            ok = st.st_uid == 0 and stat.S_IMODE(st.st_mode) == mode
            check("permissions:" + path.name, ok, "%s mode %o uid %d" % (path, stat.S_IMODE(st.st_mode), st.st_uid))
        except OSError:
            check("permissions:" + path.name, False, "%s missing" % path)
    expected_script = init_script(layout, python=record["python"], worker_user=record["worker_user"],
                                  instance_id=record["instance_id"])
    actual = read_small(layout.initd_dir / SERVICE_NAME, 64 * 1024)
    check("service_script", actual == expected_script, "init script matches the installer's template"
          if actual == expected_script else "init script differs from the installer's template")
    units = [p for p in ("etc/systemd/system", "lib/systemd/system", "usr/lib/systemd/system")
             if os.path.exists(Path(fs_root) / p / (SERVICE_NAME + ".service"))]
    check("no_systemd_unit", not units, "no systemd unit" if not units else "systemd unit present in %s" % units)
    links = rc_links(fs_root)
    if record["enable_service"]:
        ok = all(len(links.get(d, [])) == 1 for d in ("rc2.d", "rc3.d", "rc4.d", "rc5.d"))
        check("service_registration", ok, "rc links: %s" % links)
    else:
        check("service_registration", not links, "service not registered (as requested)" if not links else
              "unexpected rc links: %s" % links)
    if exercise_service:
        _exercise(layout, check, proc_root)
    procs = broker_processes(layout, proc_root)
    check("single_instance", len(procs) <= 1, "%d broker process(es)" % len(procs))
    check("broker_privilege", all(p["uid"] == 0 for p in procs), "broker uid(s): %s" % [p["uid"] for p in procs])
    if post_reboot and record["enable_service"]:
        check("started_at_boot", len(procs) == 1, "Guardian broker running after reboot" if procs else
              "Guardian broker not running")
    if post_reboot and not record["enable_service"]:
        check("not_started_at_boot", not procs, "service disabled and not running" if not procs else
              "broker running although the service is disabled")
    checks.append({"check": "yubikey", "status": "ok",
                   "detail": "%d attached; owner operations always need a touch per operation"
                             % yubikeys_present()})
    return {"result": _result(checks), "checks": checks}


def _exercise(layout: InstallLayout, check: Any, proc_root: Path) -> None:
    """start / status / restart / stop of Guardian's own service only (never other services)."""
    script = layout.initd_dir / SERVICE_NAME
    check_trusted_file(script, allowed_owners=(0,))
    was_running = bool(broker_processes(layout, proc_root))
    sequence = ["restart", "status"] if was_running else ["start", "status", "restart", "status", "stop"]
    for action in sequence:
        proc = subprocess.run([str(script), action], stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                              env=dict(SAFE_ENV), check=False)
        time.sleep(1.0 if action in ("start", "restart") else 0)
        count = len(broker_processes(layout, proc_root))
        expected = 0 if action == "stop" else 1
        check("service_" + action, proc.returncode == 0 and count == expected,
              "status %d, %d broker process(es)" % (proc.returncode, count))


def _result(checks: List[Dict[str, str]]) -> str:
    statuses = {c["status"] for c in checks}
    return "BLOCKED" if "blocked" in statuses else "FAILED" if "failed" in statuses else "PASS"


# -- uninstall -------------------------------------------------------------------------------------

def uninstall(layout: InstallLayout = InstallLayout(), *, fs_root: Path = Path("/"), run: Runner = system_runner,
              proc_root: Path = Path("/proc"), audit_factory: Any = None) -> Dict[str, Any]:
    """Remove Guardian's code, service script and registration.  State, keys, data and config stay."""
    if os.geteuid() != 0:
        raise SecurityViolation("uninstall needs root", code="NOT_ROOT")
    removed: List[str] = []
    script = layout.initd_dir / SERVICE_NAME
    if script.exists():
        check_trusted_file(script, allowed_owners=(0,))
        if broker_processes(layout, proc_root):
            subprocess.run([str(script), "stop"], stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
                           env=dict(SAFE_ENV), check=False)
        os.unlink(script)
        removed.append(str(script))
    if rc_links(fs_root):
        rc, _out, err = run(["update-rc.d", SERVICE_NAME, "remove"])
        if rc != 0:
            raise InstallerError("could not remove the service registration: %s" % err.strip()[:200],
                                 code="UNINSTALL_FAILED")
        removed.append("SysVinit registration")
    if os.path.lexists(layout.prefix):
        target = os.path.realpath(layout.current) if os.path.islink(layout.current) else None
        if not layout.releases.is_dir() or (target and Path(target).parent != Path(os.path.realpath(layout.releases))):
            raise InstallerError("%s does not look like a Guardian installation; not removed" % layout.prefix,
                                 code="UNINSTALL_FAILED")
        shutil.rmtree(layout.prefix)
        removed.append(str(layout.prefix))
    if layout.run_dir.exists():
        shutil.rmtree(layout.run_dir)
        removed.append(str(layout.run_dir))
    kept = [str(p) for p in (layout.state_dir, layout.etc_dir, layout.log_file) if p.exists()]
    if layout.state_dir.exists():
        try:
            _audit(layout, audit_factory, "installer.uninstall", removed=removed)
        except GuardianError:
            pass
    return {"removed": removed, "kept": kept,
            "note": "state (trust log, keys, leases, custody, audit, quarantine), configuration and logs are kept; "
                    "shared packages are not removed"}
