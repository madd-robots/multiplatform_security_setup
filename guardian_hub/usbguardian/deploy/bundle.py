# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline installation bundle (ROADMAP D11): target-specific, owner-signed, closed.

Layout (one directory, carried on the Rescue USB):

    manifest.json        canonical manifest (below)
    manifest.sig         SSHSIG by an enrolled owner key, namespace guardian-bundle@v1 (one touch)
    deployment.gpkg      the Forge deployment package (itself signed, guardian-deploy@v1)
    trust.log            the owner's trust log
    trust.anchor         the pinned anchor (compare it with Guardian Main before trusting it)
    packages/*.deb       the exact dependency set for this target, resolved in an authenticated
                         environment (apt-get download on a matching system)

The manifest records the target (distribution, release, Debian base,
architecture), every package (name, version, architecture, file, SHA-256,
size, class), every file's SHA-256, the deployment's ids, the trust anchor,
the SysVinit service template hash and the policy (profile, capabilities).

Verification happens before anything privileged: an active owner key of
the bundle's trust log (replayed from its anchor) must have made the
signature, every file must match, and the directory must contain exactly
the listed files (closed bundle). Any difference is INSTALLATION BLOCKED -
BUNDLE INTEGRITY FAILURE, never "most files matched". A bundle for another
target is refused rather than installed as "close enough".

The signing key never enters the bundle: signing is a touch on a YubiKey
during the build.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

from .. import APP_VERSION
from ..common.canonical import canonical_digest, canonical_dumps, canonical_loads
from ..common.errors import GuardianError, IntegrityError, ValidationError
from ..common.fsutil import read_file_bounded
from ..forge.install import parse_trust_log, verify_deployment
from ..forge.profiles import PROFILES
from ..identity.sshkeys import HARDWARE_KEY_TYPES, KEY_ID_PATTERN
from ..identity.sshsig import NS_BUNDLE, SCHEME, SigCheck, check_armor
from ..identity.trust import TrustVerifier, replay
from ..runtime import schema as S
from .debian import InstallLayout, init_script, read_anchor
from .inventory import TOOLS
from .system import Runner, system_runner

INSTALLER_VERSION = "2.0"
BUNDLE_DOMAIN = "guardian/install-bundle/v1"
MANIFEST_NAME, SIGNATURE_NAME = "manifest.json", "manifest.sig"
FIXED_FILES = ("deployment.gpkg", "trust.log", "trust.anchor")
MAX_MANIFEST = 4 * 1024 * 1024
MAX_FILES = 2048
CLASSES = ("REQUIRED RUNTIME", "REQUIRED INSTALLER", "OPTIONAL FEATURE", "HARDWARE FEATURE", "DEPENDENCY")
SHA = S.Str(pattern=r"[0-9a-f]{64}", max_len=64)
NAME = r"[a-z0-9][a-z0-9+.-]{0,63}"
DEB_FILE = r"packages/[A-Za-z0-9][A-Za-z0-9+.~_-]{0,200}\.deb"

TARGET_SPEC = S.Obj({"distribution": S.Str(pattern=r"[a-z]{2,16}", max_len=16),
                     "release": S.Str(pattern=r"[0-9]{1,3}", max_len=3),
                     "debian": S.Str(pattern=r"[0-9]{1,3}", max_len=3),
                     "architecture": S.Str(pattern=r"[a-z0-9-]{1,16}", max_len=16)})
MANIFEST_SPEC = S.Obj({
    "format": S.Const("guardian-install-bundle"),
    "version": S.Const(1),
    "guardian_version": S.Str(pattern=r"[0-9.]{1,16}", max_len=16),
    "installer_version": S.Str(pattern=r"[0-9.]{1,16}", max_len=16),
    "created": S.Str(pattern=r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", max_len=20),
    "target": TARGET_SPEC,
    "deployment": S.Obj({"deployment_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
                         "instance_id": S.Str(pattern=r"[a-z0-9][a-z0-9-]{0,63}", max_len=64),
                         "platform": S.Str(max_len=32), "profile": S.Enum(tuple(PROFILES))}),
    "trust": S.Obj({"anchor": SHA}),
    "packages": S.List(S.Obj({"name": S.Str(pattern=NAME, max_len=64),
                              "version": S.Str(pattern=r"[0-9A-Za-z.+~:-]{1,64}", max_len=64),
                              "architecture": S.Str(pattern=r"[a-z0-9-]{1,16}", max_len=16),
                              "file": S.Str(pattern=DEB_FILE, max_len=220), "class": S.Enum(CLASSES)}),
                       max_items=1024),
    "files": S.List(S.Obj({"path": S.Str(max_len=220), "sha256": SHA,
                           "size": S.Int(min_value=0, max_value=2 ** 40)}), min_items=3, max_items=MAX_FILES),
    "service_template_sha256": SHA,
    "policy": S.Obj({"profile": S.Enum(tuple(PROFILES)), "capabilities_sha256": SHA}),
    "signer": S.Obj({"key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71)}),
})


def bundle_failure(message: str) -> IntegrityError:
    return IntegrityError("INSTALLATION BLOCKED - BUNDLE INTEGRITY FAILURE: " + message,
                          code="BUNDLE_INTEGRITY_FAILURE")


def manifest_digest(manifest: Dict[str, Any]) -> bytes:
    return canonical_digest(BUNDLE_DOMAIN, manifest)


def service_template_sha256() -> str:
    """Hash of the SysVinit script template, rendered with fixed placeholder values."""
    text = init_script(InstallLayout(), python="/usr/bin/python3", worker_user="usbguardian-worker",
                       instance_id="instance")
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def capabilities_sha256(profile: str) -> str:
    return hashlib.sha256(canonical_dumps(sorted(PROFILES[profile]))).hexdigest()


def _sha256_file(path: Path) -> "tuple[str, int]":
    h = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise bundle_failure("%s is not a regular file" % path.name)
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)
    return h.hexdigest(), size


def list_files(root: Path) -> List[str]:
    """Every regular file under ``root`` as a relative path; links and special files are integrity failures."""
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            st = os.lstat(os.path.join(dirpath, name))
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            if stat.S_ISLNK(st.st_mode):
                raise bundle_failure("unexpected symlink %s" % rel)
            if name in filenames:
                if not stat.S_ISREG(st.st_mode):
                    raise bundle_failure("unexpected special file %s" % rel)
                out.append(rel)
        if len(out) > MAX_FILES:
            raise bundle_failure("too many files")
    return sorted(out)


def deb_fields(path: Path, run: Runner = system_runner) -> Dict[str, str]:
    rc, out, err = run(["dpkg-deb", "--field", str(path), "Package", "Version", "Architecture"])
    if rc != 0:
        raise ValidationError("not a Debian package: %s (%s)" % (path.name, err.strip()[:100]))
    fields = dict(line.split(": ", 1) for line in out.splitlines() if ": " in line)
    if set(fields) < {"Package", "Version", "Architecture"}:
        raise ValidationError("incomplete package metadata in %s" % path.name)
    return {"name": fields["Package"].strip(), "version": fields["Version"].strip(),
            "architecture": fields["Architecture"].strip()}


def build_bundle(out_dir: Path, *, deployment: Path, trust_log: Path, anchor_file: Path, debs_dir: Optional[Path],
                 target: Dict[str, str], signer: Any, sig_check: SigCheck, created: str,
                 allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES, run: Runner = system_runner) -> Dict[str, Any]:
    """Build and sign a bundle in a new directory ``out_dir``.  ``signer.sign_ns`` costs one touch."""
    target = S.validate(TARGET_SPEC, target, "$.target")
    anchor = read_anchor(anchor_file)
    envelopes = parse_trust_log(read_file_bounded(Path(trust_log), 8 * 1024 * 1024))
    fd = os.open(deployment, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        desc = verify_deployment(fd, envelopes, anchor, sig_check, allowed_types=allowed_types)["descriptor"]
    finally:
        os.close(fd)
    if desc["platform"] not in ("debian-mx", "rescue-usb"):
        raise ValidationError("bundles are built for Debian/MX deployments")
    state = replay(envelopes, sig_check, anchor=anchor, allowed_types=allowed_types)
    if signer.key_id not in state.active:
        raise ValidationError("the signing key is not an active owner key")
    os.mkdir(out_dir, 0o755)  # must be new
    (Path(out_dir) / "packages").mkdir(mode=0o755)
    shutil.copyfile(deployment, Path(out_dir) / "deployment.gpkg")
    shutil.copyfile(trust_log, Path(out_dir) / "trust.log")
    shutil.copyfile(anchor_file, Path(out_dir) / "trust.anchor")
    packages = []
    for deb in sorted(Path(debs_dir).glob("*.deb")) if debs_dir else []:
        info = deb_fields(deb, run)
        if info["architecture"] not in (target["architecture"], "all"):
            raise ValidationError("%s is built for %s, not %s" % (deb.name, info["architecture"],
                                                                  target["architecture"]))
        if not re.fullmatch(DEB_FILE, "packages/" + deb.name):
            raise ValidationError("unusual package file name %s" % deb.name)
        shutil.copyfile(deb, Path(out_dir) / "packages" / deb.name)
        cls = next((c for _t, (p, c, _u) in TOOLS.items() if p == info["name"]), "DEPENDENCY")
        packages.append(dict(info, file="packages/" + deb.name, **{"class": cls}))
    files = []
    for rel in list_files(Path(out_dir)):
        sha, size = _sha256_file(Path(out_dir) / rel)
        files.append({"path": rel, "sha256": sha, "size": size})
    manifest = S.validate(MANIFEST_SPEC, {
        "format": "guardian-install-bundle", "version": 1, "guardian_version": APP_VERSION,
        "installer_version": INSTALLER_VERSION, "created": created, "target": target,
        "deployment": {k: desc[k] for k in ("deployment_id", "instance_id", "platform", "profile")},
        "trust": {"anchor": anchor}, "packages": packages, "files": files,
        "service_template_sha256": service_template_sha256(),
        "policy": {"profile": desc["profile"], "capabilities_sha256": capabilities_sha256(desc["profile"])},
        "signer": {"key_id": signer.key_id}})
    signature = signer.sign_ns(NS_BUNDLE, manifest_digest(manifest))
    with open(Path(out_dir) / MANIFEST_NAME, "xb") as fh:
        fh.write(canonical_dumps(manifest) + b"\n")
    with open(Path(out_dir) / SIGNATURE_NAME, "xb") as fh:
        fh.write(signature)
    return manifest


def verify_bundle(bundle: Path, sig_check: SigCheck, *, allowed_types: FrozenSet[str] = HARDWARE_KEY_TYPES,
                  expected_anchor: Optional[str] = None) -> Dict[str, Any]:
    """Authenticate the manifest and every file.  Returns the manifest; raises BUNDLE_INTEGRITY_FAILURE."""
    bundle = Path(bundle)
    try:
        present = list_files(bundle)
        manifest = S.validate(MANIFEST_SPEC, canonical_loads(
            read_file_bounded(bundle / MANIFEST_NAME, MAX_MANIFEST).rstrip(b"\n"), require_canonical=True,
            max_bytes=MAX_MANIFEST), "$.manifest")
        signature = check_armor(read_file_bounded(bundle / SIGNATURE_NAME, 16 * 1024))
        anchor = read_anchor(bundle / "trust.anchor")
        envelopes = parse_trust_log(read_file_bounded(bundle / "trust.log", 8 * 1024 * 1024))
    except IntegrityError:
        raise
    except GuardianError as exc:
        raise bundle_failure(exc.message) from None
    if expected_anchor is not None and anchor != expected_anchor:
        raise IntegrityError("bundle is pinned to a different trust anchor", code="TRUST_ANCHOR_MISMATCH")
    if manifest["trust"]["anchor"] != anchor:
        raise bundle_failure("manifest anchor differs from trust.anchor")
    try:
        state = replay(envelopes, sig_check, anchor=anchor, allowed_types=allowed_types)
        TrustVerifier(state, sig_check, NS_BUNDLE).verify(SCHEME, manifest["signer"]["key_id"],
                                                          manifest_digest(manifest), signature)
    except GuardianError as exc:
        raise bundle_failure("manifest signature: %s" % exc.message) from None
    listed = {f["path"]: f for f in manifest["files"]}
    expected = set(listed) | {MANIFEST_NAME, SIGNATURE_NAME}
    if set(present) != expected:
        extra, missing = sorted(set(present) - expected), sorted(expected - set(present))
        raise bundle_failure("unexpected %s / missing %s" % (extra[:5], missing[:5]))
    if not set(FIXED_FILES) <= set(listed) or any(p["file"] not in listed for p in manifest["packages"]):
        raise bundle_failure("manifest does not list its own files")
    for rel, entry in sorted(listed.items()):
        sha, size = _sha256_file(bundle / rel)
        if (sha, size) != (entry["sha256"], entry["size"]):
            raise bundle_failure("%s does not match the manifest" % rel)
    if manifest["service_template_sha256"] != service_template_sha256():
        raise bundle_failure("installer service template differs from the one the bundle was signed for")
    return manifest


def check_target(manifest: Dict[str, Any], platform: Dict[str, Optional[str]]) -> None:
    target = manifest["target"]
    for key in ("distribution", "release", "debian", "architecture"):
        if platform.get(key) != target[key]:
            raise ValidationError("no matching bundle for this system: bundle is for %s %s (Debian %s, %s), "
                                  "this is %s %s (Debian %s, %s)" % (
                                      target["distribution"], target["release"], target["debian"],
                                      target["architecture"], platform.get("distribution"),
                                      platform.get("release"), platform.get("debian"),
                                      platform.get("architecture")), code="BUNDLE_TARGET_MISMATCH")
