# SPDX-License-Identifier: GPL-3.0-or-later
"""Deployment descriptor and code inventory."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .. import APP_VERSION
from ..common.errors import SecurityViolation, ValidationError
from ..common.names import validate_relative_path
from ..identity.sshkeys import KEY_ID_PATTERN
from ..runtime import schema as S
from ..runtime.authz import CAPABILITIES
from ..vault.custody import SHA256_SPEC, TIMESTAMP_PATTERN
from .profiles import FORGE_ONLY, PLATFORMS, PROFILES

DESCRIPTOR_NAME = "deployment.json"
TRUST_LOG_NAME = "trust.log"
CODE_PREFIX = "code/"
MAX_CODE_FILES = 512
# Never shipped: test-only handlers that simulate hostile workers.
EXCLUDED_CODE = frozenset({"usbguardian/runtime/testing_handlers.py"})
INSTANCE_ID_PATTERN = r"[a-z0-9][a-z0-9-]{0,63}"

DESCRIPTOR_SPEC = S.Obj({
    "format": S.Const("guardian-deployment"),
    "version": S.Const(1),
    "deployment_id": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "instance_id": S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64),
    "platform": S.Enum(PLATFORMS),
    "profile": S.Enum(PROFILES),
    "capabilities": S.List(S.Enum(CAPABILITIES), max_items=len(CAPABILITIES), unique=True),
    "issued": S.Str(pattern=TIMESTAMP_PATTERN, max_len=20),
    # Latest install time for the package itself. Authority comes from the lease (D5, lease/).
    "expires": S.Nullable(S.Str(pattern=TIMESTAMP_PATTERN, max_len=20)),
    "app_version": S.Str(pattern=r"[0-9]{1,4}(\.[0-9]{1,4}){1,3}", max_len=32),
    "trust": S.Obj({"anchor": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
                    "head": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
                    "seq": S.Int(min_value=0, max_value=1023)}),
    "issuer": S.Obj({"instance_id": S.Str(pattern=INSTANCE_ID_PATTERN, max_len=64),
                     "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71)}),
    "code": S.List(S.Obj({"path": S.Str(min_len=1, max_len=255), "sha256": SHA256_SPEC,
                          "length": S.Int(min_value=0, max_value=16 * 1024 * 1024)}),
                   min_items=1, max_items=MAX_CODE_FILES),
})


def check_descriptor(doc: Any) -> Dict[str, Any]:
    desc = S.validate(DESCRIPTOR_SPEC, doc, "$.descriptor")
    if set(desc["capabilities"]) & FORGE_ONLY:
        raise SecurityViolation("a spinoff can never hold Forge capabilities", code="SPINOFF_AUTHORITY")
    if set(desc["capabilities"]) != PROFILES[desc["profile"]]:
        raise ValidationError("capabilities do not match the profile")
    paths = [c["path"] for c in desc["code"]]
    if len(set(paths)) != len(paths) or paths != sorted(paths):
        raise ValidationError("code inventory must be sorted and unique")
    for p in paths:
        validate_relative_path(p)
    return desc


def collect_code(root: Path) -> List[Tuple[str, Path]]:
    """Every shipped source file under ``root`` (the directory holding guardian.py).

    Only regular ``.py`` files are taken; a symlink anywhere in the tree is an error.
    """
    root = Path(root)
    files: List[Tuple[str, Path]] = [("guardian.py", root / "guardian.py")]
    pkg = root / "usbguardian"
    for dirpath, dirnames, filenames in os.walk(pkg, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            st = os.lstat(path)
            if stat.S_ISLNK(st.st_mode):
                raise SecurityViolation("symlink in the code tree: %s" % rel, code="UNTRUSTED_PATH")
            if not name.endswith(".py") or rel in EXCLUDED_CODE:
                continue
            if not stat.S_ISREG(st.st_mode):
                raise SecurityViolation("non-regular file in the code tree: %s" % rel, code="UNTRUSTED_PATH")
            validate_relative_path(rel)
            files.append((rel, path))
    if not (root / "guardian.py").is_file() or len(files) > MAX_CODE_FILES:
        raise ValidationError("code tree is incomplete or too large")
    return sorted(files)


def build_descriptor(*, deployment_id: str, instance_id: str, platform: str, profile: str, issued: str,
                     trust: Dict[str, Any], issuer_instance: str, key_id: str,
                     code: List[Dict[str, Any]], expires: Optional[str] = None) -> Dict[str, Any]:
    return check_descriptor({
        "format": "guardian-deployment", "version": 1, "deployment_id": deployment_id,
        "instance_id": instance_id, "platform": platform, "profile": profile,
        "capabilities": sorted(PROFILES[profile]) if profile in PROFILES else [],
        "issued": issued, "expires": expires, "app_version": APP_VERSION,
        "trust": trust, "issuer": {"instance_id": issuer_instance, "key_id": key_id}, "code": code,
    })
