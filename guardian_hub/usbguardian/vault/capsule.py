# SPDX-License-Identifier: GPL-3.0-or-later
"""age capsules (ROADMAP D7): confidentiality around data Guardian already signs.

STATUS: behind the D7 hardware gate. ``HARDWARE_GATE_PASSED`` is False, so
no broker operation or CLI command offers capsules yet, and Guardian does
not claim hardware-backed encryption. This module holds the mechanics and
the policy so the gate test on the MX machine exercises reviewed code.

Design:
- A capsule is ``age`` encryption of bytes that carry their own owner
  signature (a transfer package, for example). age's authenticated
  encryption detects tampering of the ciphertext, but anyone who knows the
  recipients can make a capsule, so integrity still comes from the inner
  signature, which is verified after opening, as before.
- Recipients come only from an owner-signed recipient set
  (``guardian-recipients@v1``): for each active owner key, the age
  recipient of the matching YubiKey. Sealing requires a recipient for
  every active owner key, so either YubiKey alone can open a capsule (D3).
  Recipients of revoked owner keys are dropped automatically.
- Production accepts only ``age1yubikey1...`` recipients (age-plugin-
  yubikey, PIV, PIN policy never, touch policy always) and only plugin
  identity stubs for opening, never a software secret key. Software X25519
  keys are accepted only under the explicit test policy.
- Plaintext and ciphertext move through descriptors (stdin/stdout of age);
  recipients are public and identities are stubs, so nothing secret is
  placed on a command line.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, FrozenSet, List

from ..common.canonical import canonical_digest
from ..common.errors import GuardianError, IntegrityError, ValidationError
from ..common.fsutil import read_file_bounded
from ..common.text import display_text
from ..common.tools import SAFE_ENV, find_tool, require_tool
from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import NS_RECIPIENTS, SCHEME, SigCheck, check_armor
from ..identity.trust import TrustState, TrustVerifier
from ..runtime import schema as S

HARDWARE_GATE_PASSED = False   # flipped only by a reviewed change after the MX hardware test (ROADMAP D7)
RECIPIENTS_DOMAIN = "guardian/capsule-recipients/v1"
YUBIKEY_RECIPIENT = re.compile(r"age1yubikey1[02-9ac-hj-np-z]{20,120}")
X25519_RECIPIENT = re.compile(r"age1[02-9ac-hj-np-z]{58}")
PLUGIN_IDENTITY = re.compile(r"AGE-PLUGIN-YUBIKEY-1[0-9A-Z]{20,200}")
HARDWARE_POLICY: FrozenSet[str] = frozenset({"yubikey"})
TEST_POLICY: FrozenSet[str] = frozenset({"yubikey", "x25519"})

RECIPIENT_SET_SPEC = S.Obj({
    "format": S.Const("guardian-capsule-recipients"),
    "version": S.Const(1),
    "trust_anchor": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "recipients": S.List(S.Obj({"owner_key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                                "recipient": S.Str(min_len=10, max_len=200),
                                "label": S.Str(pattern=r"[A-Za-z0-9 ._-]{0,32}", max_len=32)}),
                         min_items=1, max_items=8),
})


def recipient_kind(recipient: str) -> str:
    if YUBIKEY_RECIPIENT.fullmatch(recipient):
        return "yubikey"
    if X25519_RECIPIENT.fullmatch(recipient):
        return "x25519"
    raise ValidationError("unsupported age recipient")


def recipient_set_digest(doc: Dict[str, Any]) -> bytes:
    return canonical_digest(RECIPIENTS_DOMAIN, doc)


def capsule_recipients(doc: Any, signer_key_id: str, signature: bytes, trust: TrustState, sig_check: SigCheck, *,
                       policy: FrozenSet[str] = HARDWARE_POLICY) -> List[str]:
    """Verify an owner-signed recipient set; return the recipients for sealing (one or more per active key)."""
    doc = S.validate(RECIPIENT_SET_SPEC, doc, "$.recipients")
    if doc["trust_anchor"] != trust.anchor:
        raise IntegrityError("recipient set belongs to another trust anchor", code="CAPSULE_RECIPIENTS_INVALID")
    try:
        TrustVerifier(trust, sig_check, NS_RECIPIENTS).verify(SCHEME, signer_key_id, recipient_set_digest(doc),
                                                              check_armor(signature))
    except (GuardianError, UnicodeEncodeError) as exc:
        raise IntegrityError("recipient set signature invalid: %s" % getattr(exc, "message", exc),
                             code="CAPSULE_RECIPIENTS_INVALID") from None
    chosen: List[str] = []
    for entry in doc["recipients"]:
        if recipient_kind(entry["recipient"]) not in policy:
            raise ValidationError("recipient type not allowed by policy (hardware recipients only)",
                                  code="CAPSULE_RECIPIENT_NOT_ALLOWED")
        if entry["owner_key_id"] in trust.active and entry["recipient"] not in chosen:
            chosen.append(entry["recipient"])
    covered = {e["owner_key_id"] for e in doc["recipients"] if e["owner_key_id"] in trust.active}
    missing = sorted(set(trust.active) - covered)
    if missing:
        raise ValidationError("no recipient for active owner key(s) %s: either key alone must be able to open "
                              "a capsule" % ", ".join(missing), code="CAPSULE_RECIPIENTS_INCOMPLETE")
    return chosen


def _age(args: List[str], src_fd: int, dst_fd: int, timeout: float) -> None:
    try:
        proc = subprocess.run([require_tool("age")] + args, stdin=src_fd, stdout=dst_fd, stderr=subprocess.PIPE,
                              env=dict(SAFE_ENV), timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        raise GuardianError("age timed out (no touch on the YubiKey?)", code="CAPSULE_TIMEOUT") from None
    if proc.returncode != 0:
        detail = display_text(proc.stderr[-400:], 400)
        code = "CAPSULE_HARDWARE_UNAVAILABLE" if re.search(r"plugin|pcsc|yubikey|smart ?card", detail, re.I) \
            else "CAPSULE_FAILED"
        raise GuardianError("age failed: %s" % detail, code=code)


def seal(src_fd: int, dst_fd: int, recipients: List[str], *, policy: FrozenSet[str] = HARDWARE_POLICY,
         timeout: float = 600.0) -> None:
    """Encrypt everything readable from ``src_fd`` to ``dst_fd`` for the given recipients."""
    if not recipients:
        raise ValidationError("no recipients")
    for r in recipients:
        if recipient_kind(r) not in policy:
            raise ValidationError("recipient type not allowed by policy", code="CAPSULE_RECIPIENT_NOT_ALLOWED")
    args = ["--encrypt"]
    for r in recipients:
        args += ["-r", r]
    _age(args, src_fd, dst_fd, timeout)


def open_capsule(src_fd: int, dst_fd: int, identity_path: str, *, policy: FrozenSet[str] = HARDWARE_POLICY,
                 timeout: float = 600.0) -> None:
    """Decrypt ``src_fd`` into ``dst_fd``.  In production the identity file holds plugin stubs only.

    The output is not trusted until the inner signature has been verified.
    """
    text = read_file_bounded(identity_path, 16 * 1024).decode("ascii", "replace")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    for ln in lines:
        if PLUGIN_IDENTITY.fullmatch(ln):
            continue
        if ln.startswith("AGE-SECRET-KEY-1") and "x25519" in policy:
            continue
        raise ValidationError("identity file must contain YubiKey plugin identities only (no software keys)",
                              code="CAPSULE_IDENTITY_NOT_ALLOWED")
    if not lines:
        raise ValidationError("empty identity file")
    _age(["--decrypt", "-i", identity_path], src_fd, dst_fd, timeout)


def gate_status() -> Dict[str, Any]:
    return {"hardware_gate_passed": HARDWARE_GATE_PASSED,
            "status": "available" if HARDWARE_GATE_PASSED else "deferred until the D7 hardware test passes",
            "age_installed": find_tool("age") is not None,
            "age_plugin_yubikey_installed": find_tool("age-plugin-yubikey") is not None}
