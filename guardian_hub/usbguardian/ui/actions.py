# SPDX-License-Identifier: GPL-3.0-or-later
"""UI actions.  Each returns a one-line result for the message bar; nothing here holds authority.

Owner actions go through the same broker operations and YubiKey touch as
the command line. The erase-verification additionally asks the user to
type the device name and re-checks the fingerprint the screen showed, so
a device that was swapped after the screen was drawn is refused.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from ..common.errors import GuardianError
from ..identity.owner import call_as_owner
from ..identity.sshsig import NS_AUDIT, NS_REPORT
from .views import t

Prompt = Callable[[str], str]      # shows a question, returns what the user typed
Notice = Callable[[str], None]     # shows a status line immediately (e.g. "touch the YubiKey")


def _err(exc: GuardianError) -> str:
    return "refused: %s (%s)" % (t(exc.message, 200), exc.code)


def assurance_report(client: Any, kname: str) -> str:
    try:
        r = client.call("assurance.device", {"kname": kname})
    except GuardianError as exc:
        return _err(exc)
    return "report %s: %s (registry %s)" % (r["report_id"], r["result"], r["body"]["registry"])


def erase_verify(client: Any, signer: Optional[Any], device: Dict[str, Any], prompt: Prompt, notice: Notice) -> str:
    if signer is None:
        return "start the UI with --auth KEY.pub HANDLE to run owner operations"
    kname = device["kname"]
    answer = prompt("DESTROY ALL DATA on %s (%s)? Type the device name to confirm: " % (t(kname, 16),
                                                                                        t(device["model"], 30)))
    if answer.strip() != kname:
        return "erase-verify cancelled"
    try:
        notice("Touch the YubiKey to start erasing %s ..." % t(kname, 16))
        out = call_as_owner(client, signer, "device.surface_test",
                            {"kname": kname, "fingerprint": device["fingerprint"]})
    except GuardianError as exc:
        return _err(exc)
    res = out["result"]
    state = "CANCELLED" if res["cancelled"] else "PASSED" if res["passed"] else "FAILED"
    return "erase-verify %s: %s, report %s" % (t(kname, 16), state, out.get("report_id"))


def cancel_erase(client: Any, kname: str) -> str:
    try:
        return "cancel requested" if client.call("device.cancel", {"kname": kname})["cancelling"] else \
            "no erase running on %s" % t(kname, 16)
    except GuardianError as exc:
        return _err(exc)


def sign_report(client: Any, signer: Optional[Any], report_id: str, notice: Notice) -> str:
    if signer is None:
        return "start the UI with --auth KEY.pub HANDLE to sign"
    try:
        entry = client.call("assurance.report", {"report_id": report_id})
        if entry["ledger_match"] is False:
            return "refused: report differs from the audit ledger"
        notice("Touch the YubiKey to sign report %s ..." % report_id)
        sig = signer.sign_ns(NS_REPORT, bytes.fromhex(entry["digest"]))
        out = client.call("assurance.sign", {"report_id": report_id, "key_id": signer.key_id,
                                             "signature": sig.decode("ascii")})
    except GuardianError as exc:
        return _err(exc)
    return "report %s signed (%d signature(s))" % (report_id, out["signatures"])


def verify_audit(client: Any) -> str:
    try:
        r = client.call("audit.verify")
    except GuardianError as exc:
        return _err(exc)
    return "audit chain intact: %d entries, %d checkpoint(s)%s" % (
        r["entries"], len(r["checkpoints"]), "" if r["signed_checkpoints_verified"] else " (signatures not checked)")


def checkpoint_audit(client: Any, signer: Optional[Any], notice: Notice) -> str:
    if signer is None:
        return "start the UI with --auth KEY.pub HANDLE to sign"
    try:
        st = client.call("audit.status")
        notice("Touch the YubiKey to sign a checkpoint at entry %d ..." % st["head_seq"])
        sig = signer.sign_ns(NS_AUDIT, bytes.fromhex(st["checkpoint_digest"]))
        client.call("audit.checkpoint", {"seq": st["head_seq"], "hash": st["head"], "key_id": signer.key_id,
                                         "signature": sig.decode("ascii")})
    except GuardianError as exc:
        return _err(exc)
    return "checkpoint signed at entry %d" % st["head_seq"]


def resume_watchdog(client: Any, signer: Optional[Any], notice: Notice) -> str:
    if signer is None:
        return "start the UI with --auth KEY.pub HANDLE to resume"
    try:
        notice("Touch the YubiKey to lift the watchdog pauses ...")
        out = call_as_owner(client, signer, "watchdog.resume", {})
    except GuardianError as exc:
        return _err(exc)
    return "lifted: %s" % (", ".join(out["lifted"]) or "nothing was paused")
