# SPDX-License-Identifier: GPL-3.0-or-later
"""Spinoff side of D5: local lease state, the spinoff key, and the ACTIVE gate.

Files (private directory ``<state>/lease``, root-owned on an installed spinoff):

    state.json        accepted lease state (canonical JSON)
    key, key.pub      the current spinoff key (ssh-ed25519), generated here, never exported
    pending.key(.pub) a fresh key waiting for its reissue lease (``lease.request`` with rekey)

What the spinoff can do: make a request, import owner-signed records, and
report its state. What it cannot do: extend, renew or un-revoke itself,
lower its generation or sequence, or accept a record not signed by an
active owner key for this instance and machine.

State rules (fail closed):
- sequences only increase; a record at or below the accepted sequence is
  refused, except the identical record again (no change)
- a revocation of generation G marks every generation <= G revoked
- a valid lease for this instance and machine with a higher generation and
  someone else's key means this installation is SUPERSEDED
- once an expiry was observed it is sticky for that lease, so setting the
  clock back never revives it
- the clock may not run behind the high-water mark of observed time (or the
  issue time of the lease) by more than CLOCK_TOLERANCE; otherwise UNKNOWN
- an owner-signed newer lease resets the high-water mark to its issue time,
  which is the recovery from a clock that once ran far ahead

Limits: without protected non-rollback storage (for example a TPM), root
can delete or replace this directory. The audit ledger records every
accepted sequence, so replacing ``state.json`` with an older copy is
detected while the ledger is intact (and a signed ledger checkpoint makes
rewriting the ledger detectable too). Deleting both is not detectable here.
"""

from __future__ import annotations

import copy
import os
import secrets
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from ..common.canonical import canonical_dumps, canonical_loads
from ..common.errors import ConfigError, GuardianError, IntegrityError, PermissionDenied, ValidationError
from ..common.fsutil import atomic_write, ensure_private_dir, read_file_bounded
from ..common.tools import SAFE_ENV, require_tool
from ..identity.sshkeys import SshPublicKey
from ..identity.sshsig import NS_LEASE, NS_SPINOFF, SCHEME, SigCheck, SshKeygenSigner
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from . import records as R
from .machine import machine_identity

CLOCK_TOLERANCE = 300        # seconds the clock may step back (NTP corrections) before UNKNOWN
HWM_PERSIST_STEP = 60        # persist the high-water mark when it advanced at least this much
MAX_ACCEPTED = 32
MAX_EVIDENCE = 8
STATE_LIMIT = 256 * 1024

STATE_SPEC = S.Obj({
    "version": S.Const(1),
    "instance_id": S.Str(pattern=R.INSTANCE_ID_PATTERN, max_len=64),
    "generation": S.Int(min_value=0, max_value=R.MAX_GENERATION),
    "seq": S.Int(min_value=0, max_value=R.MAX_SEQ),
    "lease": S.Nullable(S.Obj({}, allow_extra=True)),
    "revoked_generation": S.Int(min_value=0, max_value=R.MAX_GENERATION),
    "superseded_by": S.Int(min_value=0, max_value=R.MAX_GENERATION),
    "expired_seq": S.Int(min_value=0, max_value=R.MAX_SEQ),
    "time_hwm": S.Int(min_value=0, max_value=R.MAX_TIME),
    "accepted": S.List(S.Str(pattern=R.HEX64, max_len=64), max_items=MAX_ACCEPTED),
    "evidence": S.List(S.Obj({}, allow_extra=True), max_items=MAX_EVIDENCE),
})


def fresh_state(instance_id: str) -> Dict[str, Any]:
    return {"version": 1, "instance_id": instance_id, "generation": 0, "seq": 0, "lease": None,
            "revoked_generation": 0, "superseded_by": 0, "expired_seq": 0, "time_hwm": 0, "accepted": [],
            "evidence": []}


def apply_record(state: Dict[str, Any], envelope: Dict[str, Any], digest_hex: str, *,
                 key_id: Optional[str], pending_key_id: Optional[str]) -> Tuple[Dict[str, Any], str]:
    """Pure state transition for a record whose signature and binding were already checked."""
    s = copy.deepcopy(state)
    rec = envelope["record"]
    if digest_hex in s["accepted"]:
        return s, "already_imported"
    if rec["seq"] <= s["seq"]:
        raise IntegrityError("record sequence %d is not newer than the accepted %d (stale or rolled back)"
                             % (rec["seq"], s["seq"]), code="LEASE_STALE")
    gen = rec["generation"]
    if rec["kind"] == "revocation":
        s["revoked_generation"] = max(s["revoked_generation"], gen)
        outcome = "revoked" if s["generation"] and gen >= s["generation"] else "revocation_recorded"
        s["evidence"] = (s["evidence"] + [envelope])[-MAX_EVIDENCE:]
    else:
        if gen <= s["revoked_generation"]:
            raise IntegrityError("lease names a revoked generation", code="LEASE_GENERATION_REVOKED")
        if gen <= s["superseded_by"]:
            raise IntegrityError("lease names a superseded generation", code="LEASE_GENERATION_SUPERSEDED")
        record_key = R.parse_spinoff_key(rec["spinoff_key"]).key_id
        if record_key == key_id:
            if s["generation"] not in (0, gen):
                raise IntegrityError("generation changed without a fresh key", code="LEASE_GENERATION_MISMATCH")
            outcome = "lease_accepted"
        elif record_key == pending_key_id:
            if gen <= s["generation"]:
                raise IntegrityError("a reissue must raise the generation", code="LEASE_GENERATION_MISMATCH")
            outcome = "lease_rekeyed"
        elif gen > s["generation"]:
            # A newer generation exists for this instance and machine, with another key.
            s["superseded_by"] = gen
            s["seq"] = rec["seq"]
            s["accepted"] = (s["accepted"] + [digest_hex])[-MAX_ACCEPTED:]
            s["evidence"] = (s["evidence"] + [envelope])[-MAX_EVIDENCE:]
            return s, "superseded"
        else:
            raise IntegrityError("lease is for a different spinoff key", code="LEASE_KEY_MISMATCH")
        s["generation"] = gen
        s["lease"] = envelope
        s["time_hwm"] = rec["issued"]
    s["seq"] = rec["seq"]
    s["accepted"] = (s["accepted"] + [digest_hex])[-MAX_ACCEPTED:]
    return s, outcome


def _keygen(path: Path) -> None:
    proc = subprocess.run([require_tool("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", "guardian-spinoff",
                           "-f", str(path)], env=dict(SAFE_ENV), stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=60, shell=False, check=False)
    if proc.returncode != 0:
        raise GuardianError("spinoff key generation failed", code="KEYGEN_FAILED")


class LeaseAuthority:
    def __init__(self, directory: Path, trust: TrustStore, sig_check: SigCheck, *, instance_id: str,
                 deployment_id: str, machine_root: Path = Path("/"), audit: Optional[Any] = None,
                 clock: Callable[[], int] = lambda: int(time.time())):
        self.directory = Path(directory)
        ensure_private_dir(self.directory)
        self.trust = trust
        self.sig_check = sig_check
        self.instance_id = instance_id
        self.deployment_id = deployment_id
        self.audit = audit
        self.clock = clock
        self.state_path = self.directory / "state.json"
        self._lock = threading.Lock()
        self.problem: Optional[str] = None   # set when local state cannot be trusted (fails closed)
        self.rolled_back = False             # the only problem a newer signed record can repair
        try:
            self.machine_id, self.machine_sources = machine_identity(machine_root)
        except ConfigError as exc:
            self.machine_id, self.machine_sources = None, []
            self.problem = exc.message
        self.state = self._load()
        self._finish_rekey()
        self._check_loaded()

    # -- persistence ---------------------------------------------------------------------------

    def _load(self) -> Dict[str, Any]:
        if not self.state_path.exists():
            return fresh_state(self.instance_id)
        try:
            doc = canonical_loads(read_file_bounded(self.state_path, STATE_LIMIT, require_private=True),
                                  require_canonical=True, max_bytes=STATE_LIMIT)
            state = S.validate(STATE_SPEC, doc, "$.lease_state")
        except GuardianError as exc:
            self.problem = "local lease state is unreadable: %s" % exc.message
            return fresh_state(self.instance_id)
        if state["instance_id"] != self.instance_id:
            self.problem = "local lease state belongs to another instance"
        return state

    def _save(self, state: Dict[str, Any]) -> None:
        atomic_write(self.state_path, canonical_dumps(state))
        self.state = state

    def _check_loaded(self) -> None:
        s = self.state
        if s["lease"] is not None and self.problem is None:
            try:
                env = self._verify_envelope(s["lease"])
                if env["record"]["generation"] != s["generation"] or env["record"]["seq"] > s["seq"]:
                    raise IntegrityError("lease does not match the recorded generation or sequence")
                if R.parse_spinoff_key(env["record"]["spinoff_key"]).key_id != self._key_id("key"):
                    raise IntegrityError("the spinoff key does not match the lease")
            except GuardianError as exc:
                self.problem = "local lease state failed verification: %s" % exc.message
        if self.audit is not None and self.problem is None:
            try:
                seqs = [f.get("seq") for f in self.audit.find_fields("lease.accepted")]
                highest = max((q for q in seqs if isinstance(q, int)), default=0)
            except GuardianError as exc:
                self.problem = "audit ledger unreadable: %s" % exc.message
            else:
                if highest > s["seq"]:
                    self.rolled_back = True
                    self.problem = ("local lease state (sequence %d) is older than the audit ledger (%d): "
                                    "rolled back or lost; import the latest record again" % (s["seq"], highest))

    # -- keys ----------------------------------------------------------------------------------

    def _key_path(self, name: str) -> Path:
        return self.directory / name

    def _public(self, name: str) -> Optional[SshPublicKey]:
        priv, pub = self._key_path(name), self._key_path(name + ".pub")
        if not os.path.lexists(priv) or not os.path.lexists(pub):
            return None
        st = os.lstat(priv)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise IntegrityError("spinoff private key has unsafe type or permissions", code="NOT_PRIVATE")
        return R.parse_spinoff_key(read_file_bounded(pub, 1024).decode("ascii", "replace"))

    def _key_id(self, name: str) -> Optional[str]:
        key = self._public(name)
        return key.key_id if key is not None else None

    def _new_key(self, name: str) -> SshPublicKey:
        tmp = self._key_path(".keygen-" + secrets.token_hex(8))
        try:
            _keygen(tmp)
            os.replace(str(tmp) + ".pub", self._key_path(name + ".pub"))
            os.replace(tmp, self._key_path(name))
        finally:
            for leftover in (tmp, Path(str(tmp) + ".pub")):
                if os.path.lexists(leftover):
                    os.unlink(leftover)
        key = self._public(name)
        assert key is not None
        return key

    def _finish_rekey(self) -> None:
        """Complete a promotion interrupted after the state was saved (crash safety)."""
        lease = self.state["lease"]
        if lease is None or self.problem is not None:
            return
        try:
            wanted = R.parse_spinoff_key(lease["record"]["spinoff_key"]).key_id
            if self._key_id("key") != wanted and self._key_id("pending.key") == wanted:
                self._promote_pending()
        except (GuardianError, KeyError, TypeError):
            return  # _check_loaded reports it

    def _promote_pending(self) -> None:
        # The old private key is unlinked and never used again. Flash media may
        # keep remnants of it; that is why a reissue always uses a fresh key.
        os.replace(self._key_path("pending.key.pub"), self._key_path("key.pub"))
        os.replace(self._key_path("pending.key"), self._key_path("key"))

    # -- verification --------------------------------------------------------------------------

    def _verify_envelope(self, envelope: Any) -> Dict[str, Any]:
        env = R.check_envelope(envelope)
        rec = env["record"]
        trust = self.trust.require_state()
        if rec["trust_anchor"] != trust.anchor:
            raise IntegrityError("record belongs to another trust anchor", code="LEASE_WRONG_ANCHOR")
        if rec["instance_id"] != self.instance_id:
            raise IntegrityError("record is for another spinoff", code="LEASE_WRONG_SPINOFF")
        if self.machine_id is None or rec["machine_id"] != self.machine_id:
            raise IntegrityError("record is bound to another machine", code="LEASE_WRONG_MACHINE")
        try:
            signature = env["signature"].encode("ascii")
        except UnicodeEncodeError:
            raise IntegrityError("malformed signature", code="LEASE_SIGNATURE_INVALID") from None
        try:
            TrustVerifier(trust, self.sig_check, NS_LEASE).verify(SCHEME, rec["issuer"]["key_id"],
                                                                   R.record_digest(rec), signature)
        except IntegrityError as exc:
            raise IntegrityError("record signature invalid: %s" % exc.message,
                                 code="LEASE_SIGNATURE_INVALID") from None
        return env

    # -- evaluation ----------------------------------------------------------------------------

    def _evaluate(self, now: int) -> Tuple[str, str]:
        s = self.state
        if self.problem is not None:
            return "UNKNOWN", self.problem
        if s["generation"] and s["revoked_generation"] >= s["generation"]:
            return "REVOKED", "generation %d was revoked by the owner" % s["generation"]
        if s["superseded_by"] > s["generation"]:
            return "SUPERSEDED", "generation %d replaces this installation" % s["superseded_by"]
        if s["lease"] is None:
            return "UNLEASED", "no lease imported yet"
        rec = s["lease"]["record"]
        trust = self.trust.state()
        if trust is None or rec["issuer"]["key_id"] not in trust.active:
            return "UNLEASED", "the lease was signed by an owner key that is no longer active; renew it"
        if s["expired_seq"] >= rec["seq"]:
            return "EXPIRED", "lease expired at %s" % R.iso(rec["not_after"])
        floor = max(s["time_hwm"], rec["not_before"])
        if now + CLOCK_TOLERANCE < floor:
            return "UNKNOWN", ("system clock (%s) is behind time already observed (%s); authority fails closed"
                               % (R.iso(now), R.iso(floor)))
        if now >= rec["not_after"]:
            self._save(dict(s, expired_seq=rec["seq"], time_hwm=max(s["time_hwm"], now)))
            return "EXPIRED", "lease expired at %s" % R.iso(rec["not_after"])
        if now >= s["time_hwm"] + HWM_PERSIST_STEP:
            self._save(dict(s, time_hwm=now))
        if now >= rec["not_after"] - rec["warn_seconds"]:
            return "EXPIRING", "lease expires at %s; renew it" % R.iso(rec["not_after"])
        return "ACTIVE", "lease valid until %s" % R.iso(rec["not_after"])

    def evaluate(self) -> Tuple[str, str]:
        with self._lock:
            return self._evaluate(self.clock())

    def check(self, op: Operation) -> None:
        """Broker gate (runtime/broker.py)."""
        if op.requires_active:
            self.require_active(op.name)

    def require_active(self, op_name: str) -> None:
        """Broker gate: operations that need ACTIVE authority run only in ACTIVE or EXPIRING."""
        try:
            state, reason = self.evaluate()
        except Exception:
            state, reason = "UNKNOWN", "lease state could not be evaluated or saved"
        if state not in R.AUTHORIZED_STATES:
            raise PermissionDenied("%s needs an active lease; lease state %s: %s" % (op_name, state, reason),
                                   code="LEASE_NOT_ACTIVE")

    # -- operations ----------------------------------------------------------------------------

    def status(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        with self._lock:
            now = self.clock()
            state, reason = self._evaluate(now)
            s = self.state
            rec = s["lease"]["record"] if s["lease"] is not None else None
            current, pending = self._public("key"), self._public("pending.key")
            return {
                "state": state, "reason": reason, "instance_id": self.instance_id,
                "generation": s["generation"], "seq": s["seq"],
                "not_before": R.iso(rec["not_before"]) if rec else None,
                "not_after": R.iso(rec["not_after"]) if rec else None,
                "revoked_generation": s["revoked_generation"], "superseded_by": s["superseded_by"],
                "machine_id": self.machine_id, "machine_sources": self.machine_sources,
                "key_fingerprint": current.openssh_fingerprint if current else None,
                "pending_key_fingerprint": pending.openssh_fingerprint if pending else None,
                "clock": R.iso(now), "clock_high_water": R.iso(s["time_hwm"]) if s["time_hwm"] else None,
            }

    def request(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        with self._lock:
            if self.machine_id is None:
                raise ConfigError("machine identity unavailable", code="MACHINE_ID_UNAVAILABLE")
            state, _ = self._evaluate(self.clock())
            if params["rekey"] and self.state["generation"]:
                name, key = "pending.key", self._new_key("pending.key")
            else:
                current = self._public("key")
                if current is None:
                    if self.state["generation"]:
                        raise IntegrityError("the spinoff key is missing; request a reissue with rekey",
                                             code="SPINOFF_KEY_MISSING")
                    current = self._new_key("key")
                name, key = "key", current
            request = S.validate(R.REQUEST_SPEC, {
                "format": "guardian-lease-request", "version": 1, "instance_id": self.instance_id,
                "deployment_id": self.deployment_id, "machine_id": self.machine_id,
                "machine_sources": self.machine_sources, "spinoff_key": key.to_line(),
                "generation": self.state["generation"], "seq": self.state["seq"], "state": state,
                "time": self.clock(), "nonce": secrets.token_hex(16)})
            signature = SshKeygenSigner(str(self._key_path(name)), key).sign_ns(NS_SPINOFF,
                                                                                R.request_digest(request))
            return {"envelope": {"request": request, "key_id": key.key_id, "signature": signature.decode("ascii")},
                    "key_fingerprint": key.openssh_fingerprint, "machine_id": self.machine_id,
                    "rekey": params["rekey"]}

    def import_record(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        with self._lock:
            if self.problem is not None and not self.rolled_back:
                raise IntegrityError("lease state cannot be trusted: %s" % self.problem, code="LEASE_STATE_UNKNOWN")
            env = self._verify_envelope(params["envelope"])
            digest = R.record_digest(env["record"]).hex()
            new_state, outcome = apply_record(self.state, env, digest, key_id=self._key_id("key"),
                                              pending_key_id=self._key_id("pending.key"))
            if outcome != "already_imported":
                rec = env["record"]
                if self.audit is not None:
                    # Recorded first: a failed ledger write refuses the import.
                    self.audit.append("lease.accepted", exact={"kind": rec["kind"], "seq": rec["seq"],
                                                               "generation": rec["generation"], "record": digest,
                                                               "outcome": outcome})
                self._save(new_state)
                if outcome == "lease_rekeyed":
                    self._promote_pending()
                if self.rolled_back and new_state["seq"] >= self._ledger_floor():
                    self.problem, self.rolled_back = None, False  # caught up with the ledger again
            state, reason = self._evaluate(self.clock())
            return {"outcome": outcome, "state": state, "reason": reason, "generation": self.state["generation"],
                    "seq": self.state["seq"]}

    def _ledger_floor(self) -> int:
        if self.audit is None:
            return 0
        seqs = [f.get("seq") for f in self.audit.find_fields("lease.accepted")]
        return max((q for q in seqs if isinstance(q, int)), default=0)

    def operations(self) -> Iterable[Operation]:
        return (
            Operation("lease.status", "lease.read", S.EMPTY, inline=self.status),
            Operation("lease.request", "lease.manage", S.Obj({"rekey": S.Bool()}), inline=self.request),
            Operation("lease.import", "lease.manage", S.Obj({"envelope": S.Obj({}, allow_extra=True)}),
                      inline=self.import_record),
        )
