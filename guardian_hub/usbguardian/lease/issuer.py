# SPDX-License-Identifier: GPL-3.0-or-later
"""Guardian Main side of D5: issue, renew, reissue and revoke spinoff leases.

    lease.prepare  (forge.prepare)          build a lease or revocation record, return its digest
    lease.commit   (forge.build, 1 touch)   the owner's guardian-lease@v1 signature over that digest
                                            is the proof; record it in the registry, return the
                                            signed record for transport (untrusted media is fine)
    lease.check    (forge.prepare)          a reconnecting spinoff's signed request: is its
                                            generation current, superseded or revoked? Returns the
                                            latest signed record, which an obsolete spinoff imports

Issue rules:
- the request must be signed by the spinoff key it names (proof of possession)
- first lease: generation 1 (or the next one), bound to the request's machine
- same key as the current generation: renewal (same generation, new sequence)
- a new key: only with an explicit reissue by the owner, on the same machine;
  generation N+1, and generation N becomes SUPERSEDED at Main at once
- keys of superseded or revoked generations are refused for good, so Main
  rejects further activity from an old generation
- a retired deployment gets no new lease, but can still be revoked
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Callable, Dict, Iterable, Optional

from ..common.errors import IntegrityError, NotFound, ValidationError
from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_LEASE, SCHEME, SigCheck
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.session import Session
from ..forge.registry import DeploymentRegistry
from . import records as R

ENVELOPE_PARAM = S.Obj({}, allow_extra=True)


class LeaseIssuer:
    def __init__(self, trust: TrustStore, sig_check: SigCheck, registry: DeploymentRegistry, instance_id: str, *,
                 default_days: int = R.DEFAULT_LEASE_DAYS, warn_days: int = R.DEFAULT_WARN_DAYS,
                 clock: Callable[[], int] = lambda: int(time.time())):
        if not 0 <= warn_days < default_days <= R.MAX_LEASE_DAYS:
            raise ValueError("invalid lease policy")
        self.trust = trust
        self.sig_check = sig_check
        self.registry = registry
        self.instance_id = instance_id
        self.default_days = default_days
        self.warn_days = warn_days
        self.clock = clock

    def _issue(self, entry: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        if entry["status"] != "active":
            raise ValidationError("deployment is retired; no new lease", code="LEASE_REFUSED")
        if "request" not in params:
            raise ValidationError("issuing a lease needs the spinoff's signed request")
        req = R.verify_request(params["request"], self.sig_check)
        if req["instance_id"] != entry["instance_id"]:
            raise ValidationError("request is for another instance", code="LEASE_WRONG_SPINOFF")
        key = R.parse_spinoff_key(req["spinoff_key"])
        lease = entry["lease"]
        known = {g["key_id"]: g for g in lease["generations"]}
        previous = known.get(key.key_id)
        if previous is not None and previous["status"] == "superseded":
            raise IntegrityError("request comes from superseded generation %d" % previous["generation"],
                                 code="LEASE_GENERATION_SUPERSEDED")
        if previous is not None and previous["status"] == "revoked":
            raise IntegrityError("request comes from revoked generation %d" % previous["generation"],
                                 code="LEASE_GENERATION_REVOKED")
        if lease["machine_id"] is not None and req["machine_id"] != lease["machine_id"]:
            raise IntegrityError("request comes from another machine; a new machine needs its own instance id",
                                 code="LEASE_WRONG_MACHINE")
        if previous is not None:
            generation, kind = lease["generation"], "renewal"
        elif lease["generation"] == 0 and not lease["generations"]:
            generation, kind = 1, "first lease"
        elif params.get("reissue", False):
            generation, kind = lease["generation"] + 1, "reissue"
        else:
            raise ValidationError("this key is new for an instance that already has a generation; the owner must "
                                  "confirm a reissue", code="LEASE_REISSUE_REQUIRED")
        days = params.get("days", self.default_days)
        warn = params.get("warn_days", min(self.warn_days, days - 1))
        if not 0 <= warn < days:
            raise ValidationError("warning window must be shorter than the lease")
        now = self.clock()
        return {"kind": "lease", "generation": generation, "machine_id": req["machine_id"],
                "spinoff_key": key.to_line(), "not_before": now, "not_after": now + days * R.DAY,
                "warn_seconds": warn * R.DAY, "reason": "", "_summary": {
                    "action": kind, "key_fingerprint": key.openssh_fingerprint,
                    "machine_sources": req["machine_sources"], "days": days,
                    "not_after": R.iso(now + days * R.DAY), "spinoff_reported_state": req["state"]}}

    def _revoke(self, entry: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
        lease = entry["lease"]
        current = [g for g in lease["generations"] if g["generation"] == lease["generation"]]
        if not current or current[0]["status"] != "active":
            raise ValidationError("no active generation to revoke", code="LEASE_NOTHING_TO_REVOKE")
        return {"kind": "revocation", "generation": lease["generation"], "machine_id": lease["machine_id"],
                "spinoff_key": None, "not_before": None, "not_after": None, "warn_seconds": None,
                "reason": params.get("reason", ""), "_summary": {"action": "revocation"}}

    def prepare(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        trust = self.trust.require_state()
        if params["key_id"] not in trust.active:
            raise ValidationError("key is not an active owner key")
        entry = self.registry.get(params["instance_id"])
        built = self._issue(entry, params) if params["action"] == "issue" else self._revoke(entry, params)
        summary = built.pop("_summary")
        record = R.check_record(dict(built, format="guardian-lease", version=1, record_id=secrets.token_hex(16),
                                     instance_id=entry["instance_id"], seq=entry["lease"]["seq"] + 1,
                                     issued=self.clock(), trust_anchor=trust.anchor,
                                     issuer={"instance_id": self.instance_id, "key_id": params["key_id"]}))
        session.put_pending("lease:" + record["record_id"], (record, entry["lease"]["seq"]))
        return dict(summary, record_id=record["record_id"], digest=R.record_digest(record).hex(),
                    namespace=NS_LEASE, instance_id=record["instance_id"], kind=record["kind"],
                    generation=record["generation"], seq=record["seq"], machine_id=record["machine_id"])

    def _pending(self, params: Dict[str, Any], session: Optional[Session]) -> Any:
        pending = session.get_pending("lease:" + params["record_id"]) if session is not None else None
        if pending is None:
            raise NotFound("no prepared lease record with this id on this connection")
        return pending

    def commit_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        record, _ = self._pending(params, session)
        try:
            TrustVerifier(self.trust.require_state(), self.sig_check, NS_LEASE).verify(
                SCHEME, record["issuer"]["key_id"], R.record_digest(record), params["signature"].encode("ascii"))
        except (IntegrityError, UnicodeEncodeError):
            return False
        return True

    def commit(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        assert session is not None
        record, expected_seq = self._pending(params, session)
        envelope = {"record": record, "signature": params["signature"]}
        key_id = R.parse_spinoff_key(record["spinoff_key"]).key_id if record["kind"] == "lease" else None

        def change(lease: Dict[str, Any]) -> Dict[str, Any]:
            gens = [dict(g) for g in lease["generations"]]
            if record["kind"] == "lease":
                if record["generation"] > lease["generation"] or not gens:
                    for g in gens:
                        if g["status"] == "active":
                            g["status"] = "superseded"
                    gens.append({"generation": record["generation"], "key_id": key_id, "status": "active"})
                lease.update(generation=record["generation"], machine_id=record["machine_id"],
                             spinoff_key=record["spinoff_key"], not_after=record["not_after"])
            else:
                for g in gens:
                    if g["generation"] <= record["generation"] and g["status"] == "active":
                        g["status"] = "revoked"
            lease.update(seq=record["seq"], generations=gens[-256:], last_record=envelope)
            return lease

        self.registry.update_lease(record["instance_id"], expected_seq, change)
        session.drop_pending("lease:" + params["record_id"])
        return {"envelope": envelope, "kind": record["kind"], "instance_id": record["instance_id"],
                "generation": record["generation"], "seq": record["seq"],
                "not_after": R.iso(record["not_after"]) if record["not_after"] is not None else None}

    def check(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        req = R.verify_request(params["request"], self.sig_check)
        entry = self.registry.get(req["instance_id"])
        lease = entry["lease"]
        key_id = R.parse_spinoff_key(req["spinoff_key"]).key_id
        known = {g["key_id"]: g for g in lease["generations"]}
        g = known.get(key_id)
        if g is None:
            status = "unknown_key"
        elif g["status"] == "active":
            status = "current" if entry["status"] == "active" else "retired"
        else:
            status = g["status"]
        if lease["machine_id"] is not None and req["machine_id"] != lease["machine_id"]:
            status = "wrong_machine"
        return {"status": status, "instance_id": entry["instance_id"], "deployment": entry["status"],
                "generation": lease["generation"], "seq": lease["seq"],
                "not_after": R.iso(lease["not_after"]) if lease["not_after"] is not None else None,
                "latest": lease["last_record"]}

    def operations(self) -> Iterable[Operation]:
        iid = S.Str(pattern=R.INSTANCE_ID_PATTERN, max_len=64)
        return (
            Operation("lease.prepare", "forge.prepare",
                      S.Obj({"action": S.Enum(("issue", "revoke")), "instance_id": iid,
                             "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71), "request": ENVELOPE_PARAM,
                             "reissue": S.Bool(), "days": S.Int(min_value=1, max_value=R.MAX_LEASE_DAYS),
                             "warn_days": S.Int(min_value=0, max_value=R.MAX_LEASE_DAYS - 1),
                             "reason": S.Str(pattern=r"[A-Za-z0-9 ._,:/-]{0,200}", max_len=200)},
                            optional=("request", "reissue", "days", "warn_days", "reason")),
                      inline=self.prepare, session_aware=True),
            Operation("lease.commit", "forge.build",
                      S.Obj({"record_id": S.Str(pattern=R.HEX32, max_len=32),
                             "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}),
                      inline=self.commit, session_aware=True, owner_proof=self.commit_proof),
            Operation("lease.check", "forge.prepare", S.Obj({"request": ENVELOPE_PARAM}), inline=self.check),
        )
