# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for the audit ledger.

audit.status / audit.entries / audit.verify   read (audit.read)
audit.checkpoint                               record an owner-signed checkpoint; the
                                               signature (guardian-audit@v1) is the authority
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

from ..identity.sshkeys import KEY_ID_PATTERN
from ..identity.sshsig import MAX_SIGNATURE, NS_AUDIT, SCHEME, SigCheck
from ..identity.trust import TrustStore, TrustVerifier
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from .ledger import AuditLedger, checkpoint_digest


class AuditService:
    def __init__(self, ledger: AuditLedger, trust: TrustStore, sig_check: SigCheck):
        self.ledger = ledger
        self.trust = trust
        self.sig_check = sig_check

    def _checkpoint_verifier(self):
        verifier = TrustVerifier(self.trust.require_state(), self.sig_check, NS_AUDIT)
        return lambda key_id, digest, signature: verifier.verify(SCHEME, key_id, digest, signature)

    def status(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        seq, head = self.ledger.head()
        return {"head_seq": seq, "head": head, "checkpoint_digest": checkpoint_digest(seq, head).hex(),
                "namespace": NS_AUDIT}

    def entries(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return {"entries": self.ledger.entries(params["since"], params["limit"])}

    def verify(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        if self.trust.state() is None:
            return self.ledger.verify()  # chain only; no keys to check checkpoints against yet
        return self.ledger.verify(self._checkpoint_verifier())

    def checkpoint(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        digest = self.ledger.add_checkpoint(params["seq"], params["hash"], params["key_id"],
                                            params["signature"].encode("ascii"), self._checkpoint_verifier())
        return {"checkpoint_entry": digest}

    def operations(self) -> Iterable[Operation]:
        return (
            Operation("audit.status", "audit.read", S.EMPTY, inline=self.status),
            Operation("audit.entries", "audit.read",
                      S.Obj({"since": S.Int(min_value=0, max_value=2 ** 53 - 1),
                             "limit": S.Int(min_value=1, max_value=64)}), inline=self.entries),
            Operation("audit.verify", "audit.read", S.EMPTY, inline=self.verify),
            Operation("audit.checkpoint", "audit.read",
                      S.Obj({"seq": S.Int(min_value=0, max_value=2 ** 53 - 1),
                             "hash": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
                             "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
                             "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE)}), inline=self.checkpoint),
        )
