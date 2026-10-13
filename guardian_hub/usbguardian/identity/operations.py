# SPDX-License-Identifier: GPL-3.0-or-later
"""Broker operations for the trust log.

Trust events carry their own signatures. A valid genesis (proofs from every
new key), or a valid next event (signature by an active key), is itself the
owner proof for ``keys.manage``. No password, PIN or separate unlock step
exists.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from ..common.errors import ConfigError
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.session import Session
from .trust import TrustStore

ENVELOPE_PARAM = S.Obj({"envelope": S.Obj({}, allow_extra=True)})
LOG_PAGE = 32


class TrustService:
    def __init__(self, store: TrustStore):
        self.store = store

    def status(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        state = self.store.state()
        if state is None:
            return {"initialized": False}
        return dict(state.to_document(), initialized=True)

    def log(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        envelopes = self.store.envelopes()
        start = params["since"]
        return {"total": len(envelopes), "since": start, "envelopes": envelopes[start:start + LOG_PAGE]}

    def init_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        if self.store.state() is not None:
            raise ConfigError("trust is already initialized", code="TRUST_ALREADY_INITIALIZED")
        self.store.preview(params["envelope"])  # raises unless a valid genesis
        return True

    def append_proof(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> bool:
        self.store.require_state()
        self.store.preview(params["envelope"])  # raises unless validly signed by an active key
        return True

    def append(self, principal: authz.Principal, params: Dict[str, Any]) -> Any:
        return self.store.append(params["envelope"]).to_document()

    def operations(self) -> Iterable[Operation]:
        return (
            Operation("trust.status", "trust.read", S.EMPTY, inline=self.status),
            Operation("trust.log", "trust.read", S.Obj({"since": S.Int(min_value=0, max_value=1024)}),
                      inline=self.log),
            Operation("trust.init", "keys.manage", ENVELOPE_PARAM, inline=self.append, owner_proof=self.init_proof),
            Operation("trust.append", "keys.manage", ENVELOPE_PARAM, inline=self.append,
                      owner_proof=self.append_proof),
        )
