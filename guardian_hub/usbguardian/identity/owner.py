# SPDX-License-Identifier: GPL-3.0-or-later
"""Owner assertions: a YubiKey touch authorizes exactly one request.

    client                               broker
    auth.challenge  --------------->     fresh nonce (single use, 120 s)
    sign assertion (touch)               digest binds: nonce, broker id, uid,
                                         operation, digest of its exact params,
                                         key id
    auth.assert     --------------->     verify (sandboxed ssh-keygen) against
                                         the active keys; store a one-shot grant
    OP(params)      --------------->     grant consumed -> owner_key factor

The grant cannot be reused, moved to another connection, or applied to
different parameters. There is no session-wide unlock, and nothing is typed:
nothing a keylogger or screen observer captures is reusable (D1, D2).
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Optional, Sequence

from ..common.canonical import canonical_digest
from ..common.errors import GuardianError, PermissionDenied, ValidationError
from ..runtime import authz
from ..runtime import schema as S
from ..runtime.broker import Operation
from ..runtime.client import BrokerClient
from ..runtime.ipc import OP_PATTERN
from ..runtime.session import GRANT_TTL, Session
from .sshkeys import KEY_ID_PATTERN
from .sshsig import MAX_SIGNATURE, NS_OWNER, SigCheck, SshKeygenSigner, check_armor
from .trust import TrustStore

ASSERTION_DOMAIN = "guardian/owner-assertion/v1"
BROKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")

ASSERT_SPEC = S.Obj({
    "nonce": S.Str(pattern=r"[0-9a-f]{32}", max_len=32),
    "key_id": S.Str(pattern=KEY_ID_PATTERN, max_len=71),
    "op": S.Str(pattern=OP_PATTERN, max_len=130),
    "request_digest": S.Str(pattern=r"[0-9a-f]{64}", max_len=64),
    "signature": S.Str(min_len=1, max_len=MAX_SIGNATURE),
})


def assertion_digest(*, nonce: str, broker_id: str, uid: int, op: str, request_digest: str, key_id: str) -> bytes:
    return canonical_digest(ASSERTION_DOMAIN, {"nonce": nonce, "broker_id": broker_id, "uid": uid, "op": op,
                                               "request_digest": request_digest, "key_id": key_id})


class OwnerAuthority:
    def __init__(self, trust: TrustStore, sig_check: SigCheck, broker_id: str):
        if not BROKER_ID_RE.match(broker_id):
            raise ValueError("invalid broker id")
        self.trust = trust
        self.sig_check = sig_check
        self.broker_id = broker_id

    def challenge(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        if session is None:
            raise PermissionDenied("owner assertions need a connection")
        self.trust.require_state()
        return {"nonce": session.new_challenge(), "broker_id": self.broker_id, "uid": principal.uid,
                "expires_in": 120}

    def assert_(self, principal: authz.Principal, params: Dict[str, Any], session: Optional[Session]) -> Any:
        if session is None or not session.take_challenge(params["nonce"]):
            raise PermissionDenied("unknown, used or expired challenge", code="CHALLENGE_INVALID")
        enrolled = self.trust.require_state().active.get(params["key_id"])
        if enrolled is None:
            raise PermissionDenied("key is not an active owner key", code="OWNER_KEY_REJECTED")
        digest = assertion_digest(nonce=params["nonce"], broker_id=self.broker_id, uid=principal.uid,
                                  op=params["op"], request_digest=params["request_digest"], key_id=params["key_id"])
        try:
            signature = check_armor(params["signature"].encode("ascii"))
        except (GuardianError, UnicodeEncodeError):
            raise PermissionDenied("malformed assertion signature", code="OWNER_KEY_REJECTED") from None
        if not self.sig_check(enrolled.key, NS_OWNER, digest, signature):
            raise PermissionDenied("owner assertion did not verify", code="OWNER_KEY_REJECTED")
        session.add_grant(params["op"], params["request_digest"])
        return {"granted_op": params["op"], "key_id": params["key_id"], "expires_in": int(GRANT_TTL)}

    def operations(self) -> Iterable[Operation]:
        return (
            Operation("auth.challenge", "auth.assert", S.EMPTY, inline=self.challenge, session_aware=True),
            Operation("auth.assert", "auth.assert", ASSERT_SPEC, inline=self.assert_, session_aware=True),
        )


def call_as_owner(client: BrokerClient, signer: SshKeygenSigner, op: str, params: Dict[str, Any],
                  fds: Sequence[int] = ()) -> Any:
    """Client side: challenge, one touch, assert, then the request itself."""
    if not re.fullmatch(OP_PATTERN, op):
        raise ValidationError("invalid operation name")
    challenge = client.call("auth.challenge")
    rdigest = authz.request_digest(op, params)
    digest = assertion_digest(nonce=challenge["nonce"], broker_id=challenge["broker_id"], uid=challenge["uid"],
                              op=op, request_digest=rdigest, key_id=signer.key_id)
    signature = signer.sign_ns(NS_OWNER, digest)
    client.call("auth.assert", {"nonce": challenge["nonce"], "key_id": signer.key_id, "op": op,
                                "request_digest": rdigest, "signature": signature.decode("ascii")})
    return client.call(op, params, fds)
