# SPDX-License-Identifier: GPL-3.0-or-later
"""Per-connection broker state: owner challenges, one-shot grants, passed fds.

A grant is created only by a verified owner assertion (identity/owner.py).
It is bound to this connection, one operation name and the digest of that
operation's exact parameters, and is consumed by the first matching
request or expires. Nothing here outlives the connection: there is no
long-lived "unlocked" state.
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any, Callable, Dict, List, Tuple

CHALLENGE_TTL = 120.0
GRANT_TTL = 120.0
PENDING_TTL = 600.0
MAX_CHALLENGES = 8
MAX_GRANTS = 8
MAX_PENDING = 4


class Session:
    def __init__(self, uid: int, gid: int, pid: int, *, clock: Callable[[], float] = time.monotonic):
        self.uid = uid
        self.gid = gid
        self.pid = pid
        self.clock = clock
        self._challenges: Dict[str, float] = {}
        self._grants: List[Tuple[str, str, float]] = []
        self._pending: Dict[str, Tuple[Any, float]] = {}
        self.fds: List[int] = []

    # -- owner challenges and grants --------------------------------------

    def new_challenge(self) -> str:
        now = self.clock()
        self._challenges = {n: t for n, t in self._challenges.items() if t > now}
        while len(self._challenges) >= MAX_CHALLENGES:
            self._challenges.pop(next(iter(self._challenges)))
        nonce = secrets.token_hex(16)
        self._challenges[nonce] = now + CHALLENGE_TTL
        return nonce

    def take_challenge(self, nonce: str) -> bool:
        expiry = self._challenges.pop(nonce, None)
        return expiry is not None and expiry > self.clock()

    def add_grant(self, op: str, request_digest: str) -> None:
        now = self.clock()
        self._grants = [g for g in self._grants if g[2] > now][-(MAX_GRANTS - 1):]
        self._grants.append((op, request_digest, now + GRANT_TTL))

    def consume_grant(self, op: str, request_digest: str) -> bool:
        now = self.clock()
        for i, (g_op, g_digest, expiry) in enumerate(self._grants):
            if g_op == op and secrets.compare_digest(g_digest, request_digest) and expiry > now:
                del self._grants[i]
                return True
        return False

    # -- pending multi-step operations (transfer prepare -> write) ----------

    def put_pending(self, key: str, value: Any) -> None:
        now = self.clock()
        self._pending = {k: v for k, v in self._pending.items() if v[1] > now}
        while len(self._pending) >= MAX_PENDING:
            self._pending.pop(next(iter(self._pending)))
        self._pending[key] = (value, now + PENDING_TTL)

    def get_pending(self, key: str) -> Any:
        entry = self._pending.get(key)
        if entry is None or entry[1] <= self.clock():
            self._pending.pop(key, None)
            return None
        return entry[0]

    def drop_pending(self, key: str) -> None:
        self._pending.pop(key, None)

    # -- file descriptors received with the current request ---------------

    def take_fds(self) -> List[int]:
        fds, self.fds = self.fds, []
        return fds

    def close_fds(self) -> None:
        for fd in self.take_fds():
            try:
                os.close(fd)
            except OSError:
                pass
