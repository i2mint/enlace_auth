"""Session storage backed by a MutableMapping.

A session is ``{"user_id": str, "email": str | None, "created_at": float}``.
Session IDs are 32-byte urlsafe tokens. Revocation is a simple delete.

Records are otherwise only deleted by logout, so given a *max_age* the store
sweeps records older than it, a bounded batch at a time, whenever a session is
created -- keeping the store (and :meth:`SessionStore.revoke_user`'s scan) from
growing without bound.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import MutableMapping
from itertools import islice
from typing import Any, Optional


class SessionStore:
    """Thin adapter around a MutableMapping that speaks session semantics."""

    def __init__(
        self,
        store: MutableMapping,
        *,
        max_age: Optional[float] = None,
        sweep_batch: int = 100,
    ):
        self._store = store
        self._max_age = max_age
        self._sweep_batch = sweep_batch
        self._sweep_pos = 0

    def sweep_expired(self, *, now: Optional[float] = None) -> int:
        """Delete up to *sweep_batch* records older than *max_age*; return count.

        No-op without a *max_age*. A cursor carries the position across calls
        (wrapping at the end) so successive sweeps walk the whole store. A
        record without a numeric ``created_at`` is left alone.
        """
        if not self._max_age:
            return 0
        now = time.time() if now is None else now
        start = self._sweep_pos
        keys = list(islice(iter(self._store), start, start + self._sweep_batch))
        self._sweep_pos = 0 if len(keys) < self._sweep_batch else start + len(keys)
        removed = 0
        for sid in keys:
            try:
                record = self._store[sid]
            except KeyError:
                continue
            created = record.get("created_at") if isinstance(record, dict) else None
            if isinstance(created, (int, float)) and now - created > self._max_age:
                if self.delete(sid):
                    removed += 1
        return removed

    def create(self, user_id: str, email: Optional[str] = None) -> str:
        try:
            self.sweep_expired()
        except Exception:  # noqa: BLE001 - housekeeping must never block a login
            pass
        session_id = secrets.token_urlsafe(32)
        self._store[session_id] = {
            "user_id": user_id,
            "email": email,
            "created_at": time.time(),
        }
        return session_id

    def get(self, session_id: str) -> Optional[dict[str, Any]]:
        try:
            value = self._store[session_id]
        except KeyError:
            return None
        if not isinstance(value, dict):
            return None
        return value

    def delete(self, session_id: str) -> bool:
        try:
            del self._store[session_id]
            return True
        except KeyError:
            return False

    def revoke_user(self, user: Optional[str], *, keep: Optional[str] = None) -> int:
        """Delete every session belonging to *user*; return how many went.

        A session is matched on its ``user_id`` or its ``email``,
        case-insensitively (emails are the platform's user ids, and a record
        written before lower-casing was consistent must still be caught).
        *keep* names one session id to spare -- the browser that just changed
        its own password stays signed in while every other copy of the
        account is logged out.

        Call this whenever an account's credentials change hands: deletion,
        an admin password reset, a self-service change, a reset-link redemption.
        Without it a session outlives the change for the full cookie lifetime.
        """
        if not user:
            raise ValueError("revoke_user needs a non-empty user id")
        target = user.lower()
        revoked = 0
        for sid, record in self.list_all():
            if sid == keep:
                continue
            ids = (record.get("user_id"), record.get("email"))
            if any(isinstance(i, str) and i.lower() == target for i in ids):
                if self.delete(sid):
                    revoked += 1
        return revoked

    def list_all(self) -> list[tuple[str, dict[str, Any]]]:
        out: list[tuple[str, dict[str, Any]]] = []
        for sid in list(self._store):
            try:
                value = self._store[sid]
            except KeyError:
                continue
            if isinstance(value, dict):
                out.append((sid, value))
        return out
