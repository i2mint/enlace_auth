"""Disabled accounts, and the one way a sign-in opens a session.

A user record is a plain dict in the user store. ``disabled_at`` (epoch
seconds) marks an account that exists, keeps its grants, shares and history,
but cannot sign in by any path; its connector grants are refused too (see
``enlace_auth.plugin._make_is_active``). Disabling also ends its sessions;
re-enabling only removes the mark.

The platform keeps that mark in its own mapping, not in the stored record
(:class:`AccountRecords`, #71): several paths rewrite a whole record from a copy
read moments earlier (password change, reset, OAuth subject binding), and the
file store has no compare-and-set, so a mark inside the record could be undone
by any of them. Reads still show ``disabled_at`` on the record, so every
``is_disabled(record)`` check is unchanged; only :func:`set_disabled` writes it.

Every sign-in path opens its session through :func:`open_session`, which
re-checks the record after creating the session, so a sign-in racing an admin's
disable cannot keep a session the revocation already missed.

The last sign-in time is NOT kept on the user record (a read-modify-write there
at every login could overwrite a concurrent disable); ``SessionStore`` records
it in its own mapping (``sign_ins``).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any

DISABLED_KEY = "disabled_at"
#: What a disabled account is told when it tries to sign in.
DISABLED_DETAIL = "This account is disabled. Contact the platform admin."

_logger = logging.getLogger("enlace_auth")


def is_disabled(record: Any) -> bool:
    """True when *record* is a user record marked disabled.

    >>> is_disabled({"disabled_at": 1.0}), is_disabled({}), is_disabled(None)
    (True, False, False)
    """
    return isinstance(record, dict) and record.get(DISABLED_KEY) is not None


def _without_mark(record: dict) -> dict:
    return {k: v for k, v in record.items() if k != DISABLED_KEY}


class AccountRecords(MutableMapping):
    """User records whose disabled mark lives in its own mapping.

    Reading a record adds ``disabled_at`` from *disabled*; writing one drops
    that key, so a path that rewrites a record from a copy read before an
    admin's disable cannot undo it. Only :meth:`set_disabled` writes
    *disabled*, one key at a time, with no read-modify-write.

    >>> users = AccountRecords({"a@x.io": {"password_hash": "old"}}, {})
    >>> copy = users["a@x.io"]                   # a password change reads...
    >>> _ = users.set_disabled("a@x.io", True, now=5)  # ...an admin disables...
    >>> users["a@x.io"] = {**copy, "password_hash": "new"}  # ...it writes back
    >>> is_disabled(users["a@x.io"]), users["a@x.io"]["password_hash"]
    (True, 'new')

    A record written before this split (#70) may still carry the key itself; it
    stays disabled (rewrites keep it) until :meth:`set_disabled` enables it.
    """

    def __init__(self, users: MutableMapping, disabled: MutableMapping):
        self.users = users
        self.disabled = disabled

    def __getitem__(self, email: str) -> Any:
        record = self.users[email]
        at = self.disabled.get(email)
        if at is None or not isinstance(record, dict):
            return record
        return {**record, DISABLED_KEY: at}

    def __setitem__(self, email: str, record: Any) -> None:
        if isinstance(record, dict):
            record = _without_mark(record)
            stored = self.users.get(email)
            if is_disabled(stored):  # a pre-split mark: only an enable clears it
                record[DISABLED_KEY] = stored[DISABLED_KEY]
        self.users[email] = record

    def __delitem__(self, email: str) -> None:
        del self.users[email]
        self.disabled.pop(email, None)

    def __iter__(self) -> Iterator[str]:
        return iter(self.users)

    def __len__(self) -> int:
        return len(self.users)

    def __contains__(self, email: object) -> bool:
        return email in self.users

    def set_disabled(
        self, email: str, disabled: bool, *, now: float | None = None
    ) -> dict:
        """Mark *email* disabled (or not); return its record as now read.

        Raises ``KeyError`` when there is no such account.
        """
        record = self.users[email]
        if disabled:
            self.disabled[email] = time.time() if now is None else now
        else:
            self.disabled.pop(email, None)
            if is_disabled(record):  # clear a pre-split mark too
                self.users[email] = _without_mark(record)
        return self[email]


def make_account_records(
    store_factory: Callable[[str], MutableMapping],
) -> AccountRecords:
    """The platform's user records: ``users`` plus the ``disabled_accounts`` marks.

    >>> stores = {}
    >>> records = make_account_records(lambda name: stores.setdefault(name, {}))
    >>> sorted(stores)
    ['disabled_accounts', 'users']
    """
    return AccountRecords(store_factory("users"), store_factory("disabled_accounts"))


def set_disabled(
    user_store: MutableMapping, email: str, disabled: bool, *, now: float | None = None
) -> dict:
    """Mark *email*'s record disabled (or not); return the new record.

    Raises ``KeyError`` when there is no such account. On
    :class:`AccountRecords` (the platform's store) the mark is written apart
    from the record; on a plain mapping it is written into the record.

    >>> s = {"a@x.io": {"created_at": 0}}
    >>> is_disabled(set_disabled(s, "a@x.io", True, now=5))
    True
    >>> is_disabled(set_disabled(s, "a@x.io", False))
    False
    """
    if isinstance(user_store, AccountRecords):
        return user_store.set_disabled(email, disabled, now=now)
    record = user_store[email]
    record = dict(record) if isinstance(record, dict) else {}
    if disabled:
        record[DISABLED_KEY] = time.time() if now is None else now
    else:
        record.pop(DISABLED_KEY, None)
    user_store[email] = record
    return record


def open_session(session_store, user_store: MutableMapping, email: str) -> str:
    """Create a session for *email* and return its id, unless it is disabled.

    The disabled check runs AFTER the session exists: if an admin disabled the
    account (and revoked its sessions) while this sign-in was in flight, the
    new session is deleted here and the sign-in refused. Raises
    ``fastapi.HTTPException(403)`` in that case.
    """
    from fastapi import HTTPException

    session_id = session_store.create(user_id=email, email=email)
    try:
        disabled = is_disabled(user_store.get(email))
    except Exception:  # noqa: BLE001 - an unreadable store must not refuse a login
        _logger.warning("enlace_auth: user store unreadable re-checking %r", email)
        disabled = False
    if disabled:
        session_store.delete(session_id)
        raise HTTPException(status_code=403, detail=DISABLED_DETAIL)
    return session_id
