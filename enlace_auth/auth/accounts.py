"""Disabled accounts, and the one way a sign-in opens a session.

A user record is a plain dict in the user store. ``disabled_at`` (epoch
seconds) marks an account that exists, keeps its grants, shares and history,
but cannot sign in by any path; its connector grants are refused too (see
``enlace_auth.plugin._make_is_active``). Disabling also ends its sessions;
re-enabling only removes the key.

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
from collections.abc import MutableMapping
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


def set_disabled(
    user_store: MutableMapping, email: str, disabled: bool, *, now: float | None = None
) -> dict:
    """Mark *email*'s record disabled (or not); return the new record.

    Raises ``KeyError`` when there is no such account.

    >>> s = {"a@x.io": {"created_at": 0}}
    >>> is_disabled(set_disabled(s, "a@x.io", True, now=5))
    True
    >>> is_disabled(set_disabled(s, "a@x.io", False))
    False
    """
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
