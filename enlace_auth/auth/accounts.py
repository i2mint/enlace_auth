"""Account state kept on the user record: disabled, and last sign-in.

A user record is a plain dict in the user store. Two optional keys live there:

- ``disabled_at`` (epoch seconds): the account exists, keeps its grants, shares
  and history, but cannot sign in by any path, and its connector refresh
  families are refused (see ``enlace_auth.plugin._make_is_active``). Disabling
  also ends its sessions; re-enabling only removes the key.
- ``last_login_at`` (epoch seconds): written each time a session is opened for
  the account. Best effort: a store failure here never fails a sign-in.
"""

from __future__ import annotations

import logging
import time
from collections.abc import MutableMapping
from typing import Any, Optional

DISABLED_KEY = "disabled_at"
LAST_LOGIN_KEY = "last_login_at"
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
    user_store: MutableMapping, email: str, disabled: bool, *, now: float = None
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


def note_sign_in(
    user_store: MutableMapping, email: str, *, now: Optional[float] = None
) -> None:
    """Record that a session was just opened for *email*. Never raises.

    Re-reads the record so a concurrent password change is not overwritten
    with an older copy.

    >>> s = {"a@x.io": {"created_at": 0}}
    >>> note_sign_in(s, "a@x.io", now=7); s["a@x.io"]["last_login_at"]
    7
    >>> note_sign_in({}, "nobody@x.io")  # no account: nothing happens
    """
    try:
        record = user_store.get(email)
        if not isinstance(record, dict):
            return
        user_store[email] = {
            **record,
            LAST_LOGIN_KEY: time.time() if now is None else now,
        }
    except Exception:  # noqa: BLE001 - a sign-in must not fail on bookkeeping
        _logger.warning("enlace_auth: could not record last sign-in for %r", email)
