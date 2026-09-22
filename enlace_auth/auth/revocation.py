"""Credential revocation: end everything an account holds when its credentials change.

An account's access outlives a password change in three places, each with its own
lifetime: browser **sessions** (``session_max_age``), OAuth connector
**refresh-token families** (``refresh_family_max_lifetime``), and the per-app
**shared-password cookies** (which are not per account at all -- see
:func:`shared_password_fingerprint`). This module is the one place that knows how
to end the first two, so every path that changes an account's credentials
(admin delete, admin password set, self-service change, reset-link redemption,
the ``set-password`` CLI) calls a single :func:`make_on_credentials_changed` hook
instead of each remembering its own list.

Kept free of FastAPI/Authlib imports so the CLI can use it without the
``[oauth]`` extra.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections.abc import MutableMapping
from typing import Any, Optional, Protocol

_logger = logging.getLogger("enlace_auth")

__all__ = [
    "CredentialsChanged",
    "make_on_credentials_changed",
    "refresh_tombstone_ttl",
    "revoke_refresh_family",
    "revoke_refresh_subject",
    "revoked_family_key",
    "subject_marker_key",
    "subject_revoked_before",
    "shared_cookie_valid",
    "shared_password_fingerprint",
]


class CredentialsChanged(Protocol):
    """``on_credentials_changed(email, *, keep=None) -> None``.

    *keep* names one browser session id to spare (the browser that just changed
    its own password stays signed in).
    """

    def __call__(self, email: str, *, keep: Optional[str] = None) -> None: ...


def revoked_family_key(family: str) -> str:
    """Store key of the tombstone that marks a whole refresh family revoked."""
    return f"family:{family}"


def subject_marker_key(email: str) -> str:
    """Store key of the marker that says "nothing *email* authorized before T"."""
    digest = hashlib.sha256(email.lower().encode()).hexdigest()
    return f"subject:{digest}"


def subject_revoked_before(
    refresh_store: Optional[MutableMapping[str, Any]], email: Optional[str]
) -> Optional[int]:
    """The time before which every authorization by *email* is revoked, if any.

    A scan-and-delete revocation cannot see a family that another worker is
    creating at that very moment (its code already consumed, its first refresh
    record not yet written), nor a code issued from a session read just before
    the change. The marker closes both: the code grant refuses codes issued at
    or before it, and the refresh grant refuses families authorized at or
    before it.
    """
    if refresh_store is None or not email:
        return None
    try:
        record = refresh_store.get(subject_marker_key(email))
    except Exception:  # noqa: BLE001 - an unreadable marker is no marker
        return None
    value = (record or {}).get("revoked_before") if isinstance(record, dict) else None
    return value if isinstance(value, (int, float)) else None


def refresh_tombstone_ttl(
    *, refresh_token_ttl: int, refresh_reuse_detection: int
) -> int:
    """How long a family tombstone must live: past every token of the family."""
    return max(refresh_token_ttl, refresh_reuse_detection)


def revoke_refresh_family(
    refresh_store: MutableMapping[str, Any],
    family: str,
    *,
    reason: str,
    tombstone_ttl: int,
    now: Optional[int] = None,
) -> int:
    """Revoke one refresh-token family; return how many token records went.

    The tombstone is written FIRST: revocation expressed only as the absence of
    records loses to a worker concurrently rotating the family (its successor is
    written after our scan). A positive marker cannot be raced -- the refresh
    grant refuses any record whose family carries one.
    """
    now = int(time.time()) if now is None else now
    refresh_store[revoked_family_key(family)] = {
        "revoked_at": now,
        "reason": reason,
        "exp": now + tombstone_ttl,
    }
    revoked = 0
    for key in list(refresh_store):
        try:
            record = refresh_store[key]
        except KeyError:
            continue
        if (record or {}).get("family") != family:
            continue  # (the marker itself carries no "family" key)
        try:
            del refresh_store[key]
            revoked += 1
        except KeyError:
            pass
    _logger.warning(
        "oauth: revoked refresh family %s (%d token(s)) — %s. The connector "
        "using it is now dead until a human re-authorizes it.",
        family,
        revoked,
        reason,
    )
    return revoked


def revoke_refresh_subject(
    refresh_store: MutableMapping[str, Any],
    email: str,
    *,
    reason: str,
    tombstone_ttl: int,
    code_store: Optional[MutableMapping[str, Any]] = None,
    marker_ttl: int = 0,
    now: Optional[int] = None,
) -> int:
    """Revoke every refresh family issued to *email*; return how many families.

    Matches the subject case-insensitively. First writes a subject marker (see
    :func:`subject_revoked_before`) that lives *marker_ttl* seconds -- give it
    the family max lifetime -- so authorizations racing this call are refused
    too. Then tombstones each existing family and drops the subject's
    unredeemed authorization codes from *code_store* when given. Access JWTs
    already issued are self-contained and live out their (short) TTL.
    """
    if not email:
        raise ValueError("revoke_refresh_subject needs a non-empty email")
    target = email.lower()
    now = int(time.time()) if now is None else now
    refresh_store[subject_marker_key(target)] = {
        "revoked_before": now,
        "reason": reason,
        "exp": now + max(marker_ttl, tombstone_ttl),
    }

    def _is_subjects(record: Any) -> bool:
        subject = (record or {}).get("email") if isinstance(record, dict) else None
        return isinstance(subject, str) and subject.lower() == target

    families: set[str] = set()
    for key in list(refresh_store):
        try:
            record = refresh_store[key]
        except KeyError:
            continue
        if _is_subjects(record) and record.get("family"):
            families.add(record["family"])
    for family in sorted(families):
        revoke_refresh_family(
            refresh_store, family, reason=reason, tombstone_ttl=tombstone_ttl, now=now
        )
    if code_store is not None:
        for key in list(code_store):
            try:
                record = code_store[key]
            except KeyError:
                continue
            if _is_subjects(record):
                try:
                    del code_store[key]
                except KeyError:
                    pass
    return len(families)


def make_on_credentials_changed(
    session_store,
    *,
    refresh_store: Optional[MutableMapping[str, Any]] = None,
    code_store: Optional[MutableMapping[str, Any]] = None,
    tombstone_ttl: int = 0,
    marker_ttl: int = 0,
    reason: str = "the account's credentials changed",
) -> CredentialsChanged:
    """Return the hook every credential-changing path calls.

    Always revokes the account's browser sessions (sparing *keep*); when a
    *refresh_store* is given, also revokes the account's connector refresh
    families (and unredeemed codes in *code_store*). A failure to revoke
    connector families is logged loudly but does not undo the password change,
    which has already been written by the caller.
    """
    if refresh_store is not None and tombstone_ttl <= 0:
        raise ValueError("tombstone_ttl must be positive when refresh_store is given")

    def on_credentials_changed(email: str, *, keep: Optional[str] = None) -> None:
        # Connector revocation runs even if the session revocation fails, and
        # vice versa; a session-store failure still surfaces to the caller.
        try:
            session_store.revoke_user(email, keep=keep)
        finally:
            if refresh_store is not None:
                try:
                    revoke_refresh_subject(
                        refresh_store,
                        email,
                        reason=reason,
                        tombstone_ttl=tombstone_ttl,
                        marker_ttl=marker_ttl,
                        code_store=code_store,
                    )
                except Exception:  # noqa: BLE001 - say so loudly, don't mask
                    _logger.exception(
                        "enlace_auth: could not revoke connector sessions for %r "
                        "after a credential change; revoke them with "
                        "`enlace-auth revoke-connector-session --email`",
                        email,
                    )

    return on_credentials_changed


def shared_password_fingerprint(password_hash: str, signing_key: str) -> str:
    """A short keyed fingerprint of an app's CURRENT shared-password hash.

    Signed into the ``shared_auth_<app>`` cookie and compared by the middleware,
    so rotating the shared password invalidates every cookie minted under the
    old one. Keyed with *signing_key* so the cookie (whose payload is readable,
    only signed) reveals nothing about the hash.
    """
    digest = hmac.new(
        signing_key.encode(), f"shared-pw:{password_hash}".encode(), hashlib.sha256
    )
    return digest.hexdigest()[:32]


def shared_cookie_valid(
    value: Optional[str], password_hash: Optional[str], signing_key: str
) -> bool:
    """True iff a verified shared-cookie *value* was minted under *password_hash*."""
    if not value or not password_hash:
        return False
    expected = shared_password_fingerprint(password_hash, signing_key)
    return hmac.compare_digest(str(value), expected)
