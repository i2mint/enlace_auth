"""Password-reset tokens — minting, verification, and the link they live in.

Single source of truth for the reset-link format, shared by the three callers
that must agree on it byte-for-byte: the self-service
``/auth/password-reset/*`` endpoints, the admin
``POST /_admin/api/users/{email}/reset-link`` endpoint, and the
``enlace-auth reset-link`` CLI.

The token is a *signed* (never encrypted) string carrying three fields::

    <password fingerprint> | <absolute expiry, epoch seconds> | <email>

Two properties fall out of that shape, and neither needs a server-side token
store:

- **Single use.** The fingerprint is a hash of the account's *current* password
  hash. Consuming a link changes the password, which changes the hash, which
  invalidates that token — and every other link outstanding for the account.
- **Per-link lifetime.** The expiry lives *inside* the signed payload rather
  than being applied at verification time, so one verifier serves both the
  short-lived link sent by email and the longer-lived link an admin hands over
  out-of-band (chat, a phone call) when SMTP isn't configured.

The signature covers the expiry, so a longer lifetime cannot be forged. A
second, independent ceiling (:data:`MAX_TTL_SECONDS`) is still applied at the
signature layer, so no token can outlive it even if the embedded expiry is
somehow mis-parsed.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from typing import Any, Optional

from enlace_auth.auth.cookies import sign_cookie, verify_cookie

# Salt namespace for reset tokens — distinct from "session" / "csrf" /
# "shared:*" so a token minted for one purpose can never verify for another.
RESET_SALT = "pwreset"

# Field separator. Safe because the fingerprint is hex, the expiry is digits,
# and an email address cannot contain "|".
_SEP = "|"

#: Lifetime of a link delivered by email — short, because the inbox is a
#: hostile place to leave a credential lying around.
DEFAULT_EMAIL_TTL = 1800  # 30 minutes

#: Lifetime of a link an admin mints and delivers by hand. Longer because the
#: round trip is human: the admin sends it, the recipient reads it later.
DEFAULT_HANDOFF_TTL = 72 * 3600  # 3 days

#: Absolute ceiling on any reset link, enforced at the signature layer as a
#: second bound independent of the expiry inside the payload.
MAX_TTL_SECONDS = 30 * 24 * 3600  # 30 days


def password_fingerprint(record: Mapping[str, Any]) -> str:
    """Return a short, stable fingerprint of a user's current password hash.

    Embedded in reset tokens so a token stops working the moment the password
    changes. That is what makes every link naturally single-use (using it
    changes the hash) and what invalidates outstanding links after any other
    password change.
    """
    raw = str(record.get("password_hash"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def mint_reset_token(
    *,
    record: Mapping[str, Any],
    email: str,
    signing_key: str,
    ttl_seconds: int = DEFAULT_EMAIL_TTL,
) -> str:
    """Return a signed reset token for ``email``, valid for ``ttl_seconds``.

    Args:
        record: the user's stored record (read for its ``password_hash``).
        email: the account the token authorizes a password change for.
        signing_key: platform HMAC key.
        ttl_seconds: how long the link stays usable. Clamped to
            :data:`MAX_TTL_SECONDS`.
    """
    ttl = max(1, min(int(ttl_seconds), MAX_TTL_SECONDS))
    expires_at = int(time.time()) + ttl
    payload = _SEP.join((password_fingerprint(record), str(expires_at), email))
    return sign_cookie(payload, signing_key, salt=RESET_SALT)


def verify_reset_token(
    token: str, *, signing_key: str, user_store
) -> tuple[Optional[str], Optional[dict]]:
    """Return ``(email, record)`` for a valid token, else ``(None, None)``.

    Four independent checks must all pass: the signature, the signature-layer
    age ceiling, the expiry embedded in the payload, and that the password
    fingerprint still matches the stored hash (the single-use property).
    """
    if not token:
        return None, None
    payload = verify_cookie(
        token, signing_key, max_age=MAX_TTL_SECONDS, salt=RESET_SALT
    )
    if not payload:
        return None, None
    parts = payload.split(_SEP, 2)
    if len(parts) != 3:
        return None, None
    fingerprint, expires_raw, email = parts
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return None, None
    if expires_at <= time.time():
        return None, None
    try:
        record = user_store[email]
    except KeyError:
        return None, None
    if not isinstance(record, dict) or password_fingerprint(record) != fingerprint:
        return None, None
    return email, record


def reset_url(base_url: str, token: str) -> str:
    """Return the full ``/auth/reset-password`` link carrying ``token``."""
    from urllib.parse import quote

    return f"{base_url.rstrip('/')}/auth/reset-password?token={quote(token, safe='')}"
