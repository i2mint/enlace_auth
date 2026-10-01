"""Authentication subsystem for enlace.

Apps never import from here. The contract exposed to mounted apps is just
``request.state.user_id`` and (optionally) ``request.state.user_email``.

Public helpers:

- ``PlatformAuthMiddleware`` — pure-ASGI auth middleware.
- ``CSRFMiddleware`` — signed double-submit CSRF.
- ``SessionStore`` — MutableMapping-backed session storage.
- ``GrantStore`` — MutableMapping-backed runtime per-app access grants.
- ``ShareStore`` — owner-granted data shares (who may act on whose per-user data).
- ``hash_password`` / ``verify_password`` — argon2id helpers.
- ``make_auth_router`` — FastAPI router for ``/auth/*`` endpoints.
"""

from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.grants import GrantStore, parse_expires_at
from enlace_auth.auth.middleware import (
    AccessRule,
    CSRFMiddleware,
    PlatformAuthMiddleware,
)
from enlace_auth.auth.passwords import hash_password, verify_password
from enlace_auth.auth.routes import make_auth_router
from enlace_auth.auth.sessions import SessionStore
from enlace_auth.auth.shares import ShareError, ShareStore

__all__ = [
    "AccessRule",
    "CSRFMiddleware",
    "GrantStore",
    "PlatformAuthMiddleware",
    "SessionStore",
    "ShareError",
    "ShareStore",
    "hash_password",
    "make_auth_router",
    "parse_expires_at",
    "sign_cookie",
    "verify_cookie",
    "verify_password",
]
