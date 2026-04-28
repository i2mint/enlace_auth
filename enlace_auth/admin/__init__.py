"""Admin subsystem for enlace_auth.

Exposes ``/_admin/api/*`` endpoints for managing users and viewing app access
policy. Gated by an admin email allowlist supplied at construction time.

The middleware (``PlatformAuthMiddleware``) is what enforces "admin only" — it
sees the ``/_admin`` access rule with ``allowed_users=admin_emails`` and rejects
everyone else. The router itself only needs to enforce the *narrower* "any
authenticated user" gate for self-service endpoints like ``/me/password``.
"""

from enlace_auth.admin.routes import make_admin_router

__all__ = ["make_admin_router"]
