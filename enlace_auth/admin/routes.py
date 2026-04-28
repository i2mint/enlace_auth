"""Admin HTTP routes: user CRUD, password reset, app policy view.

Endpoints (all under ``/_admin/api/``):

- ``GET    /users``                — list registered users
- ``POST   /users``                — create a user (admin-created)
- ``DELETE /users/{email}``        — delete a user (refuses last admin)
- ``POST   /users/{email}/password`` — admin reset another user's password
- ``GET    /apps``                 — list apps with their access policy

Self-service ``POST /auth/me/password`` (change own password) lives in
``enlace_auth.auth.routes`` so it's reachable to any authenticated user — it
is NOT under ``/_admin`` because the admin access rule would block non-admins.

Access control:

- ``/_admin/*`` is gated by ``PlatformAuthMiddleware`` via the access rule the
  plugin installs (``allowed_users=admin_emails``). By the time a request
  reaches this router, the caller is an admin.
"""

from __future__ import annotations

import time
from collections.abc import MutableMapping
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr

from enlace_auth.auth.passwords import hash_password


class _CreateUserBody(BaseModel):
    email: EmailStr
    password: str


class _ResetPasswordBody(BaseModel):
    password: str


def make_admin_router(
    *,
    user_store: MutableMapping,
    session_store,  # SessionStore — kept loose to avoid import cycles
    admin_emails: tuple[str, ...] = (),
    apps: list = (),
) -> APIRouter:
    """Build a FastAPI router exposing ``/_admin/api/*`` endpoints.

    ``admin_emails`` is captured by closure so the router can enforce
    last-admin protection on delete. The middleware handles the broader
    "must be an admin to see /_admin" check.
    """
    admin_set = frozenset(e.lower() for e in admin_emails)
    apps_snapshot = list(apps)

    router = APIRouter(prefix="/_admin/api")

    def _require_admin(request: Request) -> str:
        email = getattr(request.state, "user_email", None) or ""
        if email.lower() not in admin_set:
            # Defense in depth — the middleware should have already blocked
            # this, but a misconfigured access rule shouldn't expose admin.
            raise HTTPException(status_code=403, detail="Admin only")
        return email.lower()

    @router.get("/users")
    async def list_users(request: Request) -> dict[str, Any]:
        _require_admin(request)
        items = []
        for email in list(user_store):
            try:
                record = user_store[email]
            except KeyError:
                continue
            if not isinstance(record, dict):
                continue
            items.append(
                {
                    "email": email,
                    "created_at": record.get("created_at"),
                    "is_admin": email.lower() in admin_set,
                }
            )
        return {"users": items}

    @router.post("/users")
    async def create_user(
        body: _CreateUserBody, request: Request
    ) -> dict[str, Any]:
        _require_admin(request)
        email = body.email.lower()
        if email in user_store:
            raise HTTPException(status_code=409, detail="Email already registered")
        user_store[email] = {
            "password_hash": hash_password(body.password),
            "created_at": time.time(),
        }
        return {"ok": True, "email": email}

    @router.delete("/users/{email}")
    async def delete_user(email: str, request: Request) -> dict[str, Any]:
        actor = _require_admin(request)
        target = email.lower()
        # Last-admin protection: can't delete the only admin user that
        # actually exists in the user store.
        if target in admin_set:
            existing_admins = [e for e in user_store if e.lower() in admin_set]
            existing_lower = {e.lower() for e in existing_admins}
            if len(existing_admins) <= 1 and target in existing_lower:
                raise HTTPException(
                    status_code=409,
                    detail="Cannot delete the last admin user",
                )
        try:
            del user_store[target]
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found")
        # Defensive: actor deleting themselves still returns ok, but their
        # session will fail on next request. Clients should refresh.
        _ = actor
        return {"ok": True, "email": target}

    @router.post("/users/{email}/password")
    async def admin_reset_password(
        email: str, body: _ResetPasswordBody, request: Request
    ) -> dict[str, Any]:
        _require_admin(request)
        target = email.lower()
        try:
            record = user_store[target]
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found")
        if not isinstance(record, dict):
            raise HTTPException(status_code=500, detail="Corrupt user record")
        record = dict(record)
        record["password_hash"] = hash_password(body.password)
        user_store[target] = record
        return {"ok": True, "email": target}

    @router.get("/apps")
    async def list_apps(request: Request) -> dict[str, Any]:
        _require_admin(request)
        items = []
        for app in apps_snapshot:
            items.append(
                {
                    "name": app.name,
                    "display_name": getattr(app, "display_name", "") or app.name,
                    "access": app.access,
                    "allowed_users": list(getattr(app, "allowed_users", [])),
                    "route_prefix": app.route_prefix,
                }
            )
        return {"apps": items}

    return router
