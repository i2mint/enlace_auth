"""Admin HTTP routes: user CRUD, password reset, app policy + grants.

Endpoints (all under ``/_admin/api/``):

- ``GET    /users``                — list registered users
- ``POST   /users``                — create a user (admin-created)
- ``DELETE /users/{email}``        — delete a user (refuses last admin)
- ``POST   /users/{email}/password`` — admin reset another user's password
- ``GET    /apps``                 — list apps with their access policy +
  (for ``protected:user`` apps) their runtime grants
- ``POST   /grants``               — grant a user runtime access to an app
- ``DELETE /grants/{app_id}/{email}`` — revoke a runtime grant

A minimal HTML dashboard is also mounted at ``GET /_admin/`` (and
``/_admin/index.html``); it consumes the JSON endpoints above. The HTML
lives next to this file at ``static/index.html`` and is served via
``importlib.resources`` so it ships in the wheel without any build step.

Self-service ``POST /auth/me/password`` (change own password) lives in
``enlace_auth.auth.routes`` so it's reachable to any authenticated user — it
is NOT under ``/_admin`` because the admin access rule would block non-admins.

Access control:

- ``/_admin/*`` is gated by ``PlatformAuthMiddleware`` via the access rule the
  plugin installs (``allowed_users=admin_emails``). By the time a request
  reaches this router, the caller is an admin.

Runtime grants are ADDITIVE on top of each app's static ``app.toml``
``allowed_users`` and carry an optional UTC expiry — see
``enlace_auth.auth.grants``.
"""

from __future__ import annotations

import time
from collections.abc import Iterable, MutableMapping
from importlib.resources import files
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr

from enlace_auth.auth.grants import GrantError, parse_expires_at
from enlace_auth.auth.passwords import hash_password


class _CreateUserBody(BaseModel):
    email: EmailStr
    password: str


class _ResetPasswordBody(BaseModel):
    password: str


class _CreateGrantBody(BaseModel):
    app_id: str
    email: EmailStr
    # A date ("YYYY-MM-DD", end of day UTC) or full ISO-8601 timestamp; null /
    # omitted means the grant never expires.
    expires_at: Optional[str] = None
    note: Optional[str] = None


def make_admin_router(
    *,
    user_store: MutableMapping,
    session_store,  # SessionStore — kept loose to avoid import cycles
    admin_emails: tuple[str, ...] = (),
    apps: list = (),
    grant_store=None,  # GrantStore — optional; grant endpoints inert without it
    protected_user_apps: Iterable[str] = (),
) -> APIRouter:
    """Build a FastAPI router exposing ``/_admin/api/*`` endpoints.

    ``admin_emails`` is captured by closure so the router can enforce
    last-admin protection on delete. The middleware handles the broader
    "must be an admin to see /_admin" check.

    ``grant_store`` (a :class:`~enlace_auth.auth.grants.GrantStore`) and
    ``protected_user_apps`` enable the runtime grant endpoints. When
    ``grant_store`` is None those endpoints return 503.
    """
    admin_set = frozenset(e.lower() for e in admin_emails)
    apps_snapshot = list(apps)
    app_by_name = {a.name: a for a in apps_snapshot}
    protected_set = frozenset(protected_user_apps)

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
    async def create_user(body: _CreateUserBody, request: Request) -> dict[str, Any]:
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

    def _grants_for(app_id: str, now: float) -> list[dict]:
        if grant_store is None:
            return []
        out = []
        for rec in grant_store.list_for_app(app_id):
            exp = rec.get("expires_at")
            out.append(
                {
                    "email": rec.get("email"),
                    "expires_at": exp,
                    "granted_at": rec.get("granted_at"),
                    "granted_by": rec.get("granted_by"),
                    "note": rec.get("note"),
                    "active": exp is None
                    or (isinstance(exp, (int, float)) and exp > now),
                }
            )
        out.sort(key=lambda g: (g["email"] or ""))
        return out

    @router.get("/apps")
    async def list_apps(request: Request) -> dict[str, Any]:
        _require_admin(request)
        now = time.time()
        items = []
        for app in apps_snapshot:
            allowed_users = list(getattr(app, "allowed_users", []) or [])
            entry = {
                "name": app.name,
                "display_name": getattr(app, "display_name", "") or app.name,
                "access": app.access,
                "allowed_users": allowed_users,
                "route_prefix": app.route_prefix,
            }
            if app.access == "protected:user":
                # An app with an empty baseline allow-list is open to ANY
                # authenticated user; a grant there would have no additive
                # effect (and would unintentionally restrict it), so the UI
                # disables granting on such apps.
                entry["is_open"] = not allowed_users
                entry["grants"] = _grants_for(app.name, now)
            items.append(entry)
        return {"apps": items}

    @router.post("/grants")
    async def create_grant(body: _CreateGrantBody, request: Request) -> dict[str, Any]:
        actor = _require_admin(request)
        if grant_store is None:
            raise HTTPException(status_code=503, detail="Grants store unavailable")
        app_id = body.app_id.strip()
        if app_id not in protected_set:
            raise HTTPException(
                status_code=404,
                detail=f"No protected:user app named {app_id!r}",
            )
        app = app_by_name.get(app_id)
        config_allowed = list(getattr(app, "allowed_users", []) or []) if app else []
        if not config_allowed:
            # Open-app guard: see /apps `is_open` note above.
            raise HTTPException(
                status_code=422,
                detail=(
                    f"App {app_id!r} is open to all authenticated users "
                    "(empty allowed_users): a grant would have no additive effect "
                    "and would unintentionally restrict it. Add a baseline "
                    "allowed_users in its app.toml first."
                ),
            )
        try:
            expires_at = parse_expires_at(body.expires_at)
            record = grant_store.grant(
                app_id,
                body.email,
                expires_at=expires_at,
                granted_by=actor,
                note=body.note,
            )
        except GrantError as e:
            raise HTTPException(status_code=422, detail=str(e))
        return {"ok": True, "grant": record}

    @router.delete("/grants/{app_id}/{email}")
    async def revoke_grant(app_id: str, email: str, request: Request) -> dict[str, Any]:
        _require_admin(request)
        if grant_store is None:
            raise HTTPException(status_code=503, detail="Grants store unavailable")
        if not grant_store.revoke(app_id, email):
            raise HTTPException(status_code=404, detail="Grant not found")
        return {"ok": True, "app_id": app_id, "email": email.lower()}

    return router


def make_admin_ui_router() -> APIRouter:
    """Build a FastAPI router that serves the bundled HTML dashboard.

    Mounted at ``/_admin/``; gated by the same admin access rule as the API,
    so unauthenticated browsers get redirected to login by the auth
    middleware before they ever reach this handler.
    """
    router = APIRouter(prefix="/_admin")

    # Read once at startup — the HTML is small (~5 KB) and never changes
    # at runtime, so caching the string avoids hitting importlib.resources
    # on every request.
    html = (files("enlace_auth.admin") / "static" / "index.html").read_text()

    @router.get("/", response_class=HTMLResponse, include_in_schema=False)
    @router.get("/index.html", response_class=HTMLResponse, include_in_schema=False)
    async def admin_index() -> HTMLResponse:
        return HTMLResponse(html)

    return router
