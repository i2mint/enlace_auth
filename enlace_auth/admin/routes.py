"""Admin HTTP routes: user CRUD, password reset, app policy + grants.

Endpoints (all under ``/_admin/api/``):

- ``GET    /users``                — list registered users
- ``POST   /users``                — create a user (admin-created)
- ``DELETE /users/{email}``        — delete a user (refuses last admin)
- ``POST   /users/{email}/password`` — admin reset another user's password
- ``POST   /users/{email}/reset-link`` — mint a one-time link the user follows
  to choose their *own* password. Preferred over the endpoint above: the admin
  never learns, transmits, or has to invent a credential. It is also the only
  recovery path that works when no SMTP sender is configured, since the admin
  delivers the link by hand.
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
from collections.abc import Iterable, Mapping, MutableMapping
from importlib.resources import files
from typing import Annotated, Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, BeforeValidator, EmailStr

from enlace_auth.auth.accounts import (
    DISABLED_KEY,
    LAST_LOGIN_KEY,
    set_disabled,
)
from enlace_auth.auth.grants import GrantError, parse_expires_at
from enlace_auth.auth.passwords import hash_password, password_problem
from enlace_auth.auth.reset_tokens import (
    DEFAULT_HANDOFF_TTL,
    mint_reset_token,
    reset_url,
)
from enlace_auth.auth.shares import ShareError
from enlace_auth.emails import local_part_problem, normalize_email, resolve_account
from enlace_auth.resource_policy import ANY_ACCOUNT, parse_resource_allowlist


def _refuse_decomposed(value):
    """Refuse a local part ``EmailStr`` would NFC-compose onto another key (#51)."""
    if isinstance(value, str) and (problem := local_part_problem(value.strip())):
        raise ValueError(problem)
    return value


#: An address an admin names for a grant or share: ``EmailStr``, minus its fold.
_NamedAddress = Annotated[EmailStr, BeforeValidator(_refuse_decomposed)]


class _CreateUserBody(BaseModel):
    # Keyed with normalize_email in the handler, which refuses a decomposed
    # local part rather than composing it onto another mailbox's key (#51).
    email: str
    password: str


class _ResetPasswordBody(BaseModel):
    password: str


class _CreateShareBody(BaseModel):
    app_id: str
    owner: _NamedAddress
    grantee: _NamedAddress
    access: str = "rw"
    label: Optional[str] = None
    expires_at: Optional[str] = None


class _CreateGrantBody(BaseModel):
    app_id: str
    email: _NamedAddress
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
    share_store=None,  # ShareStore — optional; share endpoints inert without it
    store_apps: Iterable[str] = (),
    signing_key: Optional[str] = None,
    reset_link_ttl: int = DEFAULT_HANDOFF_TTL,
    resource_allowlist: Optional[Mapping[str, list[str]]] = None,
    oauth_server_enabled: bool = False,
    public_base_url: Optional[str] = None,
    on_credentials_changed=None,  # CredentialsChanged; default: sessions only
) -> APIRouter:
    """Build a FastAPI router exposing ``/_admin/api/*`` endpoints.

    ``admin_emails`` is captured by closure so the router can enforce
    last-admin protection on delete. The middleware handles the broader
    "must be an admin to see /_admin" check.

    ``grant_store`` (a :class:`~enlace_auth.auth.grants.GrantStore`) and
    ``protected_user_apps`` enable the runtime grant endpoints. When
    ``grant_store`` is None those endpoints return 503.

    ``signing_key`` enables the reset-link endpoint (same key the auth router
    signs with, so the link it mints verifies there). Omit it and that endpoint
    returns 503, mirroring how ``grant_store`` gates the grant endpoints.
    ``public_base_url`` is the platform's public origin for minted reset links
    (falls back to the request origin).

    ``reset_link_ttl`` is how long a minted link stays usable — longer than an
    emailed one, because delivery is a human round trip.

    ``resource_allowlist`` is the OAuth server's per-connector allow-list (see
    ``enlace_auth.auth.oauth_server``). It exists here purely so ``/apps`` can
    tell the truth about connectors: an OAuth resource server is declared
    ``access = "public"`` because enlace must NOT gate it at the session layer
    — it authenticates its own bearer tokens instead. Reporting that as a bare
    "public" badge invites the reader to conclude private data is world-open
    (it isn't) or, worse, to make some *other* app public by analogy (which
    would be). Passing the allow-list lets the dashboard show who can actually
    reach each one. ``oauth_server_enabled`` lets it also say what happens to a
    resource that is NOT listed: refused to everyone while an allowlist is set,
    open to every account when the server runs without one.

    ``on_credentials_changed`` (``hook(email, *, keep=None)``) runs after a
    user is deleted or has their password set. The default revokes the
    account's browser sessions; the plugin injects one that also revokes its
    OAuth connector refresh families (``enlace_auth.auth.revocation``).
    """
    from enlace_auth.auth.revocation import make_on_credentials_changed

    credentials_changed = on_credentials_changed or make_on_credentials_changed(
        session_store
    )
    admin_set = frozenset(e.lower() for e in admin_emails)
    apps_snapshot = list(apps)
    app_by_name = {a.name: a for a in apps_snapshot}
    protected_set = frozenset(protected_user_apps)
    store_set = frozenset(store_apps)

    def _oauth_gates(
        allowlist: Mapping[str, frozenset[str]],
    ) -> tuple[dict[str, list[dict]], list[dict]]:
        """Index the OAuth resource allow-list by the app route it belongs to.

        A resource URL (``https://host/api/snout_mcp/mcp``) is matched to an app
        by its path prefix, so one connector app can own several resources.
        Returns ``(by_prefix, unmatched)``: the entries no app here serves (a
        stale or misspelled key, or a connector on another host) are returned
        separately, so an operator sees them rather than losing them.
        """
        from urllib.parse import urlparse

        by_prefix: dict[str, list[dict]] = {}
        unmatched: list[dict] = []
        # Longest prefix first, as enlace routes (/api/foo wins over /api):
        # first-match would hang a nested connector's entry on its parent's row.
        by_length = sorted(
            apps_snapshot,
            key=lambda a: len(getattr(a, "route_prefix", "") or ""),
            reverse=True,
        )
        base = urlparse(public_base_url or "")
        own_origin = (base.scheme, base.netloc) if base.netloc else None
        for resource, emails in allowlist.items():
            parsed = urlparse(resource)
            path = parsed.path or resource
            gate = {
                "resource": resource,
                # Parsed here, where a malformed value degrades to the raw
                # string. Doing it in the browser means one bad config key
                # throws and blanks the whole table.
                "path": path,
                "any_account": ANY_ACCOUNT in emails,
                "allowed_users": sorted(emails - {ANY_ACCOUNT}),
            }
            if own_origin and (parsed.scheme, parsed.netloc) != own_origin:
                unmatched.append(gate)  # another host: no app here serves it
                continue
            for app in by_length:
                prefix = (getattr(app, "route_prefix", "") or "").rstrip("/")
                # Segment-aware: /api/x_mcp must not claim /api/x_mcp_beta.
                if prefix and (path == prefix or path.startswith(prefix + "/")):
                    by_prefix.setdefault(app.route_prefix, []).append(gate)
                    break
            else:
                unmatched.append(gate)  # no app serves it
        return by_prefix, unmatched

    # Already validated when the config loaded; parsed again so a direct caller
    # gets the same shape (and the same refusal of a malformed one).
    _allowlist = parse_resource_allowlist(
        resource_allowlist, allow_unlisted_resources=not resource_allowlist
    )
    oauth_gates, unmatched = _oauth_gates(_allowlist)
    oauth_policy = {
        "enabled": bool(oauth_server_enabled),
        # What a resource that is not in the allowlist gets.
        "unlisted": (
            "n/a"
            if not oauth_server_enabled
            else "refused"
            if _allowlist
            else "open to every account"
        ),
        "unmatched_resources": unmatched,
    }

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
                    "last_login_at": record.get(LAST_LOGIN_KEY),
                    "disabled_at": record.get(DISABLED_KEY),
                    "is_admin": email.lower() in admin_set,
                }
            )
        return {"users": items}

    @router.post("/users")
    async def create_user(body: _CreateUserBody, request: Request) -> dict[str, Any]:
        _require_admin(request)
        try:
            email = normalize_email(body.email)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
        if email in user_store:
            raise HTTPException(status_code=409, detail="Email already registered")
        if problem := password_problem(body.password):
            raise HTTPException(status_code=400, detail=problem)
        user_store[email] = {
            "password_hash": hash_password(body.password),
            "created_at": time.time(),
            "created_via": "admin",
        }
        return {"ok": True, "email": email}

    def _account_key(email: str) -> str:
        """The key of the account a path's *email* names, in either spelling.

        A punycode domain and its Unicode form are one mailbox; the admin may
        type either, while the account is keyed in the one that made it. An
        exact match wins. Falls back to the lowercased path (then a 404).
        """
        return resolve_account(email, user_store.__contains__) or email.lower()

    @router.delete("/users/{email}")
    async def delete_user(email: str, request: Request) -> dict[str, Any]:
        actor = _require_admin(request)
        target = _account_key(email)
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
        # Sessions are not checked against the user store on each request, so
        # a deleted account keeps working until its cookie expires unless its
        # sessions go too. (An actor deleting themselves is logged out.) This
        # comes before the share cleanup so a failure there cannot leave a
        # deleted account signed in.
        _ = actor
        credentials_changed(target)
        # A share never outlives an account it names (ADR 0001 §2): the email is
        # free to be registered again by someone else.
        if share_store is not None:
            share_store.remove_account(target)
        return {"ok": True, "email": target}

    def _existing_account(email: str) -> str:
        target = _account_key(email)
        if target not in user_store:
            raise HTTPException(status_code=404, detail="User not found")
        return target

    @router.post("/users/{email}/sign-out")
    async def sign_out_everywhere(email: str, request: Request) -> dict[str, Any]:
        """End every session and connector refresh family the account holds.

        The account and its password are untouched; it can sign in again.
        """
        _require_admin(request)
        target = _existing_account(email)
        credentials_changed(target)
        return {"ok": True, "email": target}

    @router.post("/users/{email}/disable")
    async def disable_user(email: str, request: Request) -> dict[str, Any]:
        """Block sign-in by every path and end the account's sessions.

        Grants, shares and data are kept, so re-enabling restores the account
        as it was. An admin cannot disable themselves (no lock-out by mistake).
        """
        actor = _require_admin(request)
        target = _existing_account(email)
        if target.lower() == actor:
            raise HTTPException(
                status_code=409, detail="You cannot disable your own account"
            )
        try:
            set_disabled(user_store, target, True)
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found") from None
        # Marked before revoking, so a sign-in that starts after this point is
        # refused, and connector refreshes are refused from now on (is_active).
        credentials_changed(target)
        return {"ok": True, "email": target, "disabled": True}

    @router.post("/users/{email}/enable")
    async def enable_user(email: str, request: Request) -> dict[str, Any]:
        _require_admin(request)
        target = _existing_account(email)
        try:
            set_disabled(user_store, target, False)
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found") from None
        return {"ok": True, "email": target, "disabled": False}

    @router.post("/users/{email}/password")
    async def admin_reset_password(
        email: str, body: _ResetPasswordBody, request: Request
    ) -> dict[str, Any]:
        _require_admin(request)
        target = _account_key(email)
        try:
            record = user_store[target]
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found")
        if not isinstance(record, dict):
            raise HTTPException(status_code=500, detail="Corrupt user record")
        if problem := password_problem(body.password):
            raise HTTPException(status_code=400, detail=problem)
        record = dict(record)
        record["password_hash"] = hash_password(body.password)
        # A reset is account recovery: external sign-ins linked to the account
        # are unlinked too, or whoever linked one walks straight back in.
        record.pop("oauth_links", None)
        user_store[target] = record
        # An admin reset is how a compromised account is recovered: whoever
        # holds a session opened with the old password must lose it.
        credentials_changed(target)
        return {"ok": True, "email": target}

    @router.post("/users/{email}/reset-link")
    async def admin_reset_link(email: str, request: Request) -> dict[str, Any]:
        """Mint a one-time link letting ``email`` choose their own password.

        Returned to the admin to deliver out-of-band. Nothing is stored: the
        link is a signed token bound to the account's *current* password hash,
        so it expires on use, and any other password change kills it too.
        """
        _require_admin(request)
        if not signing_key:
            raise HTTPException(
                status_code=503,
                detail="Reset links unavailable: no signing key configured.",
            )
        target = _account_key(email)
        try:
            record = user_store[target]
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found")
        if not isinstance(record, dict):
            raise HTTPException(status_code=500, detail="Corrupt user record")
        token = mint_reset_token(
            record=record,
            email=target,
            signing_key=signing_key,
            ttl_seconds=reset_link_ttl,
        )
        return {
            "ok": True,
            "email": target,
            "url": reset_url(public_base_url or str(request.base_url), token),
            "expires_in_seconds": reset_link_ttl,
        }

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
        out.sort(key=lambda g: g["email"] or "")
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
            # A connector is access="public" *because* it does its own bearer
            # auth — say so, rather than leaving a bare "public" to be misread
            # as "world-readable".
            gates = oauth_gates.get(app.route_prefix)
            if gates:
                entry["oauth_resources"] = gates
            if app.access == "protected:user":
                # An app with an empty baseline allow-list is open to ANY
                # authenticated user; a grant there would have no additive
                # effect (and would unintentionally restrict it), so the UI
                # disables granting on such apps.
                entry["is_open"] = not allowed_users
                entry["grants"] = _grants_for(app.name, now)
            items.append(entry)
        return {"apps": items, "oauth_policy": oauth_policy}

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

    @router.get("/shares")
    async def list_shares(request: Request) -> dict[str, Any]:
        _require_admin(request)
        if share_store is None:
            raise HTTPException(status_code=503, detail="Shares store unavailable")
        return {"shares": share_store.list_all(), "apps": sorted(store_set)}

    @router.post("/shares")
    async def create_share(body: _CreateShareBody, request: Request) -> dict[str, Any]:
        actor = _require_admin(request)
        if share_store is None:
            raise HTTPException(status_code=503, detail="Shares store unavailable")
        app_id = body.app_id.strip()
        if app_id not in store_set:
            raise HTTPException(
                status_code=404, detail=f"No per-user store for app {app_id!r}"
            )
        try:
            record = share_store.share(
                app_id,
                body.owner,
                body.grantee,
                access=body.access,
                label=body.label,
                expires_at=parse_expires_at(body.expires_at),
                granted_by=actor,
            )
        except ShareError as e:
            raise HTTPException(
                status_code=409 if e.code == "no_account" else 422, detail=str(e)
            )
        except GrantError as e:
            raise HTTPException(status_code=422, detail=str(e))
        return {"ok": True, "share": record}

    @router.delete("/shares/{app_id}/{owner}/{grantee}")
    async def revoke_share(
        app_id: str, owner: str, grantee: str, request: Request
    ) -> dict[str, Any]:
        _require_admin(request)
        if share_store is None:
            raise HTTPException(status_code=503, detail="Shares store unavailable")
        # Both sides typed by an admin: either spelling of each, and the
        # response says which shares went (they may be distinct accounts).
        removed = share_store.revoke(
            app_id, owner, grantee, widen_owner=True, widen_grantee=True
        )
        if not removed:
            raise HTTPException(status_code=404, detail="Share not found")
        return {
            "ok": True,
            "removed": [{"owner": o, "grantee": g} for o, g in removed],
        }

    @router.delete("/grants/{app_id}/{email}")
    async def revoke_grant(app_id: str, email: str, request: Request) -> dict[str, Any]:
        _require_admin(request)
        if grant_store is None:
            raise HTTPException(status_code=503, detail="Grants store unavailable")
        removed = grant_store.revoke(app_id, email)
        if not removed:
            raise HTTPException(status_code=404, detail="Grant not found")
        # Both spellings are revoked; they may be two distinct accounts.
        return {
            "ok": True,
            "app_id": app_id,
            "email": email.lower(),
            "removed": removed,
        }

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
