"""Compose-time plugin: wires auth + stores onto an enlace FastAPI app.

Usage from the host (e.g. tw_platform):

    from enlace import build_backend, PlatformConfig
    from enlace_auth import plugin as auth_plugin

    config = PlatformConfig.from_toml()
    app = build_backend(config, plugins=[auth_plugin])

The plugin is a callable ``(parent: FastAPI, config: PlatformConfig) -> None``.
It is a no-op when ``config.auth.enabled`` is False, so platforms that don't
opt in pay nothing for installing this package.

Reads (best-effort, via getattr so the plugin doesn't require enlace to know
about AuthConfig):
- ``config.auth``  — AuthConfig (or dict / None)
- ``config.stores`` — dict[name, StoreBackendConfig (or dict)]
- ``config.apps``  — list[AppConfig]; uses ``access``, ``allowed_users``,
  ``shared_password_env``, ``route_prefix``, ``name``.
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from enlace_auth.config import coerce_auth_config, coerce_stores_map

if TYPE_CHECKING:
    from fastapi import FastAPI


_logger = logging.getLogger("enlace_auth")


def _make_is_active(user_backend):
    """Return ``is_active(email)`` that fails OPEN on a store error.

    A False answer revokes the caller's whole connector session, so a transient
    unreadable user store would silently kill every connector at once -- the
    outage this refresh grant exists to prevent, triggered by a disk hiccup.
    Only a store that answers successfully and says "absent" is grounds for
    revocation; the resource allowlist still gates everything either way.
    """

    def is_active(email: str) -> bool:
        try:
            return email in user_backend
        except Exception:  # noqa: BLE001 - availability beats eager revocation
            _logger.warning(
                "enlace_auth: user store unreadable while checking %r; "
                "treating the account as active rather than revoking sessions",
                email,
            )
            return True

    return is_active


def _make_file_claim(claim_dir, *, keep_seconds: int = 600):
    """Return ``claim(key) -> bool``: True for the first caller, False after.

    The OAuth refresh grant rotates tokens, and rotation is only meaningful if
    consuming a token happens exactly once. A ``MutableMapping`` cannot express
    that — a read-then-write is not atomic — and the platform runs several
    gunicorn worker *processes* over one shared store, so an in-process lock is
    not enough either. ``O_CREAT | O_EXCL`` is: the kernel guarantees exactly one
    creator, on every POSIX filesystem, with no extra dependency.

    A claim only has to outlive the request that takes it, so *keep_seconds* is
    minutes, not days: once the tombstone is written, a second attempt is routed
    by ``consumed_at`` and never reaches the claim at all. Sweeping aggressively
    bounds how long a worker killed mid-rotation can strand a connector.
    """
    from pathlib import Path as _Path

    claim_dir = _Path(claim_dir)
    claim_dir.mkdir(parents=True, exist_ok=True)

    def _sweep(now: float, limit: int = 200) -> None:
        from itertools import islice

        for entry in islice(claim_dir.iterdir(), limit):
            try:
                if now - entry.stat().st_mtime > keep_seconds:
                    entry.unlink()
            except OSError:
                pass

    def release(key: str) -> None:
        """Hand a claim back after a failed rotation."""
        with suppress(OSError):
            (claim_dir / key).unlink()

    def claim(key: str) -> bool:
        # `key` is a sha256 hex digest, so it is already a safe filename.
        path = claim_dir / key
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            # A claim older than the window belonged to a worker that died before
            # it could consume the token. Without taking it over, that token is
            # unredeemable forever while its record still reads unconsumed -- and
            # the client's own retries can never heal it, because they never
            # reach the sweep below. Take it over exactly once.
            try:
                if time.time() - path.stat().st_mtime <= keep_seconds:
                    return False
                path.unlink()
                fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except (OSError, ValueError):
                # Someone else won the takeover, or the file vanished. Either way
                # we do not hold the claim.
                return False
        except OSError:
            # Fail CLOSED: if we cannot prove we are the only claimant, do not
            # pretend we are. The caller treats this as "already consumed",
            # which costs one re-authorization rather than risking a double mint.
            return False
        os.close(fd)
        _sweep(time.time())
        return True

    claim.release = release  # type: ignore[attr-defined]
    return claim


# Minimum accepted signing-key length. ``secrets.token_urlsafe(32)`` yields 43
# chars; anything shorter is a stub and should be rejected.
_MIN_SIGNING_KEY_LEN = 32

_UNSAFE_OPT_OUT_ENV = "ENLACE_ALLOW_UNSIGNED"


class EnlaceAuthConfigError(RuntimeError):
    """Raised when auth configuration is unusable at startup."""


def _require_signing_key(env_var: str) -> Optional[str]:
    """Resolve the auth signing key, enforcing fail-fast by default.

    Returns the key when usable. Returns ``None`` when the key is missing or
    malformed AND ``ENLACE_ALLOW_UNSIGNED=1`` is set — the caller should then
    skip auth wiring (a loud warning is already logged here).
    """
    raw = os.environ.get(env_var) or ""
    stripped = raw.strip()
    problem: Optional[str] = None
    if not stripped:
        problem = f"env var {env_var} is unset or empty"
    elif len(stripped) < _MIN_SIGNING_KEY_LEN:
        problem = (
            f"env var {env_var} is too short "
            f"({len(stripped)} chars; need >= {_MIN_SIGNING_KEY_LEN})"
        )

    if problem is None:
        return stripped

    if os.environ.get(_UNSAFE_OPT_OUT_ENV) == "1":
        _logger.error(
            "enlace auth is ENABLED but %s — booting with /auth/* DISABLED "
            "because %s=1. This gateway cannot authenticate users. Unset the "
            "opt-out and set %s to restore auth.",
            problem,
            _UNSAFE_OPT_OUT_ENV,
            env_var,
        )
        return None

    raise EnlaceAuthConfigError(
        f"enlace auth is enabled but {problem}. Generate one with "
        f"`enlace auth-generate-signing-key` and export it as {env_var}. "
        f"To boot without auth (diagnostics only), set "
        f"{_UNSAFE_OPT_OUT_ENV}=1."
    )


def _read_admin_emails(env_var: str) -> tuple[str, ...]:
    raw = os.environ.get(env_var, "")
    return tuple(e.strip().lower() for e in raw.split(",") if e.strip())


def _build_can_register(
    auth_cfg, admin_emails: tuple[str, ...]
) -> Callable[[str], bool]:
    """Build the predicate deciding whether an email may self-register.

    Open registration → always True. Otherwise only admin emails and emails
    listed in ``registration_allowlist_env`` may sign up (via ``/auth/register``
    or an OAuth first-login); everyone else is refused with 403.
    """
    if getattr(auth_cfg, "registration_open", False):
        return lambda _email: True
    allow = {e.lower() for e in admin_emails}
    allowlist_env = getattr(auth_cfg, "registration_allowlist_env", "") or ""
    raw = os.environ.get(allowlist_env, "")
    allow |= {e.strip().lower() for e in raw.split(",") if e.strip()}
    return lambda email: email.lower() in allow


def _build_email_sender():
    """Build an SMTP email sender from ``ENLACE_SMTP_*`` env vars, or None.

    Returns None when no SMTP host is set — the auth router then falls back to
    its console sender, which logs the password-reset link instead of mailing
    it. Recognized vars: ``ENLACE_SMTP_HOST`` (required to enable SMTP),
    ``ENLACE_SMTP_PORT`` (587), ``ENLACE_SMTP_USER``, ``ENLACE_SMTP_PASSWORD``,
    ``ENLACE_SMTP_FROM``, ``ENLACE_SMTP_TLS`` (``0`` to disable STARTTLS).
    """
    host = os.environ.get("ENLACE_SMTP_HOST", "").strip()
    if not host:
        return None
    from enlace_auth.auth.email import make_smtp_sender

    username = os.environ.get("ENLACE_SMTP_USER") or None
    from_addr = os.environ.get("ENLACE_SMTP_FROM") or username or "noreply@localhost"
    return make_smtp_sender(
        host=host,
        port=int(os.environ.get("ENLACE_SMTP_PORT", "587")),
        username=username,
        password=os.environ.get("ENLACE_SMTP_PASSWORD") or None,
        from_addr=from_addr,
        use_tls=os.environ.get("ENLACE_SMTP_TLS", "1") != "0",
    )


def wire(parent: "FastAPI", config) -> None:
    """Mount /auth/*, /_admin/*, store routes, and middleware on ``parent``.

    Plugin entry point. Safe to call when auth is disabled — does nothing.
    """
    auth_cfg = coerce_auth_config(getattr(config, "auth", None))
    if not auth_cfg.enabled:
        return

    signing_key = _require_signing_key(auth_cfg.signing_key_env)
    if signing_key is None:
        return

    from enlace_auth.admin.routes import make_admin_router
    from enlace_auth.auth import (
        CSRFMiddleware,
        GrantStore,
        PlatformAuthMiddleware,
        SessionStore,
        make_auth_router,
    )
    from enlace_auth.auth.middleware import AccessRule
    from enlace_auth.stores import StoreInjectionMiddleware, make_file_store_factory
    from enlace_auth.stores.middleware import make_store_router

    platform_factory = make_file_store_factory(auth_cfg.stores.path)
    session_backend = platform_factory("sessions")
    user_backend = platform_factory("users")
    session_store = SessionStore(session_backend)

    # Runtime per-app access grants (additive, optional UTC expiry). Lives beside
    # sessions/ and users/ under the same persistent store root — outside the
    # repo/rsync target, so grants survive redeploys. ``root`` is passed so the
    # store can list a single app's grants efficiently on the hot path.
    grants_root = Path(os.path.expanduser(auth_cfg.stores.path)) / "grants"
    grant_store = GrantStore(platform_factory("grants"), root=grants_root)

    stores_map = coerce_stores_map(getattr(config, "stores", None))
    user_data_cfg = stores_map.get("user_data")
    user_data_backend: Optional[object] = None
    if user_data_cfg is not None:
        user_data_factory = make_file_store_factory(user_data_cfg.path)
        user_data_backend = user_data_factory("user_data")

    admin_emails = _read_admin_emails(auth_cfg.admin_emails_env)
    can_register = _build_can_register(auth_cfg, admin_emails)
    email_sender = _build_email_sender()

    # Build access rules and shared-password lookup.
    # Two rules per app: the API prefix (/api/{name}) AND the frontend prefix
    # (/{name}) — otherwise browser requests to the frontend fall through to
    # the middleware's deny-by-default clause (issue #7).
    shared_hashes: dict[str, str] = {}
    access_rules: list[AccessRule] = []
    protected_user_apps: set[str] = set()
    for app in getattr(config, "apps", []):
        h: Optional[str] = None
        shared_env = getattr(app, "shared_password_env", None)
        if app.access == "protected:shared" and shared_env:
            h = os.environ.get(shared_env)
            if h:
                shared_hashes[app.name] = h
        if app.access == "protected:user":
            protected_user_apps.add(app.name)
        allowed = tuple(getattr(app, "allowed_users", ()))
        access_rules.append(
            AccessRule(
                prefix=app.route_prefix,
                level=app.access,
                app_id=app.name,
                shared_password_hash=h,
                allowed_users=allowed,
            )
        )
        frontend_prefix = f"/{app.name}"
        if frontend_prefix != app.route_prefix:
            access_rules.append(
                AccessRule(
                    prefix=frontend_prefix,
                    level=app.access,
                    app_id=app.name,
                    shared_password_hash=h,
                    allowed_users=allowed,
                )
            )

    # /_admin/* is admin-only when admin_emails is non-empty.
    if admin_emails:
        access_rules.append(
            AccessRule(
                prefix="/_admin",
                level="protected:user",
                app_id="_admin",
                allowed_users=admin_emails,
            )
        )

    # Root (/) and shared static assets — public. The platform landing page
    # must be reachable to anyone; per-app gating already covers everything
    # beneath a more specific prefix via longest-prefix match.
    access_rules.append(AccessRule(prefix="/", level="public", app_id="_root"))

    auth_router = make_auth_router(
        session_store=session_store,
        user_store=user_backend,
        signing_key=signing_key,
        cookie_name=auth_cfg.session_cookie_name,
        session_max_age=auth_cfg.session_max_age_seconds,
        secure_cookies=auth_cfg.secure_cookies,
        shared_password_for=shared_hashes.get,
        can_register=can_register,
        send_email=email_sender,
    )
    parent.include_router(auth_router)

    # Optional OAuth router (lazy import of Authlib).
    if auth_cfg.oauth:
        try:
            from enlace_auth.auth.oauth import make_oauth_router

            oauth_router = make_oauth_router(
                providers=auth_cfg.oauth,
                session_store=session_store,
                user_store=user_backend,
                signing_key=signing_key,
                cookie_name=auth_cfg.session_cookie_name,
                session_max_age=auth_cfg.session_max_age_seconds,
                secure_cookies=auth_cfg.secure_cookies,
                can_register=can_register,
            )
            if oauth_router is not None:
                parent.include_router(oauth_router)
        except ImportError:
            providers = ", ".join(sorted(auth_cfg.oauth)) or "(none)"
            _logger.error(
                "enlace_auth: [auth.oauth.*] is configured (%s) but authlib is "
                "not installed. OAuth endpoints will be MISSING. "
                "Install with `pip install enlace_auth[oauth]` to fix.",
                providers,
            )

    # OAuth 2.1 authorization server (issues JWTs for MCP custom connectors).
    if auth_cfg.oauth_server.enabled:
        try:
            from enlace_auth.auth.oauth_server import (
                OAuthKeys,
                make_oauth_server_router,
            )

            osc = auth_cfg.oauth_server
            _oauth_claim = _make_file_claim(
                Path(os.path.expanduser(auth_cfg.stores.path)) / "oauth_refresh_claims"
            )
            oauth_server_router = make_oauth_server_router(
                session_store=session_store,
                signing_key=signing_key,
                cookie_name=auth_cfg.session_cookie_name,
                session_max_age=auth_cfg.session_max_age_seconds,
                client_store=platform_factory("oauth_clients"),
                code_store=platform_factory("oauth_codes"),
                refresh_store=(
                    platform_factory("oauth_refresh_tokens")
                    if osc.refresh_token_ttl_seconds > 0
                    else None
                ),
                # Rotation is a read-modify-write and the platform runs several
                # worker PROCESSES over one shared store, so consumption needs a
                # cross-process claim. Without it two concurrent redemptions both
                # mint a live successor and reuse detection never fires.
                claim_once=_oauth_claim,
                release_claim=_oauth_claim.release,
                # Re-checked on every refresh: a deleted account must not keep
                # renewing its own connector session.
                is_active=_make_is_active(user_backend),
                keys=OAuthKeys(osc.key_dir),
                issuer=osc.issuer,
                access_token_ttl=osc.access_token_ttl_seconds,
                refresh_token_ttl=osc.refresh_token_ttl_seconds,
                refresh_reuse_grace=osc.refresh_reuse_grace_seconds,
                refresh_reuse_detection=osc.refresh_reuse_detection_seconds,
                refresh_family_max_lifetime=osc.refresh_family_max_lifetime_seconds,
                client_ttl=osc.client_ttl_seconds,
                code_ttl=osc.code_ttl_seconds,
                scopes_supported=tuple(osc.scopes_supported),
                require_consent=osc.require_consent,
                resource_allowlist=osc.resource_allowlist,
                resource_display_names=osc.resource_display_names,
            )
            parent.include_router(oauth_server_router)
        except ImportError:
            _logger.error(
                "enlace_auth: [auth.oauth_server] is enabled but authlib/cryptography "
                "are not installed. The OAuth server will be MISSING. Install with "
                "`pip install enlace_auth[oauth]` to fix."
            )

    # Per-user store API.
    store_router = make_store_router(
        base_store_getter=lambda: user_data_backend,
        protected_apps=protected_user_apps,
    )
    parent.include_router(store_router)

    # App-metadata overlay: the editable launcher-metadata layer (owner-added
    # keywords + icon/title overrides). Core reads the overlay + can-edit closure
    # via parent.state; the write surface (PATCH/DELETE /_apps/{name}/meta) is
    # here so it inherits CSRF + auth. Editors default to the admin allowlist.
    from enlace_auth.appmeta import make_appmeta_can_edit, make_appmeta_router

    app_meta_cfg = getattr(config, "app_meta", None)
    editors = tuple(getattr(app_meta_cfg, "editors", ()) or ()) or admin_emails
    if getattr(app_meta_cfg, "store_path", None):
        overlay_factory = make_file_store_factory(str(app_meta_cfg.store_path))
    else:
        overlay_factory = platform_factory  # beside sessions/users/grants
    overlay_store = overlay_factory("app_meta")
    can_edit_meta = make_appmeta_can_edit(editors)

    # DI slots read by enlace core (compose._overlay_entry / apps_listing).
    parent.state.app_meta_overlay = overlay_store
    parent.state.app_meta_can_edit = can_edit_meta

    parent.include_router(
        make_appmeta_router(
            apps=list(getattr(config, "apps", [])),
            config=config,
            overlay_store=overlay_store,
            can_edit=can_edit_meta,
        )
    )

    # Admin router (API + UI). UI is only mounted when there is at least one
    # admin email; otherwise the dashboard would be unreachable anyway.
    admin_router = make_admin_router(
        user_store=user_backend,
        session_store=session_store,
        admin_emails=admin_emails,
        apps=list(getattr(config, "apps", [])),
        grant_store=grant_store,
        protected_user_apps=protected_user_apps,
        signing_key=signing_key,
        resource_allowlist=auth_cfg.oauth_server.resource_allowlist,
    )
    parent.include_router(admin_router)
    if admin_emails:
        from enlace_auth.admin.routes import make_admin_ui_router

        parent.include_router(make_admin_ui_router())

    # CSRF exempt prefixes: the default exempts /api/ (asgi-mode sub-app APIs
    # mounted at the conventional prefix). Non-asgi modes (process/external)
    # proxy to a black-box upstream that can't participate in enlace's
    # double-submit flow, so their entire mount prefix must also be exempt.
    csrf_exempt = ["/auth/callback", "/auth/login/", "/api/"]
    if auth_cfg.oauth_server.enabled:
        # OAuth 2.1 server endpoints: /register + /token are cookieless
        # machine-to-machine calls (protected by PKCE + client validation), and
        # the consent POST carries its own signed CSRF token — so the platform's
        # double-submit CSRF must not gate them.
        csrf_exempt.append("/auth/oauth/")
    for app in getattr(config, "apps", []):
        if getattr(app, "mode", "asgi") in ("process", "external"):
            prefix = app.route_prefix
            if not prefix.endswith("/"):
                prefix = prefix + "/"
            if prefix not in csrf_exempt:
                csrf_exempt.append(prefix)

    # Register middleware in the order requests traverse them:
    # outermost = first added last. FastAPI/Starlette runs middleware in
    # reverse insertion order, so the last `add_middleware` call is the
    # outermost wrapper. We want: auth (outermost) -> store -> csrf -> app.
    parent.add_middleware(
        CSRFMiddleware, signing_key=signing_key, exempt_prefixes=csrf_exempt
    )
    parent.add_middleware(StoreInjectionMiddleware, base_store=user_data_backend)
    parent.add_middleware(
        PlatformAuthMiddleware,
        access_rules=access_rules,
        session_store=session_store,
        signing_key=signing_key,
        cookie_name=auth_cfg.session_cookie_name,
        max_age=auth_cfg.session_max_age_seconds,
        # Browser navigations to a gated page are redirected here (with
        # ?login_required=1&next=<path>) instead of bounced to the landing
        # app, which would silently drop those hints. The auth router serves
        # the actual sign-in form at this path.
        login_redirect_path="/auth/login",
        # Consult runtime grants live, per request, on top of each rule's static
        # allowed_users. ``now`` is evaluated at call time so expiry is exact.
        dynamic_allowed_users=lambda app_id: grant_store.active_emails_for_app(
            app_id, now=time.time()
        ),
    )


# Plugin protocol: a plain callable. Re-exported for clarity.
plugin = wire
