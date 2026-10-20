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
import secrets
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Mapping, Optional

from enlace.access import GRANTS_STATE_ATTR

from enlace_auth.config import coerce_auth_config, coerce_stores_map
from enlace_auth.emails import account_spellings, lowercase_changes_letter

if TYPE_CHECKING:
    from fastapi import FastAPI


_logger = logging.getLogger("enlace_auth")


def _make_is_active(user_backend):
    """Return ``is_active(email)`` that fails OPEN on a store error.

    A False answer revokes the caller's whole connector session, so a transient
    unreadable user store would silently kill every connector at once -- the
    outage this refresh grant exists to prevent, triggered by a disk hiccup.
    Only a store that answers successfully and says "absent" (or "disabled")
    is grounds for revocation; the resource allowlist still gates everything
    either way.
    """
    from enlace_auth.auth.accounts import is_disabled

    def is_active(email: str) -> bool:
        try:
            if email not in user_backend:
                return False
            return not is_disabled(user_backend.get(email))
        except Exception:  # noqa: BLE001 - availability beats eager revocation
            _logger.warning(
                "enlace_auth: user store unreadable while checking %r; "
                "treating the account as active rather than revoking sessions",
                email,
            )
            return True

    return is_active


# The nonce each file claim wrote, keyed by claimant and key, so a release can only
# delete its own file (#62). A ContextVar, not a dict: a uvicorn worker serves
# many requests at once, and a request that took a stale claim over in this same
# process must not have its file deleted by the slow request it replaced. Each
# request runs in its own context, so each sees only the nonces it wrote.
_held_claims: ContextVar[Mapping[tuple[str, str], bytes]] = ContextVar(
    "enlace_auth_held_claims", default={}
)


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

    @contextmanager
    def _unlinking():
        """Hold the directory's exclusive lock while a claim file may be unlinked.

        Creation needs no lock: ``O_EXCL`` only succeeds on an absent path. Every
        *unlink* does, because "stat says stale, so unlink" is two steps: between
        them another process can take the stale claim over and write a fresh one,
        and the unlink then deletes that live claim, letting a third process
        create it again -- two winners (#60). Renaming the stale file aside first
        does not help: the rename can just as well move the fresh claim. With
        every unlink serialized here and creation impossible while the file
        exists, nothing can replace a file between the stat and the unlink.

        ``flock`` on the directory itself, so there is no lock file to sweep.
        Where ``fcntl`` is missing (Windows) this degrades to no lock.
        """
        if fcntl is None:
            yield
            return
        fd = os.open(str(claim_dir), os.O_RDONLY)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                # E.g. ENOLCK on a network filesystem without a lock daemon.
                # Every takeover and sweep then refuses, so stale claims stay
                # stuck: the outage this exists to prevent. Say so loudly.
                _logger.error(
                    "cannot lock claim dir %s; stale claims will not be taken "
                    "over or swept",
                    claim_dir,
                    exc_info=True,
                )
                raise
            yield
        finally:
            os.close(fd)  # closing the last descriptor releases the flock

    def _unlink_if_stale(path, now: float) -> bool:
        """Unlink *path* if it is older than the window; True if it is now gone.

        Call under the lock. A file that is already gone counts as gone: a sweep
        may have removed the stale claim while we queued for the lock, and the
        key is then free, not taken (review of #61).
        """
        try:
            if now - path.stat().st_mtime <= keep_seconds:
                return False
            path.unlink()
        except FileNotFoundError:
            return True
        except (OSError, ValueError):
            return False
        return True

    def _sweep(now: float, limit: int = 200) -> None:
        from itertools import islice

        # Housekeeping only: it must never turn a granted claim into an error.
        with suppress(OSError), _unlinking():
            for entry in islice(claim_dir.iterdir(), limit):
                _unlink_if_stale(entry, now)

    # Two claimants on one directory are two owners, even in one context.
    owner = secrets.token_hex(8)

    def _create(path) -> None:
        """Create *path* exclusively and stamp it with a nonce this claim keeps.

        Raises ``FileExistsError`` if it already exists, like ``O_EXCL`` itself.
        """
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        nonce = secrets.token_hex(16).encode()
        try:
            if os.write(fd, nonce) != len(nonce):
                # A short write would make the claim one its owner can never
                # release, stranding the token for a whole window.
                raise OSError(f"short write to claim file {path}")
        except BaseException:
            # A claim nobody can release would strand the token for a whole
            # window. The file is ours alone: fresh, so no takeover touches it.
            with suppress(OSError):
                path.unlink()
            raise
        finally:
            os.close(fd)
        _held_claims.set({**_held_claims.get(), (owner, path.name): nonce})

    def release(key: str) -> None:
        """Hand a claim back after a failed rotation -- only if it is still ours.

        A rotation that outlived *keep_seconds* has had its claim taken over as
        stale; unlinking by name would then delete the new claimant's live file
        and let a third one in: two rotations of one token (#62). So unlink only
        if the file still holds the nonce this claim wrote, checked under the
        lock so nothing can replace the file in between.
        """
        mine = _held_claims.get()
        nonce = mine.get((owner, key))
        if nonce is None:
            return
        _held_claims.set({k: v for k, v in mine.items() if k != (owner, key)})
        path = claim_dir / key
        with suppress(OSError), _unlinking():
            if path.read_bytes() == nonce:
                path.unlink()

    def claim(key: str) -> bool:
        # `key` is a sha256 hex digest, so it is already a safe filename.
        path = claim_dir / key
        try:
            _create(path)
        except FileExistsError:
            # A claim older than the window belonged to a worker that died before
            # it could consume the token. Without taking it over, that token is
            # unredeemable forever while its record still reads unconsumed -- and
            # the client's own retries can never heal it, because they never
            # reach the sweep below. Take it over exactly once.
            # The unlink and the re-create both happen under the lock, so of all
            # the processes that saw the same stale file, only the first through
            # the lock finds it still stale; the rest find the fresh claim.
            try:
                with _unlinking():
                    if not _unlink_if_stale(path, time.time()):
                        return False
                    _create(path)
            except (OSError, ValueError):
                # Someone else created it between our unlink and our create (a
                # plain O_EXCL claimant needs no lock), or the dir is unusable.
                # Either way we do not hold the claim.
                return False
        except OSError:
            # Fail CLOSED: if we cannot prove we are the only claimant, do not
            # pretend we are. The caller treats this as "already consumed",
            # which costs one re-authorization rather than risking a double mint.
            # Logged: an unwritable claim dir would otherwise refuse every grant
            # or consent with nothing in the journal (review of #59).
            _logger.error(
                "claim dir %s is not writable; refusing", claim_dir, exc_info=True
            )
            return False
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


def read_email_list(env_var: str, *, keep_unsafe: bool = False) -> tuple[str, ...]:
    """Read a comma-separated, case-folded email list from env var *env_var*.

    Entries are compared as written (lowercased), not normalized: mapping an
    operator's entry onto another spelling would also change which existing
    account it names. ``enlace doctor`` reports an admin entry whose account is
    keyed in another form (a punycode domain ``add-user`` stored in Unicode).

    An entry whose local part lowercasing changes by more than case (``İ``,
    ``ẞ``) is dropped with a warning, unless *keep_unsafe*: lowercased, it names
    another mailbox, one no path may now create an account for except a provider
    vouching for that other mailbox, so honouring it would hand the slot (an
    admin's, say) to whoever holds the twin (#57). The doctor reads the list
    with *keep_unsafe* to say why the entry never matches.
    """
    raw = os.environ.get(env_var or "", "")
    out = []
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        culprit = lowercase_changes_letter(entry.rpartition("@")[0] or entry)
        if culprit and not keep_unsafe:
            _logger.warning(
                "%s: ignoring an entry whose part before @ changes letters when "
                "lowercased (U+%04X); retype it (see `enlace doctor`).",
                env_var,
                ord(culprit),
            )
            continue
        out.append(entry.lower())
    return tuple(out)


# ``allowed_users = ["@admins"]`` in an app.toml means "the platform admins"
# (``admin_emails_env``). It lets an owner-only app say so without committing
# anyone's email address, and keeps one source of truth for who the owner is.
ADMINS_ALIAS = "@admins"


def _expand_allowed_users(
    allowed: Iterable[str], admin_emails: tuple[str, ...], *, app_name: str = ""
) -> list[str]:
    """Replace :data:`ADMINS_ALIAS` in *allowed* by the admin emails, and widen
    every other entry to both canonical spellings of its address
    (:func:`~enlace_auth.emails.account_spellings`), so an entry with a punycode
    domain admits the account ``add-user`` keyed in Unicode, and vice versa.

    The admin emails are NOT widened: ``@admins`` means exactly the accounts the
    admin check admits (that check compares as written), so it cannot hand an
    owner-only app to an account in another spelling that is not an admin.
    ``enlace doctor`` reports an admin entry spelled unlike its account.

    Fails CLOSED: with no admins configured the alias is kept verbatim. It can
    never equal a real (validated) email, so the list stays non-empty and the
    app admits nobody -- dropping it would empty the list, and an empty
    ``allowed_users`` means "any signed-in user".
    """
    allowed = list(allowed)
    if ADMINS_ALIAS not in allowed:
        return _with_all_spellings(allowed)
    if not admin_emails:
        _logger.warning(
            "enlace_auth: app %r allows %r but no admin emails are configured; "
            "the app will admit nobody until they are.",
            app_name,
            ADMINS_ALIAS,
        )
        return allowed
    out: list[str] = []
    for entry in allowed:
        widened = (
            admin_emails if entry == ADMINS_ALIAS else _with_all_spellings([entry])
        )
        out.extend(email for email in widened if email not in out)
    return out


def _with_all_spellings(entries: Iterable[str]) -> list[str]:
    """*entries*, each followed by its other canonical spelling, deduplicated.

    Only non-string entries are passed through untouched; the gate compares the
    account key exactly, so widening a written entry never folds a look-alike.
    """
    out: list[str] = []
    for entry in entries:
        forms = account_spellings(entry) if isinstance(entry, str) else (entry,)
        out.extend(f for f in forms if f not in out)
    return out


def _require_user_gate_for_admins_alias(app) -> None:
    """Make an app that names :data:`ADMINS_ALIAS` a ``protected:user`` app.

    ``allowed_users`` is only enforced at the ``protected:user`` level; on a
    ``public``/``local`` (the default!) or ``protected:shared`` app it is
    ignored. The alias exists to lock owner-only tools down, so an app that
    uses it but forgot ``access = "protected:user"`` is raised to that level
    -- failing closed -- rather than silently served to everyone. Refusing to
    start would take every other app down with it.
    """
    if ADMINS_ALIAS not in (getattr(app, "allowed_users", None) or ()):
        return
    if app.access != "protected:user":
        _logger.error(
            "enlace_auth: app %r lists %r in allowed_users but has access=%r, "
            "where allowed_users is not enforced; treating it as "
            "access='protected:user'. Set that in its app.toml.",
            app.name,
            ADMINS_ALIAS,
            app.access,
        )
        app.access = "protected:user"


def _public_base_url(config, auth_cfg) -> Optional[str]:
    """The platform's public origin, if the config pins one.

    Same precedence as the ``reset-link`` CLI: the OAuth issuer, else
    ``https://{domain}``. ``None`` for the default ``localhost`` domain, so a
    local dev server keeps building links from the request it is serving.
    """
    osc = getattr(auth_cfg, "oauth_server", None)
    issuer = getattr(osc, "issuer", None) if getattr(osc, "enabled", True) else None
    if issuer:
        return issuer
    domain = getattr(config, "domain", None)
    if domain and domain != "localhost":
        return f"https://{domain}"
    return None


def _build_can_register(
    auth_cfg, admin_emails: tuple[str, ...]
) -> Callable[[str], bool]:
    """Build the predicate deciding whether an email may self-register.

    Open registration admits every address; otherwise only emails listed in
    ``registration_allowlist_env`` may sign up (via ``/auth/register`` or an
    OAuth first-login), and everyone else is refused with 403.

    An admin address is refused in **both** cases: self-registration proves
    nothing about who owns the address, so an admin address with no account yet
    would go to whoever registers it first (i2mint/enlace_auth#35, #38). Admin
    accounts are made with ``enlace-auth add-user``, or by a first sign-in
    through an OAuth provider that verifies the address (``make_oauth_router``'s
    *admin_emails*). ``doctor`` flags any admin address that has no account.

    An admin address is refused in both canonical spellings
    (:func:`~enlace_auth.emails.account_spellings`): refusing only the spelling
    written would let registration claim the other one (#45 review). The
    registration allowlist is NOT widened: registration proves nothing about who
    owns an address, so an entry admits exactly the spelling written, and the
    other spelling can only arrive through a provider that verified it.
    """
    admins = frozenset(s for e in admin_emails for s in account_spellings(e))
    if getattr(auth_cfg, "registration_open", False):
        return lambda email: email.strip().lower() not in admins
    allow = set(read_email_list(getattr(auth_cfg, "registration_allowlist_env", "")))
    return lambda email: (e := email.strip().lower()) in allow and e not in admins


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
    from enlace_auth.auth.share_routes import make_share_router
    from enlace_auth.auth.shares import ShareStore
    from enlace_auth.stores import StoreInjectionMiddleware, make_file_store_factory
    from enlace_auth.stores.middleware import make_store_router

    platform_factory = make_file_store_factory(auth_cfg.stores.path)
    session_backend = platform_factory("sessions")
    user_backend = platform_factory("users")
    session_store = SessionStore(
        session_backend,
        max_age=auth_cfg.session_max_age_seconds,
        sign_ins=platform_factory("sign_ins"),
    )

    # Runtime per-app access grants (additive, optional UTC expiry). Lives beside
    # sessions/ and users/ under the same persistent store root — outside the
    # repo/rsync target, so grants survive redeploys. ``root`` is passed so the
    # store can list a single app's grants efficiently on the hot path.
    grants_root = Path(os.path.expanduser(auth_cfg.stores.path)) / "grants"
    grant_store = GrantStore(platform_factory("grants"), root=grants_root)

    # Owner-granted data shares (ADR 0001): who may act on whose per-user data.
    # Beside grants, under the same root; a share may only name existing accounts.
    share_store = ShareStore(
        platform_factory("shares"),
        root=Path(os.path.expanduser(auth_cfg.stores.path)) / "shares",
        account_exists=lambda email: email in user_backend,
    )

    def grants_resolver(app_id: str) -> set[str]:
        """Emails with an active grant for ``app_id``; ``now`` read per call."""
        return grant_store.active_emails_for_app(app_id, now=time.time())

    stores_map = coerce_stores_map(getattr(config, "stores", None))
    user_data_cfg = stores_map.get("user_data")
    user_data_backend: Optional[object] = None
    if user_data_cfg is not None:
        user_data_factory = make_file_store_factory(user_data_cfg.path)
        user_data_backend = user_data_factory("user_data")

    admin_emails = read_email_list(auth_cfg.admin_emails_env)
    can_register = _build_can_register(auth_cfg, admin_emails)
    email_sender = _build_email_sender()

    # Build access rules and shared-password lookup.
    # Two rules per app: the API prefix (/api/{name}) AND the frontend prefix
    # (/{name}) — otherwise browser requests to the frontend fall through to
    # the middleware's deny-by-default clause (issue #7).
    shared_hashes: dict[str, str] = {}
    access_rules: list[AccessRule] = []
    protected_user_apps: set[str] = set()
    store_apps: set[str] = set()
    for app in getattr(config, "apps", []):
        _require_user_gate_for_admins_alias(app)
        h: Optional[str] = None
        shared_env = getattr(app, "shared_password_env", None)
        if app.access == "protected:shared" and shared_env:
            h = os.environ.get(shared_env)
            if h:
                shared_hashes[app.name] = h
        if app.access == "protected:user":
            protected_user_apps.add(app.name)
        if app.access == "protected:user" or getattr(app, "user_store", False) is True:
            # Apps with a per-user store: protected:user ones, and any app (public
            # included) that opts in with ``user_store = true``. Kept apart from
            # protected_user_apps, which the grants admin uses.
            store_apps.add(app.name)
        allowed = tuple(
            _expand_allowed_users(
                getattr(app, "allowed_users", ()), admin_emails, app_name=app.name
            )
        )
        if list(allowed) != list(getattr(app, "allowed_users", ())):
            # Write the expansion back so enlace core's /_apps visibility check
            # (which reads app.allowed_users directly) agrees with the gate.
            app.allowed_users = list(allowed)
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

    # One hook for every path that changes an account's credentials: browser
    # sessions always go; the account's OAuth connector refresh families go too
    # when the OAuth server keeps them (i2mint/enlace_auth#26).
    from enlace_auth.auth.revocation import (
        make_on_credentials_changed,
        refresh_tombstone_ttl,
    )

    osc = auth_cfg.oauth_server
    _connector_revocation = (
        dict(
            refresh_store=platform_factory("oauth_refresh_tokens"),
            code_store=platform_factory("oauth_codes"),
            tombstone_ttl=refresh_tombstone_ttl(
                refresh_token_ttl=osc.refresh_token_ttl_seconds,
                refresh_reuse_detection=osc.refresh_reuse_detection_seconds,
            ),
            marker_ttl=osc.refresh_family_max_lifetime_seconds,
        )
        # Wired even while the OAuth server is off: families minted before it
        # was disabled come back to life if it is re-enabled.
        if refresh_tombstone_ttl(
            refresh_token_ttl=osc.refresh_token_ttl_seconds,
            refresh_reuse_detection=osc.refresh_reuse_detection_seconds,
        )
        > 0
        else {}
    )
    on_credentials_changed = make_on_credentials_changed(
        session_store, **_connector_revocation
    )

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
        public_base_url=_public_base_url(config, auth_cfg),
        on_credentials_changed=on_credentials_changed,
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
                admin_emails=admin_emails,
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
                # A consent approval is one-shot (#55). The claim is keyed on the
                # request's binding, and a reload re-mints a token for the same
                # binding at any time in the session, so the claim must last as
                # long as the session can: aged out after only consent_ttl, a token
                # re-minted just before then would approve the request again.
                consent_claim_once=_make_file_claim(
                    Path(os.path.expanduser(auth_cfg.stores.path))
                    / "oauth_consent_claims",
                    keep_seconds=max(
                        osc.consent_ttl_seconds, auth_cfg.session_max_age_seconds
                    ),
                ),
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
                consent_ttl=osc.consent_ttl_seconds,
                scopes_supported=tuple(osc.scopes_supported),
                require_consent=osc.require_consent,
                resource_allowlist=osc.resource_allowlist,
                allow_unlisted_resources=osc.allow_unlisted_resources,
                resource_display_names=osc.resource_display_names,
            )
            parent.include_router(oauth_server_router)
        except ImportError:
            _logger.error(
                "enlace_auth: [auth.oauth_server] is enabled but joserfc/cryptography "
                "are not installed. The OAuth server will be MISSING. Install with "
                "`pip install enlace_auth[oauth]` to fix."
            )

    # Per-user store API.
    store_router = make_store_router(
        base_store_getter=lambda: user_data_backend,
        protected_apps=store_apps,
        share_access=lambda app_id, owner, grantee: share_store.access(
            app_id, owner, grantee
        ),
    )
    parent.include_router(store_router)
    parent.include_router(
        make_share_router(share_store=share_store, store_apps=store_apps)
    )

    # App-metadata overlay: the editable launcher-metadata layer (owner-added
    # keywords + icon/title overrides). Core reads the overlay + can-edit closure
    # via parent.state; the write surface (PATCH/DELETE /_apps/{name}/meta) is
    # here so it inherits CSRF + auth. Editors default to the admin allowlist.
    from enlace_auth.appmeta import make_appmeta_can_edit, make_appmeta_router

    app_meta_cfg = getattr(config, "app_meta", None)
    explicit_editors = tuple(getattr(app_meta_cfg, "editors", ()) or ())
    if getattr(app_meta_cfg, "store_path", None):
        overlay_factory = make_file_store_factory(str(app_meta_cfg.store_path))
    else:
        overlay_factory = platform_factory  # beside sessions/users/grants
    overlay_store = overlay_factory("app_meta")
    # Only an explicit editor list is widened to both spellings: the admin
    # default stays exactly what the admin check admits (#45 review).
    can_edit_meta = make_appmeta_can_edit(
        explicit_editors or admin_emails, widen=bool(explicit_editors)
    )

    # DI slots read by enlace core (compose._overlay_entry / apps_listing).
    parent.state.app_meta_overlay = overlay_store
    parent.state.app_meta_can_edit = can_edit_meta
    # The grants resolver the gate consults, handed to enlace core too, so the
    # /_apps launcher shows a granted user the apps they can open (enlace #35).
    setattr(parent.state, GRANTS_STATE_ATTR, grants_resolver)

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
        share_store=share_store,
        store_apps=store_apps,
        signing_key=signing_key,
        resource_allowlist=auth_cfg.oauth_server.resource_allowlist,
        oauth_server_enabled=auth_cfg.oauth_server.enabled,
        public_base_url=_public_base_url(config, auth_cfg),
        on_credentials_changed=on_credentials_changed,
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

    # The CSRF cookie is minted only where a state-changing request can follow:
    # the auth routes (``/auth/csrf`` is where every client fetches its token),
    # the admin page, and the ``protected:*`` apps. A ``public`` app's pages set
    # no cookie, so an app that promises "nothing stored on the device" keeps
    # that promise when it runs on this platform (i2mint/enlace_auth#31).
    csrf_mint = ["/auth", "/_admin"] + [
        r.prefix for r in access_rules if r.level.startswith("protected:")
    ]

    # Register middleware in the order requests traverse them:
    # outermost = first added last. FastAPI/Starlette runs middleware in
    # reverse insertion order, so the last `add_middleware` call is the
    # outermost wrapper. We want: auth (outermost) -> store -> csrf -> app.
    parent.add_middleware(
        CSRFMiddleware,
        signing_key=signing_key,
        exempt_prefixes=csrf_exempt,
        enforce_prefixes=[f"/api/{name}/store" for name in sorted(store_apps)],
        mint_prefixes=csrf_mint,
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
        dynamic_allowed_users=grants_resolver,
    )


# Plugin protocol: a plain callable. Re-exported for clarity.
plugin = wire
