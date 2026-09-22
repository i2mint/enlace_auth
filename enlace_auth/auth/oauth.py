"""OAuth2/OIDC login via Authlib.

Lazy import — ``authlib`` lives behind the ``enlace[oauth]`` extra. Providers
are configured in ``platform.toml`` under ``[auth.oauth.{name}]`` with
``client_id_env`` / ``client_secret_env`` pointing at env vars (secrets never
in TOML). On callback we create a local session — the upstream tokens are
discarded because we use OAuth for identity only, not API access.

Two rules keep an OAuth login from being weaker than the account it opens:

- **The anti-CSRF state lives in a signed cookie** scoped to ``/auth``
  (:func:`_oauth_state_session`). Authlib keeps the ``state``, nonce and PKCE
  verifier in ``request.session``; the plugin installs no Starlette
  ``SessionMiddleware``, so this module supplies that session itself. A callback
  whose ``state`` was not issued to *this* browser is refused.
- **An identity is bound to the provider's stable subject** (``sub``, or
  ``tid``/``oid`` for Microsoft, GitHub's numeric ``id``), recorded as
  ``oauth_links[provider]`` on the account. A later login must present the same
  subject. An existing *password* account, or one linked to another provider, is
  never taken over by an email match alone.

Residual limits, by design: the state cookie is signed but not bound to the
browser, so a script that can set cookies on the platform origin (any
co-hosted app) could plant its own state for a browser that has none and so
log that browser in as the attacker (two cookies of the name are refused). An
account created by a provider before links existed is bound to the first
subject that signs in to it after the upgrade. A password reset (admin, emailed
link, CLI) unlinks every external sign-in. The cookie path assumes the router
is mounted at ``/auth`` with no root path.

Built-in provider presets for Google and GitHub auto-fill the well-known
endpoints; other providers need explicit URLs in the config.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.sessions import SessionStore
from enlace_auth.config import OAuthProviderConfig

_logger = logging.getLogger("enlace_auth.oauth")

_PROVIDER_PRESETS = {
    "google": {
        "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
        "scopes": ["openid", "profile", "email"],
    },
    "github": {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scopes": ["read:user", "user:email"],
    },
}


def _import_authlib():
    try:
        from authlib.integrations.starlette_client import OAuth  # type: ignore
    except ImportError as e:
        raise ImportError(
            "authlib is required for OAuth. Install via `pip install enlace[oauth]`."
        ) from e
    return OAuth


#: Presets whose userinfo exposes only verified emails, without a claim saying so.
_EMAIL_VERIFIED_BY_PRESET = frozenset({"github"})


def _verified(flag) -> bool:
    """True only when an ``email_verified`` claim affirms the address.

    >>> _verified(True), _verified("true"), _verified(False), _verified(None)
    (True, True, False, False)
    >>> _verified(1)
    False
    """
    return flag is True or (isinstance(flag, str) and flag.strip().lower() == "true")


def _email_trusted(provider: str, cfg, claims: dict) -> bool:
    """Whether an email returned by *provider* may identify an account here."""
    if _verified(claims.get("email_verified")):
        return True
    if claims.get("email_verified") is not None:
        return False  # the provider said "not verified" (in whatever form)
    return provider in _EMAIL_VERIFIED_BY_PRESET or bool(
        getattr(cfg, "trust_unverified_email", False)
    )


def _is_entra_issuer(iss: str) -> bool:
    """True for Microsoft Entra ID token issuers."""
    from urllib.parse import urlparse

    host = (urlparse(iss).hostname or "").lower()
    return host in {"login.microsoftonline.com", "sts.windows.net"}


def _cookie_count(request: Request, name: str) -> int:
    """How many cookies called *name* the request carries (Starlette keeps one)."""
    raw = request.headers.get("cookie", "")
    return sum(1 for part in raw.split(";") if part.strip().split("=", 1)[0] == name)


def _stable_subject(provider: str, claims: dict) -> Optional[str]:
    """The provider's stable, non-reassignable id for the signed-in identity.

    >>> _stable_subject("google", {"sub": "123", "email": "a@x.io"})
    '123'
    >>> _stable_subject("microsoft", {"sub": "s", "tid": "T", "oid": "O",
    ...     "iss": "https://login.microsoftonline.com/T/v2.0"})
    'T/O'
    >>> _stable_subject("custom", {"sub": "s", "tid": "T", "oid": "O"})
    's'
    >>> _stable_subject("github", {"id": 42})
    '42'
    >>> _stable_subject("x", {"email": "a@x.io"}) is None
    True
    """
    tid, oid = claims.get("tid"), claims.get("oid")
    iss = str(claims.get("iss") or "")
    if tid and oid and _is_entra_issuer(iss):
        # Entra ID: `sub` is pairwise per app; tid/oid is the user. Only for
        # Entra's own issuers -- elsewhere these are ordinary, maybe
        # user-influenced, claims.
        return f"{tid}/{oid}"
    for key in ("sub", "id"):  # OIDC, then GitHub's /user
        value = claims.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _login_refusal(record: Any, provider: str, subject: Optional[str]) -> Optional[str]:
    """Why *record* must not be opened by this OAuth identity, or None if it may.

    >>> _login_refusal({"password_hash": "h"}, "google", "1") is not None
    True
    >>> _login_refusal({"oauth_links": {"google": "1"}}, "google", "1") is None
    True
    >>> _login_refusal({"oauth_links": {"google": "1"}}, "google", "2") is not None
    True
    >>> _login_refusal({"password_hash": None, "oauth_provider": "google"},
    ...                "google", "1") is None
    True
    >>> _login_refusal({"password_hash": None, "oauth_provider": "github"},
    ...                "google", "1") is not None
    True
    """
    if not isinstance(record, dict):
        return "This account cannot be opened with an external sign-in."
    links = record.get("oauth_links") or {}
    if provider in links:
        if subject is not None and links[provider] == subject:
            return None
        return "This sign-in does not match the identity linked to this account."
    if record.get("password_hash"):
        return (
            "This email belongs to a password account. Sign in with your "
            "password; an external sign-in is not linked to it."
        )
    if record.get("oauth_provider") == provider:
        return None  # created by this provider before links were recorded
    return "This account is linked to a different sign-in method."


def _build_oauth_registry(providers: dict[str, OAuthProviderConfig]):
    OAuth = _import_authlib()
    oauth = OAuth()
    for name, cfg in providers.items():
        preset = _PROVIDER_PRESETS.get(name, {})
        client_id = os.environ.get(cfg.client_id_env)
        client_secret = os.environ.get(cfg.client_secret_env)
        if not client_id or not client_secret:
            # Skip providers whose env vars aren't set; `enlace check` surfaces this.
            continue
        kwargs: dict[str, Any] = {
            "name": name,
            "client_id": client_id,
            "client_secret": client_secret,
            "client_kwargs": {
                "scope": " ".join(cfg.scopes or preset.get("scopes", [])),
            },
        }
        smu = cfg.server_metadata_url or preset.get("server_metadata_url")
        if smu:
            kwargs["server_metadata_url"] = smu
        else:
            if cfg.authorize_url or preset.get("authorize_url"):
                kwargs["authorize_url"] = cfg.authorize_url or preset.get(
                    "authorize_url"
                )
            if cfg.token_url or preset.get("token_url"):
                kwargs["access_token_url"] = cfg.token_url or preset.get("token_url")
            if cfg.userinfo_url or preset.get("userinfo_url"):
                kwargs["userinfo_endpoint"] = cfg.userinfo_url or preset.get(
                    "userinfo_url"
                )
        oauth.register(**kwargs)
    return oauth


def make_oauth_router(
    *,
    providers: dict[str, OAuthProviderConfig],
    session_store: SessionStore,
    user_store,  # MutableMapping[email -> {...}]
    signing_key: str,
    cookie_name: str = "enlace_session",
    session_max_age: int = 86400,
    secure_cookies: bool = True,
    can_register: Callable[[str], bool] = lambda _: False,
    state_cookie_name: str = "enlace_oauth_state",
    state_max_age: int = 600,
) -> Optional[APIRouter]:
    """Build an OAuth router or return None if no providers are configured.

    *state_cookie_name* / *state_max_age* name and bound the signed cookie that
    carries Authlib's per-login state between ``/auth/login/{provider}`` and the
    callback (see the module docstring). It is only used when no Starlette
    ``SessionMiddleware`` already provides ``request.session``.
    """
    if not providers:
        return None

    oauth = _build_oauth_registry(providers)
    router = APIRouter(prefix="/auth")

    def _set_session_cookie(response: Response, session_id: str):
        signed = sign_cookie(session_id, signing_key, salt="session")
        attrs = [
            f"{cookie_name}={signed}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={session_max_age}",
            "SameSite=Lax",
        ]
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))

    _state_salt = "oauth-state"

    def _oauth_state_session(request: Request) -> bool:
        """Give Authlib a ``request.session`` backed by the signed state cookie.

        Returns True when this module owns the session (and so must write it
        back), False when a real ``SessionMiddleware`` already provides one.
        """
        if "session" in request.scope:
            return False
        data: dict = {}
        token = request.cookies.get(state_cookie_name)
        if _cookie_count(request, state_cookie_name) > 1:
            # Two cookies of this name means one was planted at another path
            # (cookie tossing) to smuggle in someone else's login state.
            token = None
        raw = (
            verify_cookie(token, signing_key, max_age=state_max_age, salt=_state_salt)
            if token
            else None
        )
        if raw:
            try:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    data = loaded
            except ValueError:
                pass
        request.scope["session"] = data
        return True

    def _state_cookie_header(session: dict) -> str:
        if session:
            value = sign_cookie(json.dumps(session), signing_key, salt=_state_salt)
            attrs = [
                f"{state_cookie_name}={value}",
                "Path=/auth",
                "HttpOnly",
                f"Max-Age={state_max_age}",
                "SameSite=Lax",
            ]
        else:
            attrs = [f"{state_cookie_name}=", "Path=/auth", "HttpOnly", "Max-Age=0"]
        if secure_cookies:
            attrs.append("Secure")
        return "; ".join(attrs)

    def _write_state_cookie(response: Response, session: dict) -> None:
        response.headers.append("set-cookie", _state_cookie_header(session))

    def _drop_provider_states(session: dict, provider: str) -> None:
        """A callback spends every pending state of its provider, win or lose."""
        for key in [k for k in session if k.startswith(f"_state_{provider}_")]:
            session.pop(key, None)

    @router.get("/login/{provider}")
    async def login(provider: str, request: Request):
        client = getattr(oauth, provider, None)
        if client is None:
            raise HTTPException(
                status_code=404, detail=f"Unknown provider '{provider}'"
            )
        owns_session = _oauth_state_session(request)
        redirect_uri = str(request.url_for("oauth_callback", provider=provider))
        resp = await client.authorize_redirect(request, redirect_uri)
        if owns_session:
            _write_state_cookie(resp, request.session)
        return resp

    @router.get("/callback/{provider}", name="oauth_callback")
    async def callback(provider: str, request: Request):
        client = getattr(oauth, provider, None)
        if client is None:
            raise HTTPException(
                status_code=404, detail=f"Unknown provider '{provider}'"
            )
        owns_session = _oauth_state_session(request)
        try:
            resp = await _complete_login(provider, client, request)
        except HTTPException as e:
            if owns_session:
                _drop_provider_states(request.session, provider)
                e.headers = {
                    **(e.headers or {}),
                    "set-cookie": _state_cookie_header(request.session),
                }
            raise
        if owns_session:
            _drop_provider_states(request.session, provider)
            _write_state_cookie(resp, request.session)
        return resp

    async def _complete_login(provider: str, client, request: Request) -> Response:
        try:
            token = await client.authorize_access_token(request)
        except Exception as e:
            # The error text can echo attacker-supplied callback parameters.
            _logger.warning("OAuth callback failed for %s: %s", provider, e)
            raise HTTPException(status_code=401, detail="OAuth sign-in failed") from e

        email = None
        claims: dict = {}
        userinfo = token.get("userinfo") if isinstance(token, dict) else None
        if userinfo and isinstance(userinfo, dict):
            claims = userinfo
            email = userinfo.get("email")

        if not email and hasattr(client, "userinfo"):
            try:
                info = await client.userinfo(token=token)
                if isinstance(info, dict):
                    claims = info
                    email = info.get("email")
            except Exception:
                pass

        if not email:
            raise HTTPException(status_code=401, detail="No email from OAuth provider")
        # Accounts are keyed by email, so an address the provider has not
        # verified would let someone sign in as whoever owns it here --
        # including an existing password account. Require the provider to
        # affirm it (OIDC ``email_verified``); providers that never send the
        # claim pass only if known to verify (github preset) or opted in.
        if not _email_trusted(provider, providers.get(provider), claims):
            raise HTTPException(
                status_code=401,
                detail="The OAuth provider has not verified this email address",
            )

        email = email.lower()
        subject = _stable_subject(provider, claims)
        try:
            record = user_store[email]
        except KeyError:
            record = None
        if record is None:
            if not can_register(email):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "This account is not permitted to register on this "
                        "platform. Contact the platform admin."
                    ),
                )
            user_store[email] = {
                "password_hash": None,
                "created_at": time.time(),
                "oauth_provider": provider,
                "oauth_links": {provider: subject} if subject else {},
            }
        else:
            refusal = _login_refusal(record, provider, subject)
            if refusal is not None:
                _logger.warning(
                    "OAuth sign-in via %s refused for %s: %s", provider, email, refusal
                )
                raise HTTPException(status_code=403, detail=refusal)
            links = record.get("oauth_links") or {}
            if subject and provider not in links:
                # A legacy account this provider created: bind it to the
                # subject now, so the email alone never opens it again.
                # Re-read so a password change racing this login is not
                # overwritten with the copy read above.
                current = user_store.get(email, record)
                user_store[email] = {
                    **current,
                    "oauth_links": {
                        **(current.get("oauth_links") or {}),
                        provider: subject,
                    },
                }
        session_id = session_store.create(user_id=email, email=email)
        resp = JSONResponse({"ok": True, "email": email})
        _set_session_cookie(resp, session_id)
        return resp

    return router
