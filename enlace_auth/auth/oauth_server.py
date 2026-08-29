"""OAuth 2.1 authorization server — issue tokens for MCP custom connectors.

The companion to :mod:`enlace_auth.auth.oauth` (which is a login *client*, "sign in
with Google"). This module makes ``enlace_auth`` an authorization **server**: it
issues and signs the bearer tokens a Claude.ai custom connector — an OAuth
*resource server* — validates. It reuses the platform's existing user store and
session login, so a connector authenticates against the same accounts as the rest
of the platform.

The flow Claude.ai drives (OAuth 2.1 authorization-code + PKCE, RFC 7591 dynamic
client registration, RFC 8707 resource indicators):

1. The connector replies 401, pointing at its protected-resource metadata, which
   names this server as the authorization server.
2. The client discovers our endpoints via ``/.well-known/oauth-authorization-server``.
3. It registers itself (DCR) at ``/auth/oauth/register``.
4. ``GET /auth/oauth/authorize`` — the user signs in (reusing ``/auth/login``) and
   consents; we issue a short-lived, PKCE-bound authorization code.
5. ``POST /auth/oauth/token`` — the code + PKCE verifier is exchanged for a signed
   JWT whose ``aud`` is the connector (the ``resource`` parameter).
6. The connector's FastMCP ``JWTVerifier`` validates that JWT against
   ``/auth/oauth/jwks``.
7. Before the access token expires, the client exchanges its **refresh token**
   (``grant_type=refresh_token``) for a fresh pair — no browser, no human. This is
   what keeps a connector alive: without it an access token's expiry ends the
   session outright, and the only way back is for a person to re-run the whole
   browser authorization. See :func:`make_oauth_server_router` for the rotation and
   reuse-detection rules.

Endpoints (mounted on the platform root, so they sit at the issuer origin)::

    GET  /.well-known/oauth-authorization-server   metadata (RFC 8414)
    GET  /auth/oauth/jwks                            signing public keys
    POST /auth/oauth/register                        dynamic client registration
    GET  /auth/oauth/authorize                        sign-in + consent → code
    POST /auth/oauth/authorize                        consent submit → code
    POST /auth/oauth/token                            code + PKCE → JWT
                                                      refresh_token → JWT
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from enlace_auth.auth import pages
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.sessions import SessionStore
from enlace_auth.stores.validation import sanitize_key

_logger = logging.getLogger("enlace_auth")

__all__ = ["OAuthKeys", "make_oauth_server_router"]

_REFRESH_SALT = "oauth-refresh"  # domain separation for refresh-token hashing

_CONSENT_SALT = "oauth-consent"  # CSRF token salt for the consent form
_SESSION_SALT = "session"  # must match make_auth_router's session-cookie salt


def _now() -> int:
    return int(time.time())


def _b64u(raw: bytes) -> str:
    """URL-safe base64 without padding (the PKCE / JOSE encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hash_refresh(token: str) -> str:
    """Storage key for a refresh token — the token itself is never persisted.

    Refresh tokens are long-lived credentials. Storing them verbatim would make a
    read of the store (a backup, a stray ``cat``, a misconfigured store API) a
    credential dump. Hashing means the store holds only something that can
    *recognise* a token presented back to us, never mint one.
    """
    return hashlib.sha256(f"{_REFRESH_SALT}:{token}".encode()).hexdigest()


def _sweep_expired(
    store: MutableMapping[str, Any],
    *,
    now: int,
    limit: int = 500,
    cursor: Optional[dict] = None,
) -> int:
    """Drop expired records from *store*; return how many were removed.

    Both the authorization-code store and the refresh-token store are
    write-then-expire: nothing else ever deletes a record whose moment has passed.
    Without this, expired codes accumulate forever (they did in production) and —
    far worse once refresh tokens exist — the store grows an unbounded pile of
    credentials that are dead but still readable.

    Bounded by *limit* so a large store can never turn one token request into a
    long scan. *cursor* carries the position across calls and wraps at the end,
    so successive sweeps walk the whole store: the iteration order of a
    file-backed store is stable, and a fixed start would re-examine the same live
    prefix forever while expired records behind it were never reached.

    This is opportunistic housekeeping, not a correctness mechanism — expiry is
    enforced when a record is USED, never by whether it has been swept yet.
    """
    removed = 0
    # islice over the ITERATOR, never list(store): materialising every key
    # first pays the full O(n) directory walk on a request path regardless of
    # the limit, which is a denial-of-service handle on an unauthenticated
    # endpoint once the store is large.
    start = (cursor or {}).get("pos", 0)
    walked = 0
    for key in list(islice(iter(store), start, start + limit)):
        walked += 1
        try:
            record = store[key]
        except KeyError:  # concurrent delete — nothing to do
            continue
        exp = (record or {}).get("exp")
        if isinstance(exp, int) and exp <= now:
            try:
                del store[key]
                removed += 1
            except KeyError:
                pass
    if cursor is not None:
        # Short read means we reached the end; start over next time.
        cursor["pos"] = 0 if walked < limit else start + walked
    return removed


def _verify_pkce_s256(verifier: str, challenge: str) -> bool:
    """True iff ``BASE64URL(SHA256(verifier)) == challenge`` (PKCE S256, RFC 7636)."""
    expected = _b64u(hashlib.sha256(verifier.encode("ascii")).digest())
    return secrets.compare_digest(expected, challenge)


class OAuthKeys:
    """The server's RSA signing key — persisted, exposed as a JWKS.

    Generates a 2048-bit RSA key on first use under *key_dir* (``private_key.pem``,
    mode 0600) and reuses it thereafter, so tokens stay verifiable across restarts.
    Signs JWTs (RS256) and publishes the public half as a one-key JWKS for the
    connector's verifier to fetch.
    """

    def __init__(self, key_dir: str | Path):
        self._dir = Path(key_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pem_path = self._dir / "private_key.pem"
        self._pem = self._load_or_create()
        from authlib.jose import JsonWebKey

        self._jwk = JsonWebKey.import_key(self._pem)
        self.kid = self._jwk.thumbprint()

    def _load_or_create(self) -> bytes:
        if self._pem_path.exists():
            return self._pem_path.read_bytes()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._pem_path.write_bytes(pem)
        self._pem_path.chmod(0o600)
        return pem

    def jwks(self) -> dict[str, Any]:
        pub = self._jwk.as_dict(is_private=False)
        pub.update({"use": "sig", "alg": "RS256", "kid": self.kid})
        return {"keys": [pub]}

    def sign(self, claims: dict[str, Any]) -> str:
        from authlib.jose import jwt

        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        return jwt.encode(header, claims, self._pem).decode("ascii")


@dataclass
class _Authorized:
    """A validated /authorize request (params parsed, client + redirect checked)."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    state: str
    scope: str
    resource: str


def make_oauth_server_router(
    *,
    session_store: SessionStore,
    signing_key: str,
    cookie_name: str,
    session_max_age: int,
    client_store: MutableMapping[str, Any],
    code_store: MutableMapping[str, Any],
    keys: OAuthKeys,
    issuer: Optional[str] = None,
    refresh_store: MutableMapping[str, Any] | None = None,
    claim_once: Optional[Callable[[str], bool]] = None,
    release_claim: Optional[Callable[[str], None]] = None,
    is_active: Optional[Callable[[str], bool]] = None,
    access_token_ttl: int = 3600,
    refresh_token_ttl: int = 2592000,
    refresh_reuse_grace: int = 60,
    refresh_reuse_detection: int = 86400,
    refresh_family_max_lifetime: int = 7776000,
    client_ttl: int = 15552000,
    code_ttl: int = 120,
    scopes_supported: tuple[str, ...] = ("mcp:read",),
    require_consent: bool = True,
    resource_allowlist: Mapping[str, list[str]] | None = None,
    resource_display_names: Mapping[str, str] | None = None,
) -> APIRouter:
    """Build the OAuth 2.1 authorization-server router (see the module docstring).

    *issuer* pins the token ``iss`` and the discovery URLs; when ``None`` it is
    derived from each request's base URL (so the same code serves any domain). The
    consent step reuses the platform session — an unauthenticated ``/authorize``
    redirects to ``/auth/login`` and returns.

    *refresh_store* backs the ``refresh_token`` grant. Supply it and clients renew
    their own access tokens in the background, unattended; omit it and this server
    issues bare access tokens whose expiry silently ends the session, recoverable
    only by a human re-running the browser authorization. It is optional purely for
    backwards compatibility — **always pass it in a deployment**, and see
    :func:`enlace_auth.diagnostics.check_oauth_server` which reports its absence as
    a fault. Tokens are stored hashed (:func:`_hash_refresh`), never verbatim.

    Refresh tokens **rotate**: each use consumes the presented token and returns a
    new one. Consumption goes through *claim_once*, which must be atomic across
    PROCESSES — several workers share one store, and a plain read-then-write lets
    two concurrent redemptions both mint a live successor, which is precisely the
    double-spend rotation exists to detect.

    A spent token presented again is theft *unless* it looks like a retry. The
    token is consumed before the response is written, so a dropped response
    leaves an honest client holding a spent token; revoking there would strand
    the connector exactly as having no refresh grant does. Within
    *refresh_reuse_grace*, from the same client, with the successor still unused
    and the subject still authorized, it is reissued instead. Anything else
    revokes the whole family (OAuth 2.1 §4.3.1). Spent tokens are remembered for
    *refresh_reuse_detection* so a replay is recognised rather than merely
    unknown.

    *refresh_token_ttl* is an IDLE timeout that each rotation resets;
    *refresh_family_max_lifetime* is the absolute ceiling, fixed when the session
    is authorized. Both *resource_allowlist* and *is_active* are re-evaluated on
    every refresh — with no denylist and no revocation endpoint, they are the
    only way a session ends before its own expiry, which is why access tokens
    should stay short.

    *resource_allowlist* maps a connector resource URL to the emails permitted to
    authorize for it. A resource **not** in the map is open to any authenticated
    user (back-compatible); a resource that **is** in the map denies everyone
    else — per-connector access control (e.g. restrict a private connector to its
    own staff). Secure to key on the resource: the connector only accepts tokens
    whose ``aud`` is that exact resource, so a denied user can't get a usable token
    another way.

    *resource_display_names* maps the **same** resource URL to the human name the
    consent screen shows. One authorization server serves every connector on the
    platform, so this string must be per-connector: a name baked into the template
    is correct for one connector and wrong — and disclosing — for every other. A
    resource with no entry gets generic copy that names no product at all; never
    default to a specific connector's name, or the next connector added inherits
    it.
    """

    def _norm_resource(resource: str) -> str:
        """Canonical form of a resource URL — the shared key for both maps."""
        return (resource or "").rstrip("/")

    _allowlist = {
        _norm_resource(r): {e.lower() for e in emails}
        for r, emails in (resource_allowlist or {}).items()
    }
    _display_names = {
        _norm_resource(r): name for r, name in (resource_display_names or {}).items()
    }

    # One flag, consulted everywhere: a store with a zero TTL is NOT refresh
    # support, and metadata that says otherwise mints tokens dead on arrival.
    _refresh_enabled = refresh_store is not None and refresh_token_ttl > 0
    _local_claims: set[str] = set()
    _local_claim_lock = threading.Lock()
    _client_sweep_cursor: dict = {"pos": 0}
    _code_sweep_cursor: dict = {"pos": 0}
    _refresh_sweep_cursor: dict = {"pos": 0}

    def _resource_allowed(resource: str, email: str) -> bool:
        allowed = _allowlist.get(_norm_resource(resource))
        return allowed is None or email.lower() in allowed

    def _narrow_scope(requested: Optional[str]) -> str:
        """Intersect a requested scope with what this server actually supports.

        The value reaches us from a query string and ends up verbatim in a signed
        JWT, so an unfiltered scope lets any authenticated user mint a token
        claiming privileges the server never meant to grant.
        """
        if not requested:
            return " ".join(scopes_supported)
        granted = [s for s in requested.split() if s in scopes_supported]
        return " ".join(granted or scopes_supported)

    def _display_name(resource: str) -> Optional[str]:
        return _display_names.get(_norm_resource(resource))

    def _supported_grants() -> list[str]:
        """Grants this server can actually honour, in discovery-metadata form.

        Derived from ``_refresh_enabled`` rather than hardcoded, so metadata,
        dynamic client registration and the token endpoint cannot disagree about
        what is on offer — a disagreement is what let the previous DCR hand out
        a capability the token endpoint then refused.
        """
        grants = ["authorization_code"]
        if _refresh_enabled:
            grants.append("refresh_token")
        return grants

    def _revoke_family(family: str, *, reason: str) -> int:
        """Delete every refresh token descended from one authorization.

        Called when a spent token is replayed outside the retry window (presumed
        theft) or when the subject loses access. Costs a scan of the store, which
        is fine: it runs only on revocation, never on the happy path.

        Every record of the family goes, live successors included — that is the
        point. It is safe to be that blunt only because ambiguity is never read
        as theft: ``_rotate`` writes the tombstone before the successor exists,
        a worker that loses the claim refuses to treat an unconsumed record as a
        replay, and a tombstone whose successor is merely absent is refused
        rather than revoked.

        The scan is O(store), but it is reachable only by presenting a refresh
        token this server actually issued, and store size is bounded by
        *refresh_reuse_detection* (tombstones are swept past it), so it is not an
        amplification handle for an anonymous caller.

        This is the one event that silently ends a connector session, so it logs
        at WARNING — the original outage was invisible precisely because the only
        trace of a dead session was an INFO line on a different process.
        """
        if refresh_store is None:
            return 0
        revoked = 0
        for key in list(refresh_store):
            try:
                record = refresh_store[key]
            except KeyError:
                continue
            if (record or {}).get("family") != family:
                continue
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

    def _issue_refresh(
        *,
        family: str,
        client_id: str,
        resource: str,
        scope: str,
        email: str,
        family_exp: int,
        now: int,
    ) -> str:
        """Mint one refresh token and record its hash. Returns the plaintext.

        ``exp`` is an *idle* deadline that each successor resets; ``family_exp``
        is the absolute ceiling set once at authorization and carried unchanged
        through every rotation, so an actively-refreshing session still has to
        face a human eventually.
        """
        token = secrets.token_urlsafe(32)
        refresh_store[_hash_refresh(token)] = {
            "family": family,
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "email": email,
            "iat": now,
            "exp": now + refresh_token_ttl,
            "family_exp": family_exp,
            "consumed_at": None,
            "successor": None,
        }
        return token

    def _touch_client(client_id: str, now: int) -> None:
        """Extend a client registration's expiry because it is still in use."""
        record = client_store.get(client_id)
        if record:
            client_store[client_id] = {**record, "exp": now + client_ttl}

    def _grace_key(key: str) -> str:
        """Store key for the short-lived retry copy of a successor plaintext."""
        return f"grace:{key}"

    def _claim(key: str) -> bool:
        """Atomically take ownership of consuming *key*, exactly once.

        Rotation is a read-modify-write, and production runs two gunicorn worker
        PROCESSES over one shared store: without a cross-process claim, two
        concurrent redemptions both observe ``consumed_at is None``, both mint a
        live successor, and reuse detection — the entire point of rotation —
        never fires. The default below only guards one process, which is why
        ``plugin.py`` injects a filesystem-backed claim; a single-process
        library user or a test is served correctly by the default.
        """
        if claim_once is not None:
            return claim_once(key)
        with _local_claim_lock:
            if key in _local_claims:
                return False
            _local_claims.add(key)
            return True

    def _access_token(
        *, iss: str, email: str, resource: str, scope: str, client_id: str, now: int
    ) -> str:
        """Sign one access token. Single source of the claim set for both grants."""
        return keys.sign(
            {
                "iss": iss,
                "sub": email,
                "aud": resource or iss,
                "scope": scope,
                "client_id": client_id,
                "iat": now,
                "exp": now + access_token_ttl,
                "jti": secrets.token_urlsafe(16),
            }
        )

    router = APIRouter(tags=["oauth-server"])

    def _issuer(request: Request) -> str:
        return (issuer or str(request.base_url)).rstrip("/")

    def _current_email(request: Request) -> Optional[str]:
        token = request.cookies.get(cookie_name)
        if not token:
            return None
        sid = verify_cookie(
            token, signing_key, max_age=session_max_age, salt=_SESSION_SALT
        )
        if not sid:
            return None
        session = session_store.get(sid)
        return session.get("email") if session else None

    def _redirect_error(
        redirect_uri: str, error: str, state: str, desc: str = ""
    ) -> RedirectResponse:
        params = {"error": error, "state": state}
        if desc:
            params["error_description"] = desc
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    @router.get("/.well-known/oauth-authorization-server", include_in_schema=False)
    async def metadata(request: Request):
        iss = _issuer(request)
        return JSONResponse(
            {
                "issuer": iss,
                "authorization_endpoint": f"{iss}/auth/oauth/authorize",
                "token_endpoint": f"{iss}/auth/oauth/token",
                "registration_endpoint": f"{iss}/auth/oauth/register",
                "jwks_uri": f"{iss}/auth/oauth/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": _supported_grants(),
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": list(scopes_supported),
            }
        )

    @router.get("/auth/oauth/jwks", include_in_schema=False)
    async def jwks():
        return JSONResponse(keys.jwks())

    @router.get(
        "/.well-known/oauth-protected-resource/{resource_path:path}",
        include_in_schema=False,
    )
    async def protected_resource(resource_path: str, request: Request):
        """RFC 9728 protected-resource metadata, served at the platform origin.

        An MCP connector mounted on a sub-path behind a prefix-stripping reverse
        proxy advertises this metadata at the **origin root** (per RFC 9728) but
        cannot serve the origin root itself. The authorization server — which
        *does* own the root — serves it on the connector's behalf, naming itself
        as the resource's authorization server. Generic over ``resource_path`` so
        one handler covers every connector on the platform.
        """
        iss = _issuer(request)
        return JSONResponse(
            {
                "resource": f"{iss}/{resource_path}",
                "authorization_servers": [iss],
                "scopes_supported": list(scopes_supported),
                "bearer_methods_supported": ["header"],
            }
        )

    # ------------------------------------------------------------------ #
    # Dynamic client registration (RFC 7591)
    # ------------------------------------------------------------------ #
    @router.post("/auth/oauth/register", include_in_schema=False)
    async def register(request: Request):
        body = await request.json()
        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return JSONResponse(
                {
                    "error": "invalid_redirect_uri",
                    "error_description": "redirect_uris required",
                },
                status_code=400,
            )
        client_id = secrets.token_urlsafe(24)
        # Negotiate, never dictate: echo back the intersection of what the client
        # asked for with what we support. Hardcoding the reply told a client that
        # correctly requested refresh_token it had been granted authorization_code
        # only -- a 201 that looks like success while silently removing the very
        # capability that keeps the connector alive. A client that asks for nothing
        # gets everything we offer, which is what RFC 7591 defaults to anyway.
        supported = _supported_grants()
        requested = body.get("grant_types")
        if isinstance(requested, list) and requested:
            granted = [g for g in supported if g in requested]
        else:
            granted = list(supported)
        record = {
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "client_name": body.get("client_name", ""),
            "grant_types": granted or ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",  # public client (PKCE)
            "created_at": _now(),
        }
        # Registration is unauthenticated by design (RFC 7591 + how Claude.ai
        # connects), so without an expiry it is an anonymous, unbounded, never
        # reclaimed disk-write primitive. `exp` lets the same sweep that reaps
        # codes and tokens reclaim abandoned registrations; a client that keeps
        # being used has its expiry extended on every successful token exchange.
        client_store[client_id] = {**record, "exp": _now() + client_ttl}
        return JSONResponse(record, status_code=201)

    # ------------------------------------------------------------------ #
    # Authorization endpoint
    # ------------------------------------------------------------------ #
    def _validate_authorize(
        params,
    ) -> tuple[Optional[_Authorized], Optional[HTMLResponse]]:
        """Parse + validate /authorize params. Returns (ok, error_page)."""
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        # Guard the empty key explicitly: a file-backed client_store resolves an
        # empty client_id to its root directory and raises IsADirectoryError
        # (a 500) instead of returning None — so a missing/blank client_id must
        # short-circuit to the clean "unknown client" page below.
        client = client_store.get(client_id) if client_id else None
        if not client or redirect_uri not in client.get("redirect_uris", []):
            # Cannot safely redirect to an unverified URI — show an error page.
            return None, HTMLResponse(
                pages._page(
                    "Authorization error", "<p>Unknown client or redirect URI.</p>"
                ),
                status_code=400,
            )
        auth = _Authorized(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=params.get("code_challenge", ""),
            state=params.get("state", ""),
            # Never mint a token for a scope this server does not offer: the
            # value is attacker-controlled and lands verbatim in a signed JWT,
            # and the consent screen would show one scope while another was
            # submitted.
            scope=_narrow_scope(params.get("scope")),
            resource=params.get("resource", ""),
        )
        return auth, None

    def _issue_code(auth: _Authorized, email: str) -> str:
        code = secrets.token_urlsafe(32)
        code_store[code] = {
            "client_id": auth.client_id,
            "email": email,
            "redirect_uri": auth.redirect_uri,
            "code_challenge": auth.code_challenge,
            "scope": auth.scope,
            "resource": auth.resource,
            "exp": _now() + code_ttl,
        }
        return code

    @router.get("/auth/oauth/authorize", include_in_schema=False)
    async def authorize(request: Request):
        params = dict(request.query_params)
        auth, err = _validate_authorize(params)
        if err is not None:
            return err
        if params.get("response_type") != "code":
            return _redirect_error(
                auth.redirect_uri, "unsupported_response_type", auth.state
            )
        if not auth.code_challenge or params.get("code_challenge_method") != "S256":
            return _redirect_error(
                auth.redirect_uri, "invalid_request", auth.state, "PKCE S256 required"
            )

        email = _current_email(request)
        if not email:
            # Reuse the platform login, returning here once authenticated.
            here = f"{request.url.path}?{request.url.query}"
            return RedirectResponse(
                f"/auth/login?{urlencode({'next': here})}", status_code=302
            )

        if not _resource_allowed(auth.resource, email):
            return HTMLResponse(_denied_page(email), status_code=403)

        if not require_consent:
            code = _issue_code(auth, email)
            return RedirectResponse(
                f"{auth.redirect_uri}?{urlencode({'code': code, 'state': auth.state})}",
                status_code=302,
            )
        return HTMLResponse(
            _consent_page(
                auth, email, signing_key, display_name=_display_name(auth.resource)
            )
        )

    @router.post("/auth/oauth/authorize", include_in_schema=False)
    async def authorize_consent(
        request: Request,
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        code_challenge: str = Form(...),
        state: str = Form(""),
        scope: str = Form(""),
        resource: str = Form(""),
        csrf: str = Form(...),
        decision: str = Form(...),
    ):
        email = _current_email(request)
        if not email:
            return JSONResponse({"error": "login_required"}, status_code=401)
        # CSRF: the token is signed and bound to this user's session.
        if verify_cookie(csrf, signing_key, salt=_CONSENT_SALT) != email:
            return JSONResponse({"error": "invalid_csrf"}, status_code=403)
        auth, err = _validate_authorize(
            {"client_id": client_id, "redirect_uri": redirect_uri}
        )
        if err is not None:
            return err
        auth = _Authorized(
            client_id,
            redirect_uri,
            code_challenge,
            state,
            _narrow_scope(scope),
            resource,
        )
        if not _resource_allowed(resource, email):
            return _redirect_error(redirect_uri, "access_denied", state)
        if decision != "approve":
            return _redirect_error(redirect_uri, "access_denied", state)
        code = _issue_code(auth, email)
        return RedirectResponse(
            f"{redirect_uri}?{urlencode({'code': code, 'state': state})}",
            status_code=302,
        )

    # ------------------------------------------------------------------ #
    # Token endpoint
    # ------------------------------------------------------------------ #
    @router.post("/auth/oauth/token", include_in_schema=False)
    async def token(
        request: Request,
        grant_type: str = Form(...),
        client_id: str = Form(...),
        # Per-grant fields. Every one is Optional because FastAPI validates the
        # signature BEFORE the body of this function runs: declaring the
        # authorization_code fields as required would 422 every refresh request
        # before it could ever reach its branch.
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        refresh_token: Optional[str] = Form(None),
    ):
        now = _now()
        if grant_type not in ("authorization_code", "refresh_token"):
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

        if grant_type == "authorization_code":
            return _grant_authorization_code(
                request,
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                code_verifier=code_verifier,
                now=now,
            )
        if grant_type == "refresh_token" and _refresh_enabled:
            return _grant_refresh_token(
                request, refresh_token=refresh_token, client_id=client_id, now=now
            )
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    def _token_payload(
        *,
        iss: str,
        email: str,
        resource: str,
        scope: str,
        client_id: str,
        family: Optional[str],
        family_exp: int,
        now: int,
    ) -> tuple[dict, Optional[str]]:
        """Build the token payload for both grants — one shape, one place.

        Returns ``(body, refresh_plaintext)``; the plaintext is ``None`` when
        this server cannot honour a refresh, so a client is never handed a
        credential the token endpoint would reject. Callers get the successor
        back directly rather than re-parsing the response they just built.
        """
        body: dict[str, Any] = {
            "access_token": _access_token(
                iss=iss,
                email=email,
                resource=resource,
                scope=scope,
                client_id=client_id,
                now=now,
            ),
            "token_type": "Bearer",
            "expires_in": access_token_ttl,
            "scope": scope,
        }
        if not (_refresh_enabled and family is not None):
            return body, None
        plaintext = _issue_refresh(
            family=family,
            client_id=client_id,
            resource=resource,
            scope=scope,
            email=email,
            family_exp=family_exp,
            now=now,
        )
        body["refresh_token"] = plaintext
        return body, plaintext

    def _grant_authorization_code(
        request: Request,
        *,
        code: Optional[str],
        redirect_uri: Optional[str],
        client_id: str,
        code_verifier: Optional[str],
        now: int,
    ) -> JSONResponse:
        if not code or not redirect_uri or not code_verifier:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        try:
            # `code` is an attacker-controlled form field used directly as a
            # store key, i.e. a filesystem path component. The store guards this
            # too; rejecting here turns a hostile key into a clean invalid_grant
            # rather than relying on the backend's exception type.
            code = sanitize_key(code)
        except ValueError:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        data = code_store.get(code)
        # One-time use: remove regardless of outcome.
        if data is not None:
            try:
                del code_store[code]
            except KeyError:
                pass
        if (
            data is None
            or data["exp"] < now
            or data["client_id"] != client_id
            or data["redirect_uri"] != redirect_uri
            or not _verify_pkce_s256(code_verifier, data["code_challenge"])
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        body, _ = _token_payload(
            iss=_issuer(request),
            email=data["email"],
            resource=data["resource"],
            scope=data["scope"],
            client_id=client_id,
            # A fresh authorization starts a new family; every token that descends
            # from it is revoked together if one of them is ever replayed.
            family=secrets.token_urlsafe(16),
            family_exp=now + refresh_family_max_lifetime,
            now=now,
        )
        # Housekeeping on a path that required a valid authorization code, not on
        # one an anonymous caller can reach.
        _touch_client(client_id, now)
        _sweep_expired(client_store, now=now, cursor=_client_sweep_cursor)
        _sweep_expired(code_store, now=now, cursor=_code_sweep_cursor)
        if _refresh_enabled:
            _sweep_expired(refresh_store, now=now, cursor=_refresh_sweep_cursor)
        return JSONResponse(body)

    def _grant_refresh_token(
        request: Request,
        *,
        refresh_token: Optional[str],
        client_id: str,
        now: int,
    ) -> JSONResponse:
        if not refresh_token:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        key = _hash_refresh(refresh_token)  # already hex, safe as a store key
        record = refresh_store.get(key)
        if record is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if record.get("consumed_at") is not None:
            return _replayed(
                request, key=key, record=record, client_id=client_id, now=now
            )

        family = record.get("family")

        # Absolute ceiling. `exp` is an idle timeout that every rotation resets,
        # so without this a continuously-refreshing session would never once face
        # a human again.
        family_exp = record.get("family_exp") or 0
        if family_exp and family_exp <= now:
            _revoke_family(family, reason="family reached its absolute lifetime")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if record.get("exp", 0) <= now:
            try:
                del refresh_store[key]
            except KeyError:
                pass
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Bound to the client it was issued to: a token lifted from one client
        # cannot be redeemed by another.
        if record.get("client_id") != client_id:
            _revoke_family(family, reason="presented by a different client_id")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Re-check authorization on EVERY refresh. Access tokens are
        # self-contained JWTs with no denylist, so these checks are the only way
        # a session can be ended before its own expiry.
        email = record.get("email", "")
        resource = record.get("resource", "")
        if not _resource_allowed(resource, email):
            _revoke_family(family, reason="subject no longer on the resource allowlist")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if is_active is not None and not is_active(email):
            _revoke_family(family, reason="subject no longer has an active account")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Consume atomically or not at all -- see _claim.
        if not _claim(key):
            # Another worker is mid-rotation on this exact token. That is NOT a
            # replay: its tombstone may not be written yet, and revoking here
            # would delete the successor the winner is about to hand back.
            current = refresh_store.get(key)
            if current is None or current.get("consumed_at") is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return _replayed(
                request, key=key, record=current, client_id=client_id, now=now
            )

        try:
            return _rotate(
                request, key=key, record=record, client_id=client_id, now=now
            )
        except BaseException:
            # Give the claim back. Holding it after a failed rotation makes the
            # token permanently unredeemable while its record still says
            # unconsumed -- the connector is dead and nothing explains why.
            if release_claim is not None:
                try:
                    release_claim(key)
                except Exception:  # noqa: BLE001 - never mask the real error
                    pass
            _logger.warning(
                "oauth: rotation failed for family %s; claim released",
                record.get("family"),
            )
            raise

    def _rotate(
        request: Request,
        *,
        key: str,
        record: dict,
        client_id: str,
        now: int,
    ) -> JSONResponse:
        """Consume *record*, mint its successor, and answer with the new pair.

        ORDER MATTERS. The tombstone is written before the successor record
        exists, so no concurrent reader can ever observe this token as claimed
        but unconsumed. Writing the successor first opened a window in which the
        losing worker saw ``consumed_at is None``, concluded "replay", and
        revoked the family -- destroying the successor the winner was about to
        return, and stranding the connector exactly as an absent refresh grant
        does.
        """
        family = record.get("family")
        family_exp = record.get("family_exp") or (now + refresh_family_max_lifetime)
        email = record.get("email", "")
        resource = record.get("resource", "")
        scope = record.get("scope", "")

        plaintext = secrets.token_urlsafe(32)
        successor_key = _hash_refresh(plaintext)

        # 1. Tombstone. A consumed record is kept only long enough to recognise a
        #    replay -- never its original 30-day exp, which would turn every
        #    rotation into a dead record retained for a month.
        refresh_store[key] = {
            **record,
            "consumed_at": now,
            "successor": successor_key,
            "exp": now + max(refresh_reuse_grace, refresh_reuse_detection),
        }
        # 2. A short-lived copy of the successor plaintext, so a retry can hand
        #    back the SAME credential instead of minting a replacement and
        #    deleting one that is already on the wire. Its own record so it is
        #    swept after the grace window rather than living as long as the
        #    tombstone -- a plaintext credential at rest for 24h would defeat the
        #    point of hashing the store.
        if refresh_reuse_grace > 0:
            refresh_store[_grace_key(key)] = {
                "plaintext": plaintext,
                "family": family,
                "exp": now + refresh_reuse_grace,
            }
        # 3. Then the successor it points at.
        refresh_store[successor_key] = {
            "family": family,
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "email": email,
            "iat": now,
            "exp": now + refresh_token_ttl,
            "family_exp": family_exp,
            "consumed_at": None,
            "successor": None,
        }
        # Opportunistic garbage collection, on a path that required a real
        # credential to reach. Sweeping before dispatch made housekeeping
        # something an anonymous caller could buy on the shared event loop.
        _touch_client(client_id, now)
        _sweep_expired(client_store, now=now, cursor=_client_sweep_cursor)
        _sweep_expired(code_store, now=now, cursor=_code_sweep_cursor)
        _sweep_expired(refresh_store, now=now, cursor=_refresh_sweep_cursor)
        _logger.info(
            "oauth: refreshed session for %s on %s (family %s)", email, resource, family
        )
        return JSONResponse(
            {
                "access_token": _access_token(
                    iss=_issuer(request),
                    email=email,
                    resource=resource,
                    scope=scope,
                    client_id=client_id,
                    now=now,
                ),
                "token_type": "Bearer",
                "expires_in": access_token_ttl,
                "scope": scope,
                "refresh_token": plaintext,
            }
        )

    def _replayed(
        request: Request,
        *,
        key: str,
        record: dict,
        client_id: str,
        now: int,
    ) -> JSONResponse:
        """Answer a re-presented token: replay the same result, or call it theft.

        A retry is served IDEMPOTENTLY — it hands back the successor the first
        attempt already returned, and destroys nothing. An earlier version minted
        a replacement and deleted the previous successor, which meant duplicate
        requests each invalidated the one before: every response carried a 200
        with a refresh token the server had already deleted, and a client that
        kept any but the last was stranded. Deleting also raced the legitimate
        client consuming that successor, forking the family into two live tokens
        with no tombstone left to link them — blinding reuse detection entirely.

        Revocation needs POSITIVE evidence of theft, and only two things qualify:
        presentation outside the retry window, or by a different client. Anything
        ambiguous is refused with a plain 400 that costs the client nothing —
        notably a successor that has already been consumed, which proves the
        client moved on and therefore *has* a working credential, and a successor
        not yet written, which is just a rotation in flight.

        ACCEPTED TRADE-OFF: inside the window a thief using the same client_id is
        indistinguishable from an honest retry, and is handed the successor the
        client already holds. It cannot evict the client or fork the family, and
        detection resumes the moment the window closes. Shrinking
        *refresh_reuse_grace* narrows it; zero closes it and restores the failure
        this exists to prevent, where one dropped response costs a manual
        re-authorization.
        """
        family = record.get("family")
        within_grace = now - (record.get("consumed_at") or 0) < refresh_reuse_grace
        same_client = record.get("client_id") == client_id

        if not within_grace or not same_client:
            _revoke_family(family, reason="a spent refresh token was replayed")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # The absolute ceiling binds here too, or the retry path would be an
        # indefinite bypass of it.
        family_exp = record.get("family_exp") or 0
        if family_exp and family_exp <= now:
            _revoke_family(family, reason="family reached its absolute lifetime")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # A retry is still a refresh: same authorization gates, or revoking
        # someone would be defeated by them simply retrying.
        email = record.get("email", "")
        resource = record.get("resource", "")
        if not _resource_allowed(resource, email):
            _revoke_family(family, reason="subject no longer on the resource allowlist")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if is_active is not None and not is_active(email):
            _revoke_family(family, reason="subject no longer has an active account")
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        successor_key = record.get("successor")
        successor = refresh_store.get(successor_key) if successor_key else None
        parked = refresh_store.get(_grace_key(key))

        if (
            successor is None
            or successor.get("consumed_at") is not None
            or not parked
            or not parked.get("plaintext")
        ):
            # Rotation still in flight, the client already moved on, or the retry
            # window has lapsed. None of these is theft, and none of them costs
            # the client anything it does not already have.
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        _logger.info(
            "oauth: replaying the refresh response for family %s "
            "(previous response presumed lost)",
            family,
        )
        return JSONResponse(
            {
                "access_token": _access_token(
                    iss=_issuer(request),
                    email=email,
                    resource=resource,
                    scope=record.get("scope", ""),
                    client_id=client_id,
                    now=now,
                ),
                "token_type": "Bearer",
                "expires_in": access_token_ttl,
                "scope": record.get("scope", ""),
                "refresh_token": parked["plaintext"],
            }
        )

    return router


# ---------------------------------------------------------------------- #
# Browser-facing pages
#
# Every template below is static markup whose values are filled in by
# ``pages.fill_template``, which HTML-escapes them. These pages interpolate
# values taken straight off the query string (``state``, ``scope``,
# ``resource``, ``code_challenge``) and off an openly-registerable client
# record (``redirect_uri``) into attribute values, so escaping is not optional;
# ``pages._page`` escapes the page *title* only. Compose a page from several
# filled fragments — never leave an un-escaped hole in a template.
# ---------------------------------------------------------------------- #

_DENIED_BODY = (
    "<h1>Access denied</h1><p><strong>{email}</strong> is not authorized to "
    "use this connector. Contact the connector owner if you believe this is "
    "a mistake.</p>"
)

# Named vs generic consent copy. The generic form is what a resource with no
# configured display name gets: it names no product, because this one server
# renders the consent screen for every connector on the platform.
_CONSENT_PROMPT_NAMED = (
    "<p><strong>{client}</strong> is requesting access to your "
    "<strong>{connector}</strong> data as <strong>{email}</strong>.</p>"
)
_CONSENT_PROMPT_GENERIC = (
    "<p><strong>{client}</strong> is requesting access to your data on this "
    "platform as <strong>{email}</strong>.</p>"
)

_CONSENT_FORM = """<form method="post" action="/auth/oauth/authorize">
  <input type="hidden" name="client_id" value="{client_id}">
  <input type="hidden" name="redirect_uri" value="{redirect_uri}">
  <input type="hidden" name="code_challenge" value="{code_challenge}">
  <input type="hidden" name="state" value="{state}">
  <input type="hidden" name="scope" value="{scope}">
  <input type="hidden" name="resource" value="{resource}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>"""


def _denied_page(email: str) -> str:
    """Render the 'not authorized for this connector' page (allowlist denial)."""
    return pages._page("Access denied", pages.fill_template(_DENIED_BODY, email=email))


def _consent_page(
    auth: _Authorized,
    email: str,
    signing_key: str,
    *,
    display_name: Optional[str] = None,
) -> str:
    """Render the approve/deny consent form (reuses the shared page shell + CSRF).

    *display_name* is the connector's human name, resolved from the request's
    ``resource``. When it is ``None`` the prompt falls back to generic copy —
    naming a specific connector here would show that name to everyone
    authorizing any *other* connector on the same platform.
    """
    csrf = sign_cookie(email, signing_key, salt=_CONSENT_SALT)
    prompt = (
        pages.fill_template(
            _CONSENT_PROMPT_NAMED,
            client=auth.client_id,
            connector=display_name,
            email=email,
        )
        if display_name
        else pages.fill_template(
            _CONSENT_PROMPT_GENERIC, client=auth.client_id, email=email
        )
    )
    form = pages.fill_template(
        _CONSENT_FORM,
        client_id=auth.client_id,
        redirect_uri=auth.redirect_uri,
        code_challenge=auth.code_challenge,
        state=auth.state,
        scope=auth.scope,
        resource=auth.resource,
        csrf=csrf,
    )
    body = f"<h1>Authorize access</h1>\n{prompt}\n{form}\n"
    return pages._page("Authorize access", body)
