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
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from enlace_auth.auth import pages
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.sessions import SessionStore

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
    store: MutableMapping[str, Any], *, now: int, limit: int = 500
) -> int:
    """Drop expired records from *store*; return how many were removed.

    Both the authorization-code store and the refresh-token store are
    write-then-expire: nothing else ever deletes a record whose moment has passed.
    Without this, expired codes accumulate forever (they did in production) and —
    far worse once refresh tokens exist — the store grows an unbounded pile of
    credentials that are dead but still readable.

    Bounded by *limit* so a large store can never turn one token request into a
    long scan; the remainder is swept by subsequent calls.
    """
    removed = 0
    for key in list(store)[:limit]:
        try:
            record = store[key]
        except KeyError:  # concurrent delete — nothing to do
            continue
        exp = (record or {}).get("exp")
        if isinstance(exp, int) and exp < now:
            try:
                del store[key]
                removed += 1
            except KeyError:
                pass
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
    access_token_ttl: int = 3600,
    refresh_token_ttl: int = 2592000,
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
    new one. A consumed token presented a second time is treated as theft — the
    whole family (every token descended from one authorization) is revoked, per
    OAuth 2.1 §4.3.1. The allowlist is re-evaluated on every refresh, so removing
    someone from *resource_allowlist* takes effect within one access-token
    lifetime rather than one refresh-token lifetime; that is the only revocation
    path this server has, and long-lived refresh tokens make it load-bearing.

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

    def _resource_allowed(resource: str, email: str) -> bool:
        allowed = _allowlist.get(_norm_resource(resource))
        return allowed is None or email.lower() in allowed

    def _display_name(resource: str) -> Optional[str]:
        return _display_names.get(_norm_resource(resource))

    def _supported_grants() -> list[str]:
        """Grants this server can actually honour, in discovery-metadata form.

        Derived from whether a *refresh_store* was supplied rather than hardcoded,
        so metadata, dynamic client registration and the token endpoint can never
        disagree about what is on offer.
        """
        grants = ["authorization_code"]
        if refresh_store is not None:
            grants.append("refresh_token")
        return grants

    def _revoke_family(family: str) -> int:
        """Delete every refresh token descended from one authorization.

        Called when a consumed token is replayed (presumed theft) or when the user
        behind a family loses access. Costs a scan of the store, which is fine: it
        runs only on revocation, never on the happy path.
        """
        if refresh_store is None:
            return 0
        revoked = 0
        for key in list(refresh_store):
            try:
                record = refresh_store[key]
            except KeyError:
                continue
            if (record or {}).get("family") == family:
                try:
                    del refresh_store[key]
                    revoked += 1
                except KeyError:
                    pass
        return revoked

    def _issue_refresh(
        *, family: str, client_id: str, resource: str, scope: str, email: str, now: int
    ) -> str:
        """Mint one refresh token and record its hash. Returns the plaintext."""
        token = secrets.token_urlsafe(32)
        refresh_store[_hash_refresh(token)] = {
            "family": family,
            "client_id": client_id,
            "resource": resource,
            "scope": scope,
            "email": email,
            "iat": now,
            "exp": now + refresh_token_ttl,
            "consumed_at": None,
        }
        return token

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
        client_store[client_id] = record
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
            scope=params.get("scope", " ".join(scopes_supported)),
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
            client_id, redirect_uri, code_challenge, state, scope, resource
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
        # Opportunistic garbage collection. Nothing else ever removes an expired
        # record, and the refresh store holds credentials, so it must not grow
        # without bound.
        _sweep_expired(code_store, now=now)
        if refresh_store is not None:
            _sweep_expired(refresh_store, now=now)

        if grant_type == "authorization_code":
            return _grant_authorization_code(
                request,
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                code_verifier=code_verifier,
                now=now,
            )
        if grant_type == "refresh_token" and refresh_store is not None:
            return _grant_refresh_token(
                request, refresh_token=refresh_token, client_id=client_id, now=now
            )
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    def _token_response(
        *,
        iss: str,
        email: str,
        resource: str,
        scope: str,
        client_id: str,
        family: Optional[str],
        now: int,
    ) -> JSONResponse:
        """The token response for both grants — one shape, one place.

        A refresh token is included only when this server can honour one, so a
        client is never handed a credential the token endpoint would reject.
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
        if refresh_store is not None and family is not None:
            body["refresh_token"] = _issue_refresh(
                family=family,
                client_id=client_id,
                resource=resource,
                scope=scope,
                email=email,
                now=now,
            )
            body["refresh_expires_in"] = refresh_token_ttl
        return JSONResponse(body)

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

        return _token_response(
            iss=_issuer(request),
            email=data["email"],
            resource=data["resource"],
            scope=data["scope"],
            client_id=client_id,
            # A fresh authorization starts a new family; every token that descends
            # from it is revoked together if one of them is ever replayed.
            family=secrets.token_urlsafe(16),
            now=now,
        )

    def _grant_refresh_token(
        request: Request,
        *,
        refresh_token: Optional[str],
        client_id: str,
        now: int,
    ) -> JSONResponse:
        if not refresh_token:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        key = _hash_refresh(refresh_token)
        record = refresh_store.get(key)
        if record is None:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        family = record.get("family")

        # Replay of an already-consumed token. Either the client is buggy or the
        # token leaked; both mean the family can no longer be trusted, so revoke
        # all of it and force a fresh browser authorization (OAuth 2.1 4.3.1).
        if record.get("consumed_at") is not None:
            _revoke_family(family)
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        if record.get("exp", 0) < now:
            try:
                del refresh_store[key]
            except KeyError:
                pass
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Bound to the client it was issued to: a token lifted from one client
        # cannot be redeemed by another.
        if record.get("client_id") != client_id:
            _revoke_family(family)
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Re-check the allowlist on EVERY refresh. Without this an access-token TTL
        # stops being the revocation window and a refresh-token TTL becomes it:
        # removing someone from resource_allowlist would leave them working for up
        # to refresh_token_ttl, turning a guest invitation into standing access.
        email = record.get("email", "")
        resource = record.get("resource", "")
        if not _resource_allowed(resource, email):
            _revoke_family(family)
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        # Rotate: consume this token, hand back a successor in the same family.
        record["consumed_at"] = now
        refresh_store[key] = record

        return _token_response(
            iss=_issuer(request),
            email=email,
            resource=resource,
            scope=record.get("scope", ""),
            client_id=client_id,
            family=family,
            now=now,
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
