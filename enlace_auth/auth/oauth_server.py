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

Endpoints (mounted on the platform root, so they sit at the issuer origin)::

    GET  /.well-known/oauth-authorization-server   metadata (RFC 8414)
    GET  /auth/oauth/jwks                            signing public keys
    POST /auth/oauth/register                        dynamic client registration
    GET  /auth/oauth/authorize                        sign-in + consent → code
    POST /auth/oauth/authorize                        consent submit → code
    POST /auth/oauth/token                            code + PKCE → JWT
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, MutableMapping, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from enlace_auth.auth import pages
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.sessions import SessionStore

__all__ = ["OAuthKeys", "make_oauth_server_router"]

_CONSENT_SALT = "oauth-consent"  # CSRF token salt for the consent form
_SESSION_SALT = "session"  # must match make_auth_router's session-cookie salt


def _now() -> int:
    return int(time.time())


def _b64u(raw: bytes) -> str:
    """URL-safe base64 without padding (the PKCE / JOSE encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
    access_token_ttl: int = 3600,
    code_ttl: int = 120,
    scopes_supported: tuple[str, ...] = ("mcp:read",),
    require_consent: bool = True,
) -> APIRouter:
    """Build the OAuth 2.1 authorization-server router (see the module docstring).

    *issuer* pins the token ``iss`` and the discovery URLs; when ``None`` it is
    derived from each request's base URL (so the same code serves any domain). The
    consent step reuses the platform session — an unauthenticated ``/authorize``
    redirects to ``/auth/login`` and returns.
    """
    router = APIRouter(tags=["oauth-server"])

    def _issuer(request: Request) -> str:
        return (issuer or str(request.base_url)).rstrip("/")

    def _current_email(request: Request) -> Optional[str]:
        token = request.cookies.get(cookie_name)
        if not token:
            return None
        sid = verify_cookie(token, signing_key, max_age=session_max_age, salt=_SESSION_SALT)
        if not sid:
            return None
        session = session_store.get(sid)
        return session.get("email") if session else None

    def _redirect_error(redirect_uri: str, error: str, state: str, desc: str = "") -> RedirectResponse:
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
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes_supported": list(scopes_supported),
            }
        )

    @router.get("/auth/oauth/jwks", include_in_schema=False)
    async def jwks():
        return JSONResponse(keys.jwks())

    # ------------------------------------------------------------------ #
    # Dynamic client registration (RFC 7591)
    # ------------------------------------------------------------------ #
    @router.post("/auth/oauth/register", include_in_schema=False)
    async def register(request: Request):
        body = await request.json()
        redirect_uris = body.get("redirect_uris")
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": "redirect_uris required"},
                status_code=400,
            )
        client_id = secrets.token_urlsafe(24)
        record = {
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "client_name": body.get("client_name", ""),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",  # public client (PKCE)
            "created_at": _now(),
        }
        client_store[client_id] = record
        return JSONResponse(record, status_code=201)

    # ------------------------------------------------------------------ #
    # Authorization endpoint
    # ------------------------------------------------------------------ #
    def _validate_authorize(params) -> tuple[Optional[_Authorized], Optional[HTMLResponse]]:
        """Parse + validate /authorize params. Returns (ok, error_page)."""
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        client = client_store.get(client_id)
        if not client or redirect_uri not in client.get("redirect_uris", []):
            # Cannot safely redirect to an unverified URI — show an error page.
            return None, HTMLResponse(
                pages._page("Authorization error", "<p>Unknown client or redirect URI.</p>"),
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
            return _redirect_error(auth.redirect_uri, "unsupported_response_type", auth.state)
        if not auth.code_challenge or params.get("code_challenge_method") != "S256":
            return _redirect_error(
                auth.redirect_uri, "invalid_request", auth.state, "PKCE S256 required"
            )

        email = _current_email(request)
        if not email:
            # Reuse the platform login, returning here once authenticated.
            here = f"{request.url.path}?{request.url.query}"
            return RedirectResponse(f"/auth/login?{urlencode({'next': here})}", status_code=302)

        if not require_consent:
            code = _issue_code(auth, email)
            return RedirectResponse(
                f"{auth.redirect_uri}?{urlencode({'code': code, 'state': auth.state})}",
                status_code=302,
            )
        return HTMLResponse(_consent_page(request, auth, email, signing_key))

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
        auth = _Authorized(client_id, redirect_uri, code_challenge, state, scope, resource)
        if decision != "approve":
            return _redirect_error(redirect_uri, "access_denied", state)
        code = _issue_code(auth, email)
        return RedirectResponse(
            f"{redirect_uri}?{urlencode({'code': code, 'state': state})}", status_code=302
        )

    # ------------------------------------------------------------------ #
    # Token endpoint
    # ------------------------------------------------------------------ #
    @router.post("/auth/oauth/token", include_in_schema=False)
    async def token(
        request: Request,
        grant_type: str = Form(...),
        code: str = Form(...),
        redirect_uri: str = Form(...),
        client_id: str = Form(...),
        code_verifier: str = Form(...),
    ):
        if grant_type != "authorization_code":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        data = code_store.get(code)
        # One-time use: remove regardless of outcome.
        if data is not None:
            try:
                del code_store[code]
            except KeyError:
                pass
        if (
            data is None
            or data["exp"] < _now()
            or data["client_id"] != client_id
            or data["redirect_uri"] != redirect_uri
            or not _verify_pkce_s256(code_verifier, data["code_challenge"])
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)

        iss = _issuer(request)
        now = _now()
        claims = {
            "iss": iss,
            "sub": data["email"],
            "aud": data["resource"] or iss,
            "scope": data["scope"],
            "client_id": client_id,
            "iat": now,
            "exp": now + access_token_ttl,
            "jti": secrets.token_urlsafe(16),
        }
        return JSONResponse(
            {
                "access_token": keys.sign(claims),
                "token_type": "Bearer",
                "expires_in": access_token_ttl,
                "scope": data["scope"],
            }
        )

    return router


def _consent_page(request: Request, auth: _Authorized, email: str, signing_key: str) -> str:
    """Render the approve/deny consent form (reuses the shared page shell + CSRF)."""
    csrf = sign_cookie(email, signing_key, salt=_CONSENT_SALT)
    client = auth.client_id
    body = f"""
<h1>Authorize access</h1>
<p><strong>{client}</strong> is requesting access to your Trufflepig data as
<strong>{email}</strong>.</p>
<form method="post" action="/auth/oauth/authorize">
  <input type="hidden" name="client_id" value="{auth.client_id}">
  <input type="hidden" name="redirect_uri" value="{auth.redirect_uri}">
  <input type="hidden" name="code_challenge" value="{auth.code_challenge}">
  <input type="hidden" name="state" value="{auth.state}">
  <input type="hidden" name="scope" value="{auth.scope}">
  <input type="hidden" name="resource" value="{auth.resource}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny">Deny</button>
</form>
"""
    return pages._page("Authorize access", body)
