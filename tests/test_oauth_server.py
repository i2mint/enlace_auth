"""End-to-end tests for the MCP OAuth 2.1 authorization server."""

import base64
import hashlib
import secrets

import pytest

pytest.importorskip("authlib")
pytest.importorskip("multipart")  # FastAPI Form parsing needs python-multipart

from authlib.jose import JsonWebKey, jwt as jose_jwt  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from enlace_auth.auth.cookies import sign_cookie  # noqa: E402
from enlace_auth.auth.oauth_server import OAuthKeys, make_oauth_server_router  # noqa: E402
from enlace_auth.auth.sessions import SessionStore  # noqa: E402

SIGNING_KEY = "x" * 43
COOKIE = "enlace_session"
EMAIL = "owner@example.com"
REDIRECT = "https://claude.ai/api/mcp/callback"
RESOURCE = "https://apps.thorwhalen.com/trufflepig-mcp"


def _pkce():
    verifier = secrets.token_urlsafe(40)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _build(tmp_path, *, require_consent=True):
    session_store = SessionStore({})
    sid = session_store.create(user_id=EMAIL, email=EMAIL)
    router = make_oauth_server_router(
        session_store=session_store,
        signing_key=SIGNING_KEY,
        cookie_name=COOKIE,
        session_max_age=86400,
        client_store={},
        code_store={},
        keys=OAuthKeys(tmp_path / "keys"),
        issuer=None,  # derive from request → http://testserver
        require_consent=require_consent,
    )
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    session_cookie = sign_cookie(sid, SIGNING_KEY, salt="session")
    return client, session_cookie


def _register(client) -> str:
    r = client.post("/auth/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert r.status_code == 201
    return r.json()["client_id"]


def test_metadata_and_jwks(tmp_path):
    client, _ = _build(tmp_path)
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "http://testserver"
    assert meta["token_endpoint"] == "http://testserver/auth/oauth/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    jwks = client.get("/auth/oauth/jwks").json()
    assert jwks["keys"] and jwks["keys"][0]["kty"] == "RSA"


def test_register_requires_redirect_uris(tmp_path):
    client, _ = _build(tmp_path)
    assert client.post("/auth/oauth/register", json={}).status_code == 400


def test_authorize_redirects_to_login_when_unauthenticated(tmp_path):
    client, _ = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "xyz",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith("/auth/login?")


def test_authorize_rejects_unknown_client(tmp_path):
    client, cookie = _build(tmp_path)
    r = client.get(
        "/auth/oauth/authorize",
        params={"response_type": "code", "client_id": "nope", "redirect_uri": REDIRECT,
                "code_challenge": "x", "code_challenge_method": "S256"},
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_full_authorization_code_flow_with_consent(tmp_path):
    client, cookie = _build(tmp_path)
    cid = _register(client)
    verifier, challenge = _pkce()
    params = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "xyz",
        "scope": "mcp:read",
        "resource": RESOURCE,
    }
    # 1) authorize → consent page
    page = client.get("/auth/oauth/authorize", params=params, cookies={COOKIE: cookie})
    assert page.status_code == 200 and "Approve" in page.text

    # 2) consent approve → redirect carrying the code
    csrf = sign_cookie(EMAIL, SIGNING_KEY, salt="oauth-consent")
    form = {
        "client_id": cid, "redirect_uri": REDIRECT, "code_challenge": challenge,
        "state": "xyz", "scope": "mcp:read", "resource": RESOURCE,
        "csrf": csrf, "decision": "approve",
    }
    r = client.post(
        "/auth/oauth/authorize", data=form, cookies={COOKIE: cookie}, follow_redirects=False
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(REDIRECT) and "code=" in loc and "state=xyz" in loc
    code = loc.split("code=")[1].split("&")[0]

    # 3) token exchange (PKCE verifier) → JWT
    tok = client.post(
        "/auth/oauth/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
              "client_id": cid, "code_verifier": verifier},
    )
    assert tok.status_code == 200
    body = tok.json()
    assert body["token_type"] == "Bearer"

    # 4) the JWT validates against the published JWKS, with the right claims
    jwks = client.get("/auth/oauth/jwks").json()
    claims = jose_jwt.decode(body["access_token"], JsonWebKey.import_key_set(jwks))
    assert claims["sub"] == EMAIL
    assert claims["aud"] == RESOURCE
    assert claims["iss"] == "http://testserver"
    assert claims["scope"] == "mcp:read"

    # one-time use: replaying the code fails
    again = client.post(
        "/auth/oauth/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
              "client_id": cid, "code_verifier": verifier},
    )
    assert again.status_code == 400


def test_token_rejects_wrong_pkce_verifier(tmp_path):
    client, cookie = _build(tmp_path, require_consent=False)
    cid = _register(client)
    _, challenge = _pkce()
    params = {
        "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT,
        "code_challenge": challenge, "code_challenge_method": "S256", "resource": RESOURCE,
    }
    r = client.get(
        "/auth/oauth/authorize", params=params, cookies={COOKIE: cookie}, follow_redirects=False
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    tok = client.post(
        "/auth/oauth/token",
        data={"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
              "client_id": cid, "code_verifier": "wrong-verifier"},
    )
    assert tok.status_code == 400
    assert tok.json()["error"] == "invalid_grant"
