"""End-to-end tests for the MCP OAuth 2.1 authorization server."""

import base64
import hashlib
import secrets

import pytest

pytest.importorskip("authlib")
pytest.importorskip("multipart")  # FastAPI Form parsing needs python-multipart

from authlib.jose import JsonWebKey  # noqa: E402
from authlib.jose import jwt as jose_jwt
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from enlace_auth.auth.cookies import sign_cookie  # noqa: E402
from enlace_auth.auth.oauth_server import (  # noqa: E402
    OAuthKeys,
    make_oauth_server_router,
)
from enlace_auth.auth.sessions import SessionStore  # noqa: E402

SIGNING_KEY = "x" * 43
COOKIE = "enlace_session"
EMAIL = "owner@example.com"
REDIRECT = "https://claude.ai/api/mcp/callback"
# Two connectors on one authorization server — the situation the consent
# screen has to tell apart. Names are deliberately generic placeholders.
RESOURCE = "https://apps.example.com/connector-a-mcp"
OTHER_RESOURCE = "https://apps.example.com/connector-b-mcp"
UNMAPPED_RESOURCE = "https://apps.example.com/connector-c-mcp"
DISPLAY_NAMES = {RESOURCE: "Connector A", OTHER_RESOURCE: "Connector B"}
GENERIC_PROMPT = "requesting access to your data on this platform"


def _pkce():
    verifier = secrets.token_urlsafe(40)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def _build(
    tmp_path,
    *,
    require_consent=True,
    resource_allowlist=None,
    resource_display_names=None,
    email=EMAIL,
):
    session_store = SessionStore({})
    sid = session_store.create(user_id=email, email=email)
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
        resource_allowlist=resource_allowlist,
        resource_display_names=resource_display_names,
    )
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    session_cookie = sign_cookie(sid, SIGNING_KEY, salt="session")
    return client, session_cookie


def _register(client, redirect=REDIRECT) -> str:
    r = client.post("/auth/oauth/register", json={"redirect_uris": [redirect]})
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


def test_protected_resource_metadata_served_at_origin_root(tmp_path):
    # A connector behind a prefix-stripping proxy advertises this at the origin
    # root; the AS serves it for any resource path.
    client, _ = _build(tmp_path)
    r = client.get("/.well-known/oauth-protected-resource/api/connector_a_mcp/mcp")
    assert r.status_code == 200
    meta = r.json()
    assert meta["resource"] == "http://testserver/api/connector_a_mcp/mcp"
    assert meta["authorization_servers"] == ["http://testserver"]


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
        params={
            "response_type": "code",
            "client_id": "nope",
            "redirect_uri": REDIRECT,
            "code_challenge": "x",
            "code_challenge_method": "S256",
        },
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 400


def test_authorize_blank_client_id_is_clean_400_not_500(tmp_path):
    # Regression: a file-backed client_store resolves an empty client_id to its
    # root directory and raised IsADirectoryError (a 500). A blank/missing
    # client_id must short-circuit to the same clean 400 as an unknown client.
    client, cookie = _build(tmp_path)
    for cid in ("", None):
        params = {
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "code_challenge": "x",
            "code_challenge_method": "S256",
        }
        if cid is not None:
            params["client_id"] = cid
        r = client.get(
            "/auth/oauth/authorize",
            params=params,
            cookies={COOKIE: cookie},
            follow_redirects=False,
        )
        assert r.status_code == 400, f"client_id={cid!r} -> {r.status_code}"


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
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "state": "xyz",
        "scope": "mcp:read",
        "resource": RESOURCE,
        "csrf": csrf,
        "decision": "approve",
    }
    r = client.post(
        "/auth/oauth/authorize",
        data=form,
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith(REDIRECT) and "code=" in loc and "state=xyz" in loc
    code = loc.split("code=")[1].split("&")[0]

    # 3) token exchange (PKCE verifier) → JWT
    tok = client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": cid,
            "code_verifier": verifier,
        },
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
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": cid,
            "code_verifier": verifier,
        },
    )
    assert again.status_code == 400


def test_token_rejects_wrong_pkce_verifier(tmp_path):
    client, cookie = _build(tmp_path, require_consent=False)
    cid = _register(client)
    _, challenge = _pkce()
    params = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    r = client.get(
        "/auth/oauth/authorize",
        params=params,
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    tok = client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": cid,
            "code_verifier": "wrong-verifier",
        },
    )
    assert tok.status_code == 400
    assert tok.json()["error"] == "invalid_grant"


def _authorize_params(cid, challenge, *, resource=RESOURCE, redirect=REDIRECT):
    return {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": redirect,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": resource,
    }


def test_resource_allowlist_denies_unlisted_user(tmp_path):
    client, cookie = _build(tmp_path, resource_allowlist={RESOURCE: ["other@x.com"]})
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 403
    assert "Access denied" in r.text


def test_resource_allowlist_allows_listed_user(tmp_path):
    client, cookie = _build(tmp_path, resource_allowlist={RESOURCE: [EMAIL]})
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 200 and "Approve" in r.text


# --------------------------------------------------------------------------
# Consent-screen display name (one AS renders consent for every connector)
# --------------------------------------------------------------------------


def _consent_html(tmp_path, *, resource, display_names=DISPLAY_NAMES):
    client, cookie = _build(tmp_path, resource_display_names=display_names)
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge, resource=resource),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 200, r.text
    return r.text


@pytest.mark.parametrize(
    "resource, shown, hidden",
    [
        (RESOURCE, "Connector A", "Connector B"),
        (OTHER_RESOURCE, "Connector B", "Connector A"),
    ],
)
def test_consent_page_names_the_connector_being_authorized(
    tmp_path, resource, shown, hidden
):
    # Regression: the name was hard-coded, so every connector's consent screen
    # showed the first-built connector's name. Assert the *rendered* name, not
    # merely that a page renders — the latter passes with the bug present, which
    # is how it survived three connectors. Both directions matter: one name is
    # keyed on `resource`, and no *other* configured connector may leak into it.
    page = _consent_html(tmp_path, resource=resource)
    assert shown in page
    assert hidden not in page


def test_consent_page_uses_generic_copy_for_an_unmapped_resource(tmp_path):
    # No entry for this resource → generic copy that names no product. A default
    # naming any specific connector reintroduces the bug for the next one added.
    page = _consent_html(tmp_path, resource=UNMAPPED_RESOURCE)
    assert GENERIC_PROMPT in page
    for name in DISPLAY_NAMES.values():
        assert name not in page


def test_consent_page_names_nothing_when_no_display_names_configured(tmp_path):
    # The default configuration must be name-free, so a fresh platform cannot
    # ship one connector's name to another's users.
    page = _consent_html(tmp_path, resource=RESOURCE, display_names=None)
    assert GENERIC_PROMPT in page


@pytest.mark.parametrize(
    "config_key, requested",
    [
        (RESOURCE, RESOURCE + "/"),  # trailing slash on the request
        (RESOURCE + "/", RESOURCE),  # trailing slash in the config
        (RESOURCE + "/", RESOURCE + "/"),  # on both
    ],
)
def test_display_name_key_is_normalized_like_the_allowlist(
    tmp_path, config_key, requested
):
    # Both sides go through the same normalization resource_allowlist uses, so
    # one config entry can serve both and they cannot disagree about which
    # connector a request is for. A trailing slash on either side must not
    # silently drop the name back to the generic copy.
    page = _consent_html(
        tmp_path, resource=requested, display_names={config_key: "Connector A"}
    )
    assert "Connector A" in page
    assert GENERIC_PROMPT not in page


# --------------------------------------------------------------------------
# Consent-page escaping
# --------------------------------------------------------------------------

# An attribute-breakout marker: a double quote and a `<` are exactly the two
# characters that let a value escape a `value="..."` attribute and start a new
# tag. No payload — the assertion is that neither character survives raw.
BREAKOUT = '"><x'
BREAKOUT_ESCAPED = "&quot;&gt;&lt;x"


def _assert_escaped(page, field):
    assert BREAKOUT not in page, f"{field} reached the HTML unescaped"
    assert BREAKOUT_ESCAPED in page, f"{field} did not reach the page at all"


@pytest.mark.parametrize("field", ["state", "scope", "resource", "code_challenge"])
def test_consent_page_escapes_query_supplied_values(tmp_path, field):
    # /authorize copies these straight off the query string into hidden-input
    # attribute values, and any authenticated user can be sent to a crafted
    # authorize URL on the platform's own origin.
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    params = _authorize_params(cid, challenge)
    params["state"] = "s"
    params["scope"] = "mcp:read"
    params[field] = BREAKOUT
    r = client.get("/auth/oauth/authorize", params=params, cookies={COOKIE: cookie})
    assert r.status_code == 200, r.text
    _assert_escaped(r.text, field)


def test_consent_page_escapes_the_registered_redirect_uri(tmp_path):
    # redirect_uri must match the client's registration — but registration is
    # open (RFC 7591 DCR) and does not constrain the URI's contents.
    client, cookie = _build(tmp_path)
    hostile = f"https://example.invalid/cb{BREAKOUT}"
    cid = _register(client, redirect=hostile)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge, redirect=hostile),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 200, r.text
    _assert_escaped(r.text, "redirect_uri")


def test_consent_page_escapes_the_session_email(tmp_path):
    client, cookie = _build(tmp_path, email=f"a{BREAKOUT}@example.com")
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 200, r.text
    _assert_escaped(r.text, "email")


def test_consent_page_escapes_the_configured_display_name(tmp_path):
    page = _consent_html(
        tmp_path, resource=RESOURCE, display_names={RESOURCE: f"N{BREAKOUT}"}
    )
    _assert_escaped(page, "display_name")


def test_denied_page_escapes_the_session_email(tmp_path):
    email = f"a{BREAKOUT}@example.com"
    client, cookie = _build(
        tmp_path, email=email, resource_allowlist={RESOURCE: ["someone@example.com"]}
    )
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge),
        cookies={COOKIE: cookie},
    )
    assert r.status_code == 403
    _assert_escaped(r.text, "email")
