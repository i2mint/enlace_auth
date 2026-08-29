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
    _hash_refresh,
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
    refresh_store=None,
    refresh_token_ttl=2592000,
    code_store=None,
    client_store=None,
    claim_once=None,
    release_claim=None,
    is_active=None,
    refresh_reuse_grace=60,
    refresh_reuse_detection=86400,
    refresh_family_max_lifetime=7776000,
):
    session_store = SessionStore({})
    sid = session_store.create(user_id=email, email=email)
    router = make_oauth_server_router(
        session_store=session_store,
        signing_key=SIGNING_KEY,
        cookie_name=COOKIE,
        session_max_age=86400,
        client_store={} if client_store is None else client_store,
        code_store={} if code_store is None else code_store,
        refresh_store=refresh_store,
        claim_once=claim_once,
        release_claim=release_claim,
        is_active=is_active,
        refresh_reuse_grace=refresh_reuse_grace,
        refresh_reuse_detection=refresh_reuse_detection,
        refresh_family_max_lifetime=refresh_family_max_lifetime,
        keys=OAuthKeys(tmp_path / "keys"),
        issuer=None,  # derive from request → http://testserver
        require_consent=require_consent,
        refresh_token_ttl=refresh_token_ttl,
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


@pytest.mark.parametrize("field", ["state", "resource", "code_challenge"])
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


def test_a_hostile_scope_never_reaches_the_consent_page(tmp_path):
    """Scope is narrowed to what the server supports, so it cannot carry a payload.

    Stronger than escaping: an unsupported scope is dropped outright, which also
    stops a crafted URL from displaying one scope while submitting another.
    """
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    params = _authorize_params(cid, challenge)
    params["scope"] = BREAKOUT
    r = client.get("/auth/oauth/authorize", params=params, cookies={COOKIE: cookie})
    assert r.status_code == 200
    assert BREAKOUT not in r.text


def test_a_token_cannot_carry_an_unsupported_scope(tmp_path):
    client, cookie = _build(tmp_path, refresh_store={})
    cid = _register(client)
    body = _flow(client, cookie, cid=cid, scope="mcp:read mcp:admin")
    jwks = client.get("/auth/oauth/jwks").json()
    claims = jose_jwt.decode(body["access_token"], JsonWebKey.import_key_set(jwks))
    assert "mcp:admin" not in claims["scope"]
    assert claims["scope"] == "mcp:read"


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


# ---------------------------------------------------------------------- #
# Refresh-token grant
#
# Without these, an access token's expiry ends a connector session outright and
# only a human at a browser can restore it. Production ran that way: sessions
# died on the hour and the connector looked "down all day".
# ---------------------------------------------------------------------- #


def _flow(client, cookie, *, cid, resource=RESOURCE, scope="mcp:read"):
    """Drive authorize → consent → token once; return the token response body."""
    verifier, challenge = _pkce()
    form = {
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "state": "xyz",
        "scope": scope,
        "resource": resource,
        "csrf": sign_cookie(EMAIL, SIGNING_KEY, salt="oauth-consent"),
        "decision": "approve",
    }
    r = client.post(
        "/auth/oauth/authorize",
        data=form,
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    code = r.headers["location"].split("code=")[1].split("&")[0]
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
    assert tok.status_code == 200, tok.text
    return tok.json()


def _now_ish():
    import time

    return int(time.time())


def _live(store):
    """Refresh tokens that can still be redeemed.

    The store also holds tombstones (consumed_at set) and the short-lived grace
    records that let a retry replay its response; neither is a usable token.
    """
    return [
        v
        for v in store.values()
        if v.get("client_id") is not None and v.get("consumed_at") is None
    ]


def _refresh(client, token, cid):
    return client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token,
            "client_id": cid,
        },
    )


def test_metadata_advertises_refresh_only_when_it_can_honour_it(tmp_path):
    without, _ = _build(tmp_path)
    assert without.get("/.well-known/oauth-authorization-server").json()[
        "grant_types_supported"
    ] == ["authorization_code"]

    with_store, _ = _build(tmp_path, refresh_store={})
    assert with_store.get("/.well-known/oauth-authorization-server").json()[
        "grant_types_supported"
    ] == ["authorization_code", "refresh_token"]


def test_registration_echoes_the_grants_the_client_asked_for(tmp_path):
    """DCR used to reply "authorization_code" no matter what was requested."""
    client, _ = _build(tmp_path, refresh_store={})
    r = client.post(
        "/auth/oauth/register",
        json={
            "redirect_uris": [REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )
    assert r.status_code == 201
    assert r.json()["grant_types"] == ["authorization_code", "refresh_token"]


def test_registration_never_grants_what_the_server_cannot_do(tmp_path):
    client, _ = _build(tmp_path)  # no refresh store
    r = client.post(
        "/auth/oauth/register",
        json={
            "redirect_uris": [REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
        },
    )
    assert r.json()["grant_types"] == ["authorization_code"]


def test_registration_without_grant_types_gets_everything_supported(tmp_path):
    client, _ = _build(tmp_path, refresh_store={})
    r = client.post("/auth/oauth/register", json={"redirect_uris": [REDIRECT]})
    assert r.json()["grant_types"] == ["authorization_code", "refresh_token"]


def test_authorization_code_grant_returns_a_refresh_token(tmp_path):
    client, cookie = _build(tmp_path, refresh_store={})
    body = _flow(client, cookie, cid=_register(client))
    assert body["refresh_token"]
    # Only RFC 6749 fields — no invented "refresh_expires_in" for a strict
    # client to trip over.
    assert set(body) == {
        "access_token",
        "token_type",
        "expires_in",
        "scope",
        "refresh_token",
    }


def test_response_shape_is_unchanged_when_refresh_is_disabled(tmp_path):
    """Regression guard: four live connectors depend on this exact shape."""
    client, cookie = _build(tmp_path)
    body = _flow(client, cookie, cid=_register(client))
    assert set(body) == {"access_token", "token_type", "expires_in", "scope"}


def test_refresh_mints_a_working_access_token_with_the_same_identity(tmp_path):
    client, cookie = _build(tmp_path, refresh_store={})
    cid = _register(client)
    first = _flow(client, cookie, cid=cid)

    r = _refresh(client, first["refresh_token"], cid)
    assert r.status_code == 200
    body = r.json()

    jwks = client.get("/auth/oauth/jwks").json()
    claims = jose_jwt.decode(body["access_token"], JsonWebKey.import_key_set(jwks))
    assert claims["sub"] == EMAIL
    assert claims["aud"] == RESOURCE  # audience binding survives refresh
    assert claims["scope"] == "mcp:read"
    assert claims["client_id"] == cid


def test_refresh_rotates_and_the_spent_token_stops_working(tmp_path):
    client, cookie = _build(tmp_path, refresh_store={})
    cid = _register(client)
    first = _flow(client, cookie, cid=cid)

    second = _refresh(client, first["refresh_token"], cid).json()
    assert second["refresh_token"] != first["refresh_token"]
    # the successor works...
    assert _refresh(client, second["refresh_token"], cid).status_code == 200
    # ...and the token it replaced does not
    assert _refresh(client, first["refresh_token"], cid).status_code == 400


def test_replay_by_a_different_client_revokes_the_whole_family(tmp_path):
    """Positive evidence of theft: nobody else should ever hold this token.

    (The other positive evidence -- replay outside the retry window -- is covered
    by test_replay_after_the_grace_window_still_revokes. Inside the window, from
    the same client, a replay is indistinguishable from an honest retry and is
    answered idempotently instead; revoking there killed healthy sessions.)
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    thief = _register(client)
    first = _flow(client, cookie, cid=cid)
    second = _refresh(client, first["refresh_token"], cid).json()

    assert _refresh(client, second["refresh_token"], thief).status_code == 400
    # The legitimate holder's live token is dead too -- by design.
    assert _refresh(client, second["refresh_token"], cid).status_code == 400
    assert _live(store) == []


def test_refresh_token_from_one_client_cannot_be_redeemed_by_another(tmp_path):
    client, cookie = _build(tmp_path, refresh_store={})
    cid = _register(client)
    other = _register(client)
    body = _flow(client, cookie, cid=cid)
    assert _refresh(client, body["refresh_token"], other).status_code == 400
    # and the family is burned, so the rightful client must re-authorize
    assert _refresh(client, body["refresh_token"], cid).status_code == 400


def test_expired_refresh_token_is_rejected_and_dropped(tmp_path):
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    # Age the stored record past its expiry (no sleeping in tests).
    (key,) = list(store)
    store[key] = {**store[key], "exp": 1}
    assert _refresh(client, body["refresh_token"], cid).status_code == 400
    assert _live(store) == []  # and the dead record is not left behind


def test_refresh_re_evaluates_the_allowlist(tmp_path):
    """Removing someone must bite within an access-token life, not a refresh one.

    This is the only revocation path the server has: tokens are self-contained
    JWTs with no denylist and there is no revocation endpoint. If refresh skipped
    the allowlist, a removed user would keep minting working tokens for a whole
    refresh TTL — a guest invitation would quietly become standing access.

    The allowlist is read from config when the router is built, so "remove a user"
    means redeploy: a second router over the SAME stores, which is exactly what a
    backend restart produces.
    """
    refresh_store, client_store = {}, {}
    allowed, cookie = _build(
        tmp_path,
        refresh_store=refresh_store,
        client_store=client_store,
        resource_allowlist={RESOURCE: [EMAIL]},
    )
    cid = _register(allowed)
    body = _flow(allowed, cookie, cid=cid)
    rotated = _refresh(allowed, body["refresh_token"], cid)
    assert rotated.status_code == 200
    held = rotated.json()["refresh_token"]  # the live token the client now holds

    revoked, _ = _build(
        tmp_path,
        refresh_store=refresh_store,
        client_store=client_store,
        resource_allowlist={RESOURCE: []},  # user removed from the connector
    )
    r = revoked.post(
        "/auth/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": held,
            "client_id": cid,
        },
    )
    assert r.status_code == 400
    assert _live(refresh_store) == []  # family burned, not merely this token


def test_refresh_is_unsupported_when_no_store_is_configured(tmp_path):
    client, cookie = _build(tmp_path)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    assert "refresh_token" not in body
    r = _refresh(client, "anything", cid)
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"


def test_refresh_tokens_are_never_stored_verbatim(tmp_path):
    """A read of the store must not yield a usable credential."""
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    plaintext = body["refresh_token"]
    assert plaintext not in store
    assert not any(plaintext in str(v) for v in store.values())


def test_missing_grant_fields_are_a_clean_400(tmp_path):
    """Optional Form fields must not turn a bad request into a 422."""
    client, _ = _build(tmp_path, refresh_store={})
    cid = _register(client)
    r = client.post(
        "/auth/oauth/token", data={"grant_type": "authorization_code", "client_id": cid}
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"
    r = client.post(
        "/auth/oauth/token", data={"grant_type": "refresh_token", "client_id": cid}
    )
    assert r.status_code == 400 and r.json()["error"] == "invalid_request"


def test_expired_authorization_codes_are_swept(tmp_path):
    """Nothing else deletes them; production had codes days past a 120s TTL."""
    codes = {}
    client, cookie = _build(tmp_path, code_store=codes, refresh_store={})
    cid = _register(client)
    codes["stale"] = {"exp": 1, "client_id": cid}
    _flow(client, cookie, cid=cid)  # any token call sweeps
    assert "stale" not in codes


# ---------------------------------------------------------------------- #
# Failure modes found by adversarial review of the first cut
# ---------------------------------------------------------------------- #


def test_a_lost_token_response_does_not_strand_the_connector(tmp_path):
    """The regression that would have recreated the original outage.

    The server consumes the presented token before its response is written, so a
    dropped response (proxy 502, TLS reset, client timeout) leaves an honest
    client holding a spent token. Revoking the family there means a human has to
    re-authorize — exactly the failure this grant exists to remove.
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)

    lost = _refresh(client, body["refresh_token"], cid)  # response never arrives
    assert lost.status_code == 200

    retry = _refresh(client, body["refresh_token"], cid)  # client retries
    assert retry.status_code == 200, "an honest retry must not strand the client"
    # IDEMPOTENT: the retry replays the same credential rather than minting a
    # replacement and deleting one that may already be on the wire.
    assert retry.json()["refresh_token"] == lost.json()["refresh_token"]
    assert len(_live(store)) == 1
    # Both responses name the same token, and it works.
    assert _refresh(client, retry.json()["refresh_token"], cid).status_code == 200


def test_replay_after_the_grace_window_still_revokes(tmp_path):
    # Detection is unchanged outside the retry window: that is where the
    # positive evidence of theft lives.
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store, refresh_reuse_grace=0)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    second = _refresh(client, body["refresh_token"], cid).json()
    assert _refresh(client, body["refresh_token"], cid).status_code == 400
    assert _refresh(client, second["refresh_token"], cid).status_code == 400
    assert _live(store) == []


def test_a_family_cannot_outlive_its_absolute_ceiling(tmp_path):
    """`exp` is an idle timeout every rotation resets; this is the hard stop."""
    store = {}
    client, cookie = _build(
        tmp_path, refresh_store=store, refresh_family_max_lifetime=0
    )
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    assert _refresh(client, body["refresh_token"], cid).status_code == 400
    assert _live(store) == []


def test_family_ceiling_survives_rotation(tmp_path):
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    original = _live(store)[0]["family_exp"]
    nxt = _refresh(client, body["refresh_token"], cid).json()
    live = _live(store)
    assert live[0]["family_exp"] == original, "the ceiling must not slide"
    assert nxt["refresh_token"]


def test_a_store_with_zero_ttl_is_not_refresh_support(tmp_path):
    """Metadata, DCR and the token endpoint must agree on one flag."""
    client, cookie = _build(tmp_path, refresh_store={}, refresh_token_ttl=0)
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["grant_types_supported"] == ["authorization_code"]
    reg = client.post(
        "/auth/oauth/register",
        json={"redirect_uris": [REDIRECT], "grant_types": ["refresh_token"]},
    ).json()
    assert reg["grant_types"] == ["authorization_code"]
    body = _flow(client, cookie, cid=reg["client_id"])
    assert "refresh_token" not in body
    r = _refresh(client, "x", reg["client_id"])
    assert r.json()["error"] == "unsupported_grant_type"


def test_concurrent_redemption_consumes_exactly_once(tmp_path):
    """Two worker PROCESSES share one store; only one may mint a successor.

    Modelled as two routers over the same stores with one shared claim — which
    is what plugin.py's filesystem claim provides in production. Without it both
    observe consumed_at=None and reuse detection never fires.
    """
    store, clients, claimed = {}, {}, set()

    def claim_once(key):
        if key in claimed:
            return False
        claimed.add(key)
        return True

    a, cookie = _build(
        tmp_path, refresh_store=store, client_store=clients, claim_once=claim_once
    )
    b, _ = _build(
        tmp_path, refresh_store=store, client_store=clients, claim_once=claim_once
    )
    cid = _register(a)
    body = _flow(a, cookie, cid=cid)

    first = _refresh(a, body["refresh_token"], cid)
    second = _refresh(b, body["refresh_token"], cid)  # the racing worker
    assert first.status_code == 200
    # The loser is diverted to the replay path rather than consuming the token a
    # second time. Within the grace window, from the same client, that means it
    # reissues -- deliberate, since stranding an honest retry is the failure this
    # whole grant exists to prevent. So the invariant is not that the loser is
    # refused; it is that the store never holds TWO independently live tokens.
    assert second.status_code in (200, 400)
    live = _live(store)
    assert len(live) == 1, "concurrent redemption minted two live successors"


def test_refresh_stops_when_the_subject_loses_their_account(tmp_path):
    active = {EMAIL}
    client, cookie = _build(tmp_path, refresh_store={}, is_active=lambda e: e in active)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    held = _refresh(client, body["refresh_token"], cid)
    assert held.status_code == 200
    active.clear()  # account deleted / deactivated
    assert _refresh(client, held.json()["refresh_token"], cid).status_code == 400
    # and a retry of the spent token must not sneak past the same gate
    assert _refresh(client, body["refresh_token"], cid).status_code == 400


def test_hostile_authorization_code_is_a_clean_invalid_grant(tmp_path):
    """`code` is a form field used as a store key — i.e. a path component."""
    client, _ = _build(tmp_path, refresh_store={})
    cid = _register(client)
    for hostile in ("../../etc/passwd", "..", "a/../../b", "%2e%2e/x"):
        r = client.post(
            "/auth/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": hostile,
                "redirect_uri": REDIRECT,
                "client_id": cid,
                "code_verifier": "x" * 43,
            },
        )
        assert r.status_code == 400, hostile
        assert r.json()["error"] == "invalid_grant", hostile


def test_consumed_records_do_not_accumulate(tmp_path):
    """Rotation used to leave one dead record per refresh alive for 30 days.

    Tombstones are bounded by refresh_reuse_detection; once it lapses they are
    swept rather than lingering for the token's original TTL.
    """
    store = {}
    client, cookie = _build(
        tmp_path, refresh_store=store, refresh_reuse_grace=0, refresh_reuse_detection=0
    )
    cid = _register(client)
    token = _flow(client, cookie, cid=cid)["refresh_token"]
    for _ in range(5):
        token = _refresh(client, token, cid).json()["refresh_token"]
    assert len(store) <= 2, f"store grew to {len(store)} records over 5 rotations"


def test_losing_the_claim_never_revokes_an_in_flight_family(tmp_path):
    """The regression the second review caught, reproduced deterministically.

    A worker that loses the claim used to re-read a record whose tombstone was
    not written yet, see consumed_at=None, conclude "replay", and revoke the
    family — destroying the successor the winner was about to hand back. The
    winner then returned 200 with a refresh token that no longer existed.
    """
    store, claimed = {}, set()

    def claim_once(key):
        if key in claimed:
            return False
        claimed.add(key)
        return True

    client, cookie = _build(tmp_path, refresh_store=store, claim_once=claim_once)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)

    # Another worker has claimed this token and not yet written its tombstone.
    (live_key,) = [
        k
        for k, v in store.items()
        if v.get("client_id") and v.get("consumed_at") is None
    ]
    assert claim_once(live_key) is True

    losing = _refresh(client, body["refresh_token"], cid)
    assert losing.status_code == 400
    assert store, "an in-flight rotation must not destroy the family"
    assert [v for v in store.values() if v["consumed_at"] is None], (
        "the winner's successor was destroyed by the loser"
    )


def test_duplicate_retries_all_return_the_same_credential(tmp_path):
    """Duplicates must not invalidate each other's responses.

    A re-minting retry handed every duplicate a 200 carrying a token the server
    had already deleted; a client that kept any response but the last was
    stranded. Measured at 12/15 across real processes before this became a
    replay.
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)

    responses = [_refresh(client, body["refresh_token"], cid) for _ in range(5)]
    assert [r.status_code for r in responses] == [200] * 5
    tokens = {r.json()["refresh_token"] for r in responses}
    assert len(tokens) == 1, "duplicate retries minted competing tokens"
    assert len(_live(store)) == 1
    # Whichever response the client kept, it still works.
    assert _refresh(client, tokens.pop(), cid).status_code == 200


def test_repeated_retries_keep_exactly_one_live_token(tmp_path):
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    for _ in range(4):
        assert _refresh(client, body["refresh_token"], cid).status_code == 200
        assert len(_live(store)) == 1, f"found {len(_live(store))} live tokens"


def test_tombstone_is_written_before_its_successor_exists(tmp_path):
    """Ordering is the invariant that makes the claim-loser check safe."""
    order = []

    class Recording(dict):
        def __setitem__(self, k, v):
            order.append((k, v.get("consumed_at") is not None))
            super().__setitem__(k, v)

    store = Recording()
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    order.clear()
    _refresh(client, body["refresh_token"], cid)
    assert order[0][1] is True, "successor was written before the tombstone"


def test_a_tombstone_without_its_successor_yet_is_not_theft(tmp_path):
    """Rotation is two writes; a concurrent worker can observe only the first.

    Reading that ambiguous state as theft is what made an ordinary concurrent
    refresh destroy the family — measured at 2/25 races across real processes
    before revocation was narrowed to positive evidence.
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    assert _refresh(client, body["refresh_token"], cid).status_code == 200

    # The successor has not been written yet (or is already gone).
    (successor_key,) = [
        k
        for k, v in store.items()
        if v.get("client_id") and v.get("consumed_at") is None
    ]
    del store[successor_key]

    refused = _refresh(client, body["refresh_token"], cid)
    assert refused.status_code == 400
    assert store, "an in-flight rotation must not be read as theft"


def test_a_duplicate_after_the_client_moved_on_is_refused_not_revoked(tmp_path):
    """The client demonstrably HAS a working token, so 400 costs it nothing.

    Revoking here killed healthy sessions: a duplicate of an earlier request
    landing on the other worker after the client had already used its successor
    burned the whole family. Reproduced sequentially, and in 26/60 real races.
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    second = _refresh(client, body["refresh_token"], cid).json()
    third = _refresh(client, second["refresh_token"], cid).json()  # client moves on

    duplicate = _refresh(client, body["refresh_token"], cid)
    assert duplicate.status_code == 400
    assert store, "a duplicate must not burn a healthy family"
    assert _refresh(client, third["refresh_token"], cid).status_code == 200


def test_the_retry_path_cannot_bypass_the_absolute_ceiling(tmp_path):
    """Otherwise every reissue silently extends a session past its hard stop."""
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    assert _refresh(client, body["refresh_token"], cid).status_code == 200
    # The family's ceiling passes while the client is retrying.
    for k in list(store):
        store[k] = {**store[k], "family_exp": 1}
    assert _refresh(client, body["refresh_token"], cid).status_code == 400
    assert _live(store) == []


def test_a_bogus_grant_type_does_no_store_work(tmp_path):
    """An unauthenticated caller must not be able to buy file I/O."""
    swept = []

    class Counting(dict):
        def __iter__(self):
            swept.append(1)
            return super().__iter__()

    client, _ = _build(tmp_path, refresh_store=Counting(), code_store=Counting())
    r = client.post(
        "/auth/oauth/token", data={"grant_type": "nonsense", "client_id": "x"}
    )
    assert r.status_code == 400 and r.json()["error"] == "unsupported_grant_type"
    assert not swept, "a rejected grant_type still swept the stores"


def test_abandoned_client_registrations_expire(tmp_path):
    """DCR is unauthenticated, so registrations must not accumulate forever."""
    clients = {}
    client, _ = _build(tmp_path, client_store=clients)
    cid = _register(client)
    assert clients[cid]["exp"] > _now_ish()


def test_a_client_still_in_use_keeps_its_registration(tmp_path):
    clients = {}
    client, cookie = _build(tmp_path, client_store=clients, refresh_store={})
    cid = _register(client)
    clients[cid] = {**clients[cid], "exp": 1}  # about to lapse
    _flow(client, cookie, cid=cid)
    assert clients[cid]["exp"] > 1, "an active client's registration must be renewed"


def test_a_failed_rotation_hands_the_claim_back(tmp_path):
    """Otherwise the token is unredeemable while its record says unconsumed."""
    claims, released = set(), []

    def claim_once(key):
        if key in claims:
            return False
        claims.add(key)
        return True

    class Exploding(dict):
        def __setitem__(self, k, v):
            if v.get("consumed_at") is not None:
                raise OSError("disk full")
            super().__setitem__(k, v)

    store = Exploding()
    client, cookie = _build(
        tmp_path,
        refresh_store=store,
        claim_once=claim_once,
        release_claim=lambda k: (released.append(k), claims.discard(k)),
    )
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    with pytest.raises(OSError):
        _refresh(client, body["refresh_token"], cid)
    assert released, "the claim was not released after a failed rotation"
    assert not claims, "a stuck claim makes the token permanently unredeemable"


def test_revocation_survives_a_concurrent_rotation(tmp_path):
    """Revocation must be a positive fact, not the absence of records.

    Expressed as a scan-and-delete it raced rotation: a successor written after
    the snapshot survived, and a tombstone write resurrected a parent the scan
    had just deleted, so a chain that happened to be rotating defeated detection
    outright (~22% of attempts across real processes). A marker cannot be raced.
    """
    store = {}
    client, cookie = _build(tmp_path, refresh_store=store, refresh_reuse_grace=0)
    cid = _register(client)
    body = _flow(client, cookie, cid=cid)
    survivor = _refresh(client, body["refresh_token"], cid).json()["refresh_token"]

    assert _refresh(client, body["refresh_token"], cid).status_code == 400  # revoke
    (marker_key,) = [k for k in store if k.startswith("family:")]

    # A record the delete scan missed, exactly as a concurrent rotation produces.
    store[_hash_refresh(survivor)] = {
        "family": marker_key.split("family:", 1)[1],
        "client_id": cid,
        "resource": RESOURCE,
        "scope": "mcp:read",
        "email": EMAIL,
        "iat": 1,
        "exp": 9999999999,
        "family_exp": 9999999999,
        "consumed_at": None,
        "successor": None,
    }
    assert _refresh(client, survivor, cid).status_code == 400, (
        "a token that escaped the revocation scan was still honoured"
    )
