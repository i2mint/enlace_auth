"""The authorization server behind a login that is not enlace's (#98).

Three seams: who is signed in (``current_identity``), where to send someone who is
not (``login_url``), and whether an identity may hold a token for a resource
(``may_authorize``, consulted at consent, at the code exchange and on every
refresh, with the binding the code or family recorded). Here a gateway signs its
users in with a header and revokes them by bumping an epoch. The platform's own
defaults are pinned by ``tests/test_oauth_server.py``, which is unchanged.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("authlib")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from enlace_auth import oauth_rules  # noqa: E402
from enlace_auth.auth import oauth_server  # noqa: E402
from enlace_auth.auth.oauth_server import (  # noqa: E402
    Identity,
    OAuthKeys,
    make_oauth_server_router,
)
from enlace_auth.auth.sessions import SessionStore  # noqa: E402
from tests.test_oauth_server import (  # noqa: E402
    EMAIL,
    REDIRECT,
    RESOURCE,
    SIGNING_KEY,
    _pkce,
    _refresh,
    _register,
)

HEADER = "X-Gateway-User"


class _Gateway:
    """A forward-auth gateway: a header names the user, an epoch revokes them."""

    def __init__(self):
        self.epoch = {EMAIL: "1"}
        self.calls: list[tuple[str, str, str | None]] = []
        self.allowed_resources = {RESOURCE}

    def identity(self, request):
        email = request.headers.get(HEADER)
        return Identity(email=email, binding=self.epoch.get(email)) if email else None

    def may_authorize(self, email, resource, binding):
        self.calls.append((email, resource, binding))
        if resource not in self.allowed_resources:
            return "resource not granted to this gateway's user"
        if binding != self.epoch.get(email):
            return "revoked by the gateway (epoch moved)"
        return None


def _build(tmp_path, gateway, *, refresh_store=None):
    router = make_oauth_server_router(
        # The platform's session machinery is still required, and unused here.
        session_store=SessionStore({}),
        signing_key=SIGNING_KEY,
        cookie_name="unused",
        session_max_age=86400,
        client_store={},
        code_store={},
        refresh_store={} if refresh_store is None else refresh_store,
        keys=OAuthKeys(tmp_path / "keys"),
        allow_unlisted_resources=True,
        current_identity=gateway.identity,
        login_url=lambda nxt: f"https://gw.example/login?rd={nxt}",
        may_authorize=gateway.may_authorize,
    )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _authorize_params(cid, challenge, resource=RESOURCE):
    return {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "mcp:read",
        "resource": resource,
    }


def _flow(client, cid, resource=RESOURCE):
    """authorize → consent → token, signed in by the gateway's header."""
    import re

    verifier, challenge = _pkce()
    params = _authorize_params(cid, challenge, resource)
    page = client.get("/auth/oauth/authorize", params=params, headers={HEADER: EMAIL})
    assert page.status_code == 200, page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    form = {k: v for k, v in params.items() if k not in ("response_type",)}
    form.pop("code_challenge_method")
    r = client.post(
        "/auth/oauth/authorize",
        data={**form, "csrf": csrf, "decision": "approve"},
        headers={HEADER: EMAIL},
        follow_redirects=False,
    )
    assert r.status_code == 302, r.text
    code = r.headers["location"].split("code=")[1].split("&")[0]
    return client.post(
        "/auth/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "client_id": cid,
            "code_verifier": verifier,
        },
    )


def test_an_unauthenticated_authorize_goes_to_the_gateways_login(tmp_path):
    client = _build(tmp_path, _Gateway())
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(_register(client), challenge),
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith("https://gw.example/login?rd=/auth/oauth/")


def test_the_gateways_identity_authorizes_and_its_check_runs_at_every_step(tmp_path):
    gateway = _Gateway()
    client = _build(tmp_path, gateway)
    tok = _flow(client, _register(client))
    assert tok.status_code == 200, tok.text
    assert "refresh_token" in tok.json()
    # consent page, consent submit, code exchange: each with the epoch binding
    assert gateway.calls == [(EMAIL, RESOURCE, "1")] * 3
    again = _refresh(client, tok.json()["refresh_token"], _client_of(tok, client))
    assert again.status_code == 200, again.text
    assert gateway.calls[-1] == (EMAIL, RESOURCE, "1")  # the family kept the binding


def _client_of(tok, client):
    """The client_id the token was issued to (read back from the JWT)."""
    import base64
    import json

    payload = tok.json()["access_token"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["client_id"]


def test_moving_the_epoch_revokes_the_family_on_its_next_refresh(tmp_path):
    gateway = _Gateway()
    client = _build(tmp_path, gateway)
    tok = _flow(client, _register(client))
    cid = _client_of(tok, client)
    gateway.epoch[EMAIL] = "2"  # the gateway revoked the user
    refused = _refresh(client, tok.json()["refresh_token"], cid)
    assert refused.status_code == 400
    assert refused.json()["error"] == "invalid_grant"


def test_the_gateways_refusal_at_consent_is_a_denial(tmp_path):
    gateway = _Gateway()
    gateway.allowed_resources = set()
    client = _build(tmp_path, gateway)
    _, challenge = _pkce()
    page = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(_register(client), challenge),
        headers={HEADER: EMAIL},
    )
    assert page.status_code == 403


def test_a_code_whose_binding_moved_before_the_exchange_is_refused(tmp_path):
    """The binding the consent saw travels in the code."""
    import re

    gateway = _Gateway()
    client = _build(tmp_path, gateway)
    cid = _register(client)
    verifier, challenge = _pkce()
    params = _authorize_params(cid, challenge)
    page = client.get("/auth/oauth/authorize", params=params, headers={HEADER: EMAIL})
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    form = {k: v for k, v in params.items() if k not in ("response_type",)}
    form.pop("code_challenge_method")
    r = client.post(
        "/auth/oauth/authorize",
        data={**form, "csrf": csrf, "decision": "approve"},
        headers={HEADER: EMAIL},
        follow_redirects=False,
    )
    code = r.headers["location"].split("code=")[1].split("&")[0]
    gateway.epoch[EMAIL] = "2"
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
    assert tok.status_code == 400


def test_signed_in_by_the_platform_does_not_count_under_another_gateway(tmp_path):
    """With a custom identity seam, the platform's own cookie opens nothing."""
    client = _build(tmp_path, _Gateway())
    client.cookies.set("unused", "anything")
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(_register(client), challenge),
        follow_redirects=False,
    )
    assert r.status_code == 302 and "gw.example" in r.headers["location"]


# -- the stateless rules, importable alone ---------------------------------------


def test_the_server_uses_the_public_rules():
    assert oauth_server._verify_pkce_s256 is oauth_rules.verify_pkce_s256
    assert oauth_server._hash_refresh is oauth_rules.hash_refresh
    assert oauth_server._redirect_uri_problem is oauth_rules.redirect_uri_problem
    assert oauth_server.OAuthKeys is oauth_rules.OAuthKeys


def test_the_rules_module_imports_no_web_framework():
    tree = ast.parse(Path(oauth_rules.__file__).read_text("utf-8"))
    imported = {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert not imported & {"fastapi", "starlette", "enlace", "enlace_auth"}, imported


@pytest.mark.parametrize(
    "uri, kw, ok",
    [
        ("https://claude.ai/cb", {"https_hosts": ["claude.ai"]}, True),
        ("https://CLAUDE.ai/cb", {"https_hosts": ["claude.ai"]}, True),
        ("https://evil.example/cb", {"https_hosts": ["claude.ai"]}, False),
        ("http://127.0.0.1:9/cb", {}, True),
        ("http://127.0.0.1:9/cb", {"allow_loopback": False}, False),
        ("cursor://anysphere/cb", {"https_hosts": ["claude.ai"]}, True),
        ("javascript://claude.ai/%0aalert(1)", {}, False),
    ],
)
def test_redirect_uri_vetting_knobs(uri, kw, ok):
    assert (oauth_rules.redirect_uri_problem(uri, **kw) is None) is ok


# -- review of #104 ---------------------------------------------------------------


@pytest.mark.parametrize("answer", [True, False, ""])
def test_a_yes_or_no_answer_from_may_authorize_raises_instead_of_failing_open(
    tmp_path, answer
):
    gateway = _Gateway()
    gateway.may_authorize = lambda email, resource, binding: answer
    client = _build(tmp_path, gateway)
    _, challenge = _pkce()
    with pytest.raises(TypeError, match="may_authorize must return"):
        client.get(
            "/auth/oauth/authorize",
            params=_authorize_params(_register(client), challenge),
            headers={HEADER: EMAIL},
        )


def test_an_identity_with_no_email_is_not_signed_in(tmp_path):
    gateway = _Gateway()
    gateway.identity = lambda request: Identity(email="", binding="1")
    client = _build(tmp_path, gateway)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(_register(client), challenge),
        follow_redirects=False,
    )
    assert r.status_code == 302 and "gw.example" in r.headers["location"]


def test_the_platforms_session_id_is_not_written_into_codes_or_families(tmp_path):
    """With the default seams the binding is the session id: never persisted."""
    from tests.test_oauth_server import _build as build_platform
    from tests.test_oauth_server import _flow as platform_flow

    refresh_store, code_store = {}, {}
    client, cookie = build_platform(
        tmp_path, refresh_store=refresh_store, code_store=code_store
    )
    cid = _register(client)
    assert "refresh_token" in platform_flow(client, cookie, cid=cid)
    records = list(refresh_store.values()) + list(code_store.values())
    assert records and all(r.get("binding") is None for r in records)


def test_a_gateways_binding_is_kept_in_the_family(tmp_path):
    store = {}
    gateway = _Gateway()
    client = _build(tmp_path, gateway, refresh_store=store)
    assert _flow(client, _register(client)).status_code == 200
    assert {r.get("binding") for r in store.values() if "client_id" in r} == {"1"}


def test_https_hosts_as_a_bare_string_is_refused():
    with pytest.raises(TypeError, match="not a string"):
        oauth_rules.redirect_uri_problem("https://c/cb", https_hosts="claude.ai")


def test_a_server_can_refuse_private_schemes_too():
    assert oauth_rules.redirect_uri_problem("cursor://cb") is None
    assert oauth_rules.redirect_uri_problem("cursor://cb", allow_private_schemes=False)
