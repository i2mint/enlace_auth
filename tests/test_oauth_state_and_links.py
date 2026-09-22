# ruff: noqa: F811 -- admin_client is a fixture imported from test_admin.
"""OAuth login: real Authlib state round trip, and subject-bound account links.

i2mint/enlace_auth#28. The older ``test_oauth.py`` mocks both
``authorize_redirect`` and ``authorize_access_token``, so it never exercised the
anti-CSRF ``state`` check, which needs a ``request.session`` that nothing in
enlace_auth used to provide. These tests keep Authlib's real redirect/state code
and stub only the two network calls (token exchange, userinfo).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from enlace_auth.auth import SessionStore
from enlace_auth.config import OAuthProviderConfig
from tests.test_admin import admin_client  # noqa: F401 - fixture

SIGNING_KEY = "oauth-signing-key-32bytes-minlen"


def _make_app(user_store, *, claims, can_register=lambda _e: True):
    """Router with a real Authlib registry for a stub, non-OIDC provider."""
    os.environ["STUB_ID"] = "stub-client-id"
    os.environ["STUB_SECRET"] = "stub-client-secret"
    from enlace_auth.auth import oauth as oauth_mod

    providers = {
        "stub": OAuthProviderConfig(
            client_id_env="STUB_ID",
            client_secret_env="STUB_SECRET",
            authorize_url="https://idp.example/authorize",
            token_url="https://idp.example/token",
            userinfo_url="https://idp.example/userinfo",
            scopes=["profile", "email"],
            trust_unverified_email=True,
        )
    }
    real_build = oauth_mod._build_oauth_registry
    captured = {}

    def _build(p):
        registry = real_build(p)
        client = registry.stub
        # Stub only the network: the state check stays Authlib's own.
        client.fetch_access_token = AsyncMock(
            return_value={"access_token": "at", "token_type": "Bearer"}
        )
        client.userinfo = AsyncMock(return_value=claims)
        captured["client"] = client
        return registry

    sessions = SessionStore({})
    with patch.object(oauth_mod, "_build_oauth_registry", _build):
        router = oauth_mod.make_oauth_router(
            providers=providers,
            session_store=sessions,
            user_store=user_store,
            signing_key=SIGNING_KEY,
            secure_cookies=False,
            can_register=can_register,
        )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), sessions


def _start_login(client: TestClient) -> str:
    r = client.get("/auth/login/stub", follow_redirects=False)
    assert r.status_code in (302, 303, 307), r.text
    assert "enlace_oauth_state=" in r.headers.get("set-cookie", "")
    assert "Path=/auth" in r.headers["set-cookie"]
    state = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
    return state


CLAIMS = {"sub": "subject-1", "email": "alice@example.com"}


def test_real_state_round_trip_signs_in_and_clears_the_state_cookie():
    users: dict = {}
    client, sessions = _make_app(users, claims=CLAIMS)
    state = _start_login(client)
    r = client.get(f"/auth/callback/stub?code=c&state={state}")
    assert r.status_code == 200, r.text
    assert users["alice@example.com"]["oauth_links"] == {"stub": "subject-1"}
    assert len(sessions.list_all()) == 1
    assert "enlace_oauth_state=;" in r.headers.get("set-cookie", "")


def test_callback_without_the_browsers_state_cookie_is_refused():
    """Login CSRF: a callback URL minted in another browser must not sign in."""
    attacker, _ = _make_app({}, claims=CLAIMS)
    state = _start_login(attacker)
    users: dict = {}
    victim, sessions = _make_app(users, claims=CLAIMS)
    r = victim.get(f"/auth/callback/stub?code=c&state={state}")
    assert r.status_code == 401
    assert users == {} and sessions.list_all() == []


def test_callback_with_a_different_state_is_refused():
    users: dict = {}
    client, sessions = _make_app(users, claims=CLAIMS)
    _start_login(client)
    r = client.get("/auth/callback/stub?code=c&state=forged")
    assert r.status_code == 401
    assert sessions.list_all() == []


def test_state_is_single_use():
    client, sessions = _make_app({}, claims=CLAIMS)
    state = _start_login(client)
    assert client.get(f"/auth/callback/stub?code=c&state={state}").status_code == 200
    r = client.get(f"/auth/callback/stub?code=c&state={state}")
    assert r.status_code == 401


def test_a_forged_state_cookie_is_ignored():
    client, sessions = _make_app({}, claims=CLAIMS)
    client.cookies.set(
        "enlace_oauth_state",
        '{"_state_stub_x": {"data": {}, "exp": 9999999999}}',
        path="/auth",
    )
    r = client.get("/auth/callback/stub?code=c&state=x")
    assert r.status_code == 401


# ---- account links ----------------------------------------------------------


def _signin(users, claims):
    client, sessions = _make_app(users, claims=claims)
    state = _start_login(client)
    return client.get(f"/auth/callback/stub?code=c&state={state}"), sessions


def test_existing_password_account_is_not_taken_over_by_email():
    users = {"alice@example.com": {"password_hash": "h", "created_at": 0}}
    r, sessions = _signin(users, CLAIMS)
    assert r.status_code == 403
    assert sessions.list_all() == []
    assert "oauth_links" not in users["alice@example.com"]


def test_linked_account_requires_the_same_subject():
    users = {
        "alice@example.com": {
            "password_hash": None,
            "oauth_provider": "stub",
            "oauth_links": {"stub": "subject-1"},
        }
    }
    r, _ = _signin(users, {**CLAIMS, "sub": "someone-else"})
    assert r.status_code == 403
    r, _ = _signin(users, CLAIMS)
    assert r.status_code == 200


def test_legacy_account_of_this_provider_is_linked_on_next_login():
    users = {"alice@example.com": {"password_hash": None, "oauth_provider": "stub"}}
    r, _ = _signin(users, CLAIMS)
    assert r.status_code == 200
    assert users["alice@example.com"]["oauth_links"] == {"stub": "subject-1"}
    r, _ = _signin(users, {**CLAIMS, "sub": "someone-else"})
    assert r.status_code == 403


def test_account_of_another_provider_is_not_opened():
    users = {"alice@example.com": {"password_hash": None, "oauth_provider": "google"}}
    r, _ = _signin(users, CLAIMS)
    assert r.status_code == 403


@pytest.mark.parametrize("claims", [{"email": "alice@example.com"}])
def test_linked_account_refuses_an_identity_without_subject(claims):
    users = {"alice@example.com": {"password_hash": None, "oauth_links": {"stub": "s"}}}
    r, _ = _signin(users, claims)
    assert r.status_code == 403


# ---- review of #30 -----------------------------------------------------------


def test_a_failed_callback_spends_the_state():
    """An error callback must not leave the state usable for a later code."""
    client, sessions = _make_app({}, claims=CLAIMS)
    state = _start_login(client)
    r = client.get(f"/auth/callback/stub?error=access_denied&state={state}")
    assert r.status_code == 401
    r = client.get(f"/auth/callback/stub?code=c&state={state}")
    assert r.status_code == 401
    assert sessions.list_all() == []


def test_a_refused_login_spends_the_state():
    users = {"alice@example.com": {"password_hash": "h", "created_at": 0}}
    client, _ = _make_app(users, claims=CLAIMS)
    state = _start_login(client)
    assert client.get(f"/auth/callback/stub?code=c&state={state}").status_code == 403
    assert client.get(f"/auth/callback/stub?code=c&state={state}").status_code == 401


def test_duplicate_state_cookies_are_refused():
    """Cookie tossing: a second state cookie planted at another path."""
    attacker, _ = _make_app({}, claims=CLAIMS)
    state = _start_login(attacker)
    planted = attacker.cookies.get("enlace_oauth_state")
    victim, sessions = _make_app({}, claims=CLAIMS)
    _start_login(victim)
    genuine = victim.cookies.get("enlace_oauth_state")
    r = victim.get(
        f"/auth/callback/stub?code=c&state={state}",
        headers={
            "cookie": f"enlace_oauth_state={genuine}; enlace_oauth_state={planted}"
        },
    )
    assert r.status_code == 401
    assert sessions.list_all() == []


def test_admin_password_reset_unlinks_external_sign_ins(admin_client, tmp_path):
    from enlace_auth.stores import make_file_store_factory
    from tests.test_admin import _csrf, _register

    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users",
        json={"email": "vic@example.com", "password": "victim-pw1"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users["vic@example.com"] = {
        **users["vic@example.com"],
        "oauth_links": {"google": "attacker-subject"},
    }
    r = admin_client.post(
        "/_admin/api/users/vic@example.com/password",
        json={"password": "brand-new-pw1"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    assert "oauth_links" not in users["vic@example.com"]


def test_stable_subject_ignores_tid_oid_outside_entra():
    from enlace_auth.auth.oauth import _stable_subject

    assert _stable_subject("x", {"sub": "s", "tid": "t", "oid": "o"}) == "s"
    assert (
        _stable_subject(
            "x",
            {"sub": "s", "tid": "t", "oid": "o", "iss": "https://sts.windows.net/t/"},
        )
        == "t/o"
    )
