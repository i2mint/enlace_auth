"""The CSRF cookie is minted only where a state-changing request can follow.

i2mint/enlace_auth#31: a ``public`` app's pages promise "no cookies", but the
platform used to give every first visitor an ``enlace_csrf`` cookie. Every
client of the double-submit check gets its token from ``GET /auth/csrf``, so
the cookie is minted on ``/auth``, on ``/_admin`` and on ``protected:*`` apps,
and nowhere else.
"""

from __future__ import annotations

import textwrap

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth import hash_password
from enlace_auth.auth.cookies import verify_cookie
from tests.test_admin import _seed_account

KEY = "csrf-scope-key-32bytes-minimumlen!"
ADMIN = "boss@example.com"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/ping")
    def ping():
        return {"ok": True}
    @app.post("/echo")
    def echo():
        return {"ok": True}
    """
).strip()


@pytest.fixture
def app_factory(tmp_path, monkeypatch):
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    monkeypatch.setenv("SHARED_PW", hash_password("open-sesame"))
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", ADMIN)
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    for name, toml in {
        "pub": None,
        "priv": 'access = "protected:user"\n',
        "shr": 'access = "protected:shared"\nshared_password_env = "SHARED_PW"\n',
    }.items():
        d = apps_dir / name
        d.mkdir()
        (d / "server.py").write_text(_SERVER)
        if toml:
            (d / "app.toml").write_text(toml)

    def make() -> TestClient:
        config = PlatformConfig(
            apps_dir=apps_dir,
            auth={
                "enabled": True,
                "secure_cookies": False,
                "registration_open": True,
                "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            },
            stores={"user_data": {"backend": "file", "path": str(tmp_path / "ud")}},
        )
        return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))

    return make


def _csrf_cookies(response) -> list[str]:
    return [
        v
        for v in response.headers.get_list("set-cookie")
        if v.startswith("enlace_csrf=")
    ]


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/pub",
        "/pub/",
        "/pub/anything.html",
        "/api/pub/ping",
        "/_apps",
        "/static/missing.css",
    ],
)
def test_public_pages_set_no_cookie(app_factory, path):
    client = app_factory()
    r = client.get(path)
    assert _csrf_cookies(r) == [], (path, r.status_code)
    assert "enlace_csrf" not in client.cookies


def test_public_pages_set_no_cookie_at_all(app_factory):
    """Not just the CSRF cookie: a first visit to a public page stores nothing."""
    client = app_factory()
    for path in ("/", "/pub/", "/api/pub/ping"):
        assert client.get(path).headers.get_list("set-cookie") == [], path


def test_auth_csrf_endpoint_mints_a_usable_token(app_factory):
    client = app_factory()
    r = client.get("/auth/csrf")
    assert r.status_code == 200
    assert len(_csrf_cookies(r)) == 1
    raw = verify_cookie(client.cookies.get("enlace_csrf"), KEY, salt="csrf")
    assert raw and r.json() == {"csrf": raw}
    # A second call reuses the cookie rather than minting another.
    r2 = client.get("/auth/csrf")
    assert _csrf_cookies(r2) == [] and r2.json() == {"csrf": raw}


def test_sign_in_pages_still_get_the_cookie(app_factory):
    client = app_factory()
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert len(_csrf_cookies(r)) == 1


def test_register_and_login_flow_works_from_auth_csrf_alone(app_factory):
    """The documented flow: GET /auth/csrf, echo it, POST. Nothing else first."""
    client = app_factory()
    token = client.get("/auth/csrf").json()["csrf"]
    body = {"email": "kid@example.com", "password": "secretpw123"}
    r = client.post("/auth/register", json=body, headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text
    assert (
        client.post("/auth/logout", headers={"X-CSRF-Token": token}).status_code == 200
    )
    r = client.post("/auth/login", json=body, headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text


def test_post_without_the_pair_is_still_refused(app_factory):
    """Narrowing the minting must not narrow the check."""
    client = app_factory()
    client.get("/pub/")  # no cookie comes back from here any more
    r = client.post(
        "/auth/register", json={"email": "a@b.co", "password": "secretpw123"}
    )
    assert r.status_code == 403
    assert r.json() == {"detail": "CSRF check failed"}


def test_protected_user_app_signed_in_gets_the_cookie(app_factory):
    client = app_factory()
    token = client.get("/auth/csrf").json()["csrf"]
    body = {"email": "kid@example.com", "password": "secretpw123"}
    assert (
        client.post(
            "/auth/register", json=body, headers={"X-CSRF-Token": token}
        ).status_code
        == 200
    )
    client.cookies.delete("enlace_csrf")  # a fresh token on the protected app
    r = client.get("/api/priv/ping")
    assert r.status_code == 200
    assert len(_csrf_cookies(r)) == 1


def test_admin_page_gets_the_cookie(app_factory, tmp_path):
    client = app_factory()
    token = client.get("/auth/csrf").json()["csrf"]
    # Registration refuses admin addresses; an operator seeds the account.
    _seed_account(tmp_path / "platform", ADMIN, "secretpw123")
    body = {"email": ADMIN, "password": "secretpw123"}
    r = client.post("/auth/login", json=body, headers={"X-CSRF-Token": token})
    assert r.status_code == 200, r.text
    client.cookies.delete("enlace_csrf")
    r = client.get("/_admin/")
    assert r.status_code == 200, r.status_code
    assert len(_csrf_cookies(r)) == 1


def test_protected_shared_app_gets_the_cookie_once_unlocked(app_factory):
    client = app_factory()
    token = client.get("/auth/csrf").json()["csrf"]
    r = client.post(
        "/auth/shared-login",
        json={"app": "shr", "password": "open-sesame"},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200, r.text
    client.cookies.delete("enlace_csrf")
    r = client.get("/api/shr/ping")
    assert r.status_code == 200
    assert len(_csrf_cookies(r)) == 1
