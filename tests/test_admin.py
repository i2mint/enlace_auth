"""Tests for the /_admin/api/* router and /auth/me/password self-service.

Sets up a full enlace gateway with the auth plugin and an admin email allowlist,
then exercises the admin endpoints end-to-end via TestClient.
"""

from __future__ import annotations

import textwrap

import pytest
from starlette.testclient import TestClient

from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from enlace_auth import plugin as auth_plugin


_SIGNING_KEY = "admin-test-key-thirtytwobyteslong!!"


def _write_dummy_app(apps_dir):
    """Apps_dir needs at least one app for the gateway to be useful."""
    app = apps_dir / "ping"
    app.mkdir()
    (app / "server.py").write_text(
        textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/ping")
            def ping():
                return {"ok": True}
            """
        ).strip()
    )


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)

    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@example.com")

    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    config = discover_apps(config)
    app = build_backend(config, plugins=[auth_plugin])
    return TestClient(app)


def _csrf(client: TestClient) -> dict:
    """Get a CSRF token + return it as the X-CSRF-Token header dict."""
    r = client.get("/api/ping/ping")
    assert r.status_code == 200
    signed = client.cookies.get("enlace_csrf")
    from enlace_auth.auth.cookies import verify_cookie

    raw = verify_cookie(signed, _SIGNING_KEY, salt="csrf")
    assert raw is not None
    return {"X-CSRF-Token": raw}


def _login(client: TestClient, email: str, password: str, csrf):
    return client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers=csrf,
    )


def _register(client: TestClient, email: str, password: str, csrf):
    return client.post(
        "/auth/register",
        json={"email": email, "password": password},
        headers=csrf,
    )


def test_admin_blocked_for_anonymous(admin_client):
    r = admin_client.get("/_admin/api/users")
    assert r.status_code == 401


def test_admin_blocked_for_non_admin_user(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "alice@example.com", "secretpw1", csrf)
    r = admin_client.get("/_admin/api/users")
    assert r.status_code == 401  # access rule denies non-admin emails


def test_admin_can_list_users(admin_client):
    csrf = _csrf(admin_client)
    # Register the admin then a regular user.
    assert (
        _register(admin_client, "boss@example.com", "bosspw1!", csrf).status_code == 200
    )
    # Admin must already be logged in via the register response — check listing.
    r = admin_client.get("/_admin/api/users")
    assert r.status_code == 200, r.text
    emails = {u["email"] for u in r.json()["users"]}
    assert "boss@example.com" in emails


def test_admin_creates_and_deletes_user(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)

    r = admin_client.post(
        "/_admin/api/users",
        json={"email": "carl@example.com", "password": "carlpw99"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text

    # Carl can now log in (logout admin first to drop the session cookie).
    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    r = _login(admin_client, "carl@example.com", "carlpw99", csrf2)
    assert r.status_code == 200, r.text

    # Re-auth as admin and delete.
    admin_client.post("/auth/logout", headers=csrf2)
    csrf3 = _csrf(admin_client)
    _login(admin_client, "boss@example.com", "bosspw1!", csrf3)
    r = admin_client.delete("/_admin/api/users/carl@example.com", headers=csrf3)
    assert r.status_code == 200, r.text


def test_admin_resets_password(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "dora@example.com", "password": "old-password"},
        headers=csrf,
    )

    r = admin_client.post(
        "/_admin/api/users/dora@example.com/password",
        json={"password": "new-password"},
        headers=csrf,
    )
    assert r.status_code == 200

    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    bad = _login(admin_client, "dora@example.com", "old-password", csrf2)
    assert bad.status_code == 401
    good = _login(admin_client, "dora@example.com", "new-password", csrf2)
    assert good.status_code == 200


def test_change_own_password_via_auth_me(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "edith@example.com", "starting-pw", csrf)

    r = admin_client.post(
        "/auth/me/password",
        json={"old_password": "starting-pw", "new_password": "rotated-pw"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text

    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    bad = _login(admin_client, "edith@example.com", "starting-pw", csrf2)
    assert bad.status_code == 401
    good = _login(admin_client, "edith@example.com", "rotated-pw", csrf2)
    assert good.status_code == 200


def test_change_own_password_rejects_wrong_old(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "frank@example.com", "the-real-pw", csrf)
    r = admin_client.post(
        "/auth/me/password",
        json={"old_password": "wrong-pw", "new_password": "doesnt-matter"},
        headers=csrf,
    )
    assert r.status_code == 401


def test_admin_apps_listing(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.get("/_admin/api/apps")
    assert r.status_code == 200, r.text
    names = {a["name"] for a in r.json()["apps"]}
    assert "ping" in names


def test_last_admin_protection(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    # boss is the only admin in the user store. Deleting them must fail.
    r = admin_client.delete("/_admin/api/users/boss@example.com", headers=csrf)
    assert r.status_code == 409
    assert "last admin" in r.json()["detail"].lower()
