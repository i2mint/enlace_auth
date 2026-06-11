"""Tests for the /_admin/api/* router and /auth/me/password self-service.

Sets up a full enlace gateway with the auth plugin and an admin email allowlist,
then exercises the admin endpoints end-to-end via TestClient.
"""

from __future__ import annotations

import textwrap

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

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


def _write_vault_app(apps_dir):
    """A RESTRICTED protected:user app (allowed_users baseline = boss only).

    Used to exercise runtime grants: a non-admin not in allowed_users should be
    denied until granted, then allowed, then denied again after revoke.
    """
    app = apps_dir / "vault"
    app.mkdir()
    (app / "server.py").write_text(
        textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/thing")
            def thing():
                return {"ok": True}
            """
        ).strip()
    )
    (app / "app.toml").write_text(
        'access = "protected:user"\nallowed_users = ["boss@example.com"]\n'
    )


def _write_open_app(apps_dir):
    """An OPEN protected:user app (no allowed_users) — open to any authenticated
    user. Granting on it must be rejected by the open-app guard.
    """
    app = apps_dir / "lobby"
    app.mkdir()
    (app / "server.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")
    (app / "app.toml").write_text('access = "protected:user"\n')


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    _write_vault_app(apps_dir)
    _write_open_app(apps_dir)

    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@example.com")

    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            # These tests register non-admin users to exercise admin endpoints.
            "registration_open": True,
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


# --------------------------------------------------------------------------
# Dashboard UI (bundled HTML served at /_admin/)
# --------------------------------------------------------------------------


def test_admin_dashboard_blocked_for_anonymous_browser(admin_client):
    """Browser hitting /_admin/ without a session gets redirected to login,
    not an HTML page leak.
    """
    r = admin_client.get(
        "/_admin/", headers={"Accept": "text/html"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert "login_required=1" in r.headers["location"]


def test_admin_dashboard_blocked_for_non_admin(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "alice@example.com", "secretpw1", csrf)
    # Logged in as alice (not in admin_emails) — should NOT see the dashboard.
    r = admin_client.get(
        "/_admin/", headers={"Accept": "text/html"}, follow_redirects=False
    )
    assert r.status_code == 303


def test_admin_dashboard_served_to_admin(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.get("/_admin/", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    # Sanity-check the bundled HTML actually loaded — the dashboard fetches
    # /_admin/api/users on page load.
    assert "/_admin/api" in r.text
    assert "enlace · admin" in r.text


def test_admin_dashboard_index_html_alias(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.get("/_admin/index.html", headers={"Accept": "text/html"})
    assert r.status_code == 200
    assert "enlace · admin" in r.text


# --------------------------------------------------------------------------
# Runtime grants (/_admin/api/grants + /apps enrichment)
# --------------------------------------------------------------------------


def _grant(client, app_id, email, csrf, **extra):
    return client.post(
        "/_admin/api/grants",
        json={"app_id": app_id, "email": email, **extra},
        headers=csrf,
    )


def test_grant_requires_admin(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "alice@example.com", "secretpw1", csrf)  # non-admin
    r = _grant(admin_client, "vault", "carl@example.com", csrf)
    assert r.status_code == 401  # access rule blocks non-admin from /_admin


def test_grant_unknown_app_404(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = _grant(admin_client, "nope", "carl@example.com", csrf)
    assert r.status_code == 404


def test_grant_on_open_app_rejected(admin_client):
    """The open-app guard: granting on a protected:user app with empty
    allowed_users is a 422 (it would unintentionally restrict an open app).
    """
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = _grant(admin_client, "lobby", "carl@example.com", csrf)
    assert r.status_code == 422
    assert "open to all authenticated" in r.json()["detail"]


def test_grant_past_expiry_rejected(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = _grant(admin_client, "vault", "carl@example.com", csrf, expires_at="2000-01-01")
    assert r.status_code == 422


def test_grant_appears_in_apps_listing(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    assert _grant(admin_client, "vault", "carl@example.com", csrf).status_code == 200

    r = admin_client.get("/_admin/api/apps")
    assert r.status_code == 200, r.text
    apps = {a["name"]: a for a in r.json()["apps"]}
    vault = apps["vault"]
    assert vault["is_open"] is False
    assert vault["allowed_users"] == ["boss@example.com"]
    emails = {g["email"] for g in vault["grants"]}
    assert "carl@example.com" in emails
    assert all(g["active"] for g in vault["grants"])
    # The open app reports is_open and gets no baseline users.
    assert apps["lobby"]["is_open"] is True


def test_revoke_grant(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    _grant(admin_client, "vault", "carl@example.com", csrf)
    r = admin_client.delete("/_admin/api/grants/vault/carl@example.com", headers=csrf)
    assert r.status_code == 200, r.text
    # Gone now → second revoke 404s.
    r = admin_client.delete("/_admin/api/grants/vault/carl@example.com", headers=csrf)
    assert r.status_code == 404


def test_grant_then_access_then_revoke_end_to_end(admin_client):
    """The whole point: grant a non-admin runtime access to a restricted app,
    confirm they can reach it, then revoke and confirm they're locked out —
    all without a redeploy.
    """
    # Admin (boss) registers + creates the non-admin carl.
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "carl@example.com", "password": "carlpw99"},
        headers=csrf,
    )

    # Before any grant: carl logs in and is denied the restricted app.
    admin_client.post("/auth/logout", headers=csrf)
    csrf = _csrf(admin_client)
    assert _login(admin_client, "carl@example.com", "carlpw99", csrf).status_code == 200
    assert admin_client.get("/api/vault/thing").status_code == 401

    # Admin grants carl access.
    admin_client.post("/auth/logout", headers=csrf)
    csrf = _csrf(admin_client)
    _login(admin_client, "boss@example.com", "bosspw1!", csrf)
    assert _grant(admin_client, "vault", "carl@example.com", csrf).status_code == 200

    # Now carl can reach it.
    admin_client.post("/auth/logout", headers=csrf)
    csrf = _csrf(admin_client)
    _login(admin_client, "carl@example.com", "carlpw99", csrf)
    assert admin_client.get("/api/vault/thing").status_code == 200

    # Admin revokes; carl is locked out again.
    admin_client.post("/auth/logout", headers=csrf)
    csrf = _csrf(admin_client)
    _login(admin_client, "boss@example.com", "bosspw1!", csrf)
    assert (
        admin_client.delete(
            "/_admin/api/grants/vault/carl@example.com", headers=csrf
        ).status_code
        == 200
    )

    admin_client.post("/auth/logout", headers=csrf)
    csrf = _csrf(admin_client)
    _login(admin_client, "carl@example.com", "carlpw99", csrf)
    assert admin_client.get("/api/vault/thing").status_code == 401
