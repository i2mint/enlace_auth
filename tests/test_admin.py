"""Tests for the /_admin/api/* router and /auth/me/password self-service.

Sets up a full enlace gateway with the auth plugin and an admin email allowlist,
then exercises the admin endpoints end-to-end via TestClient.
"""

from __future__ import annotations

import textwrap
import time

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth.accounts import is_disabled
from enlace_auth.auth.passwords import hash_password
from enlace_auth.plugin import _make_is_active, read_email_list
from enlace_auth.stores import make_file_store_factory

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
    client = TestClient(app)
    client.user_store_root = tmp_path / "platform"  # read by _register
    return client


def _csrf(client: TestClient) -> dict:
    """Get a CSRF token + return it as the X-CSRF-Token header dict."""
    r = client.get("/auth/csrf")  # a public GET no longer mints the cookie
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


def _seed_account(store_root, email: str, password: str) -> None:
    """Create an account as ``enlace-auth add-user`` does."""
    users = make_file_store_factory(str(store_root))("users")
    users[email.lower()] = {
        "password_hash": hash_password(password),
        "created_at": time.time(),
        "created_via": "add-user",
    }


def _register(client: TestClient, email: str, password: str, csrf):
    """Self-register *email* and sign in.

    Registration refuses admin addresses (i2mint/enlace_auth#38), so for one of
    those this creates the account the way an operator does (``add-user``) and
    signs in, when the client says where its user store is
    (``client.user_store_root``). A second call gets registration's 403: it
    refuses an admin address before looking whether the account exists (#41).
    """
    root = getattr(client, "user_store_root", None)
    if root is not None and email.lower() in read_email_list("ENLACE_ADMIN_EMAILS"):
        if email.lower() not in make_file_store_factory(str(root))("users"):
            _seed_account(root, email, password)
            return _login(client, email, password, csrf)
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
    # Signed in, not an admin: 403 ("not for you"), not 401 ("sign in").
    assert r.status_code == 403
    assert r.json()["auth"] == "forbidden"


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


def test_admin_create_user_refuses_duplicates_and_short_passwords(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    short = admin_client.post(
        "/_admin/api/users",
        json={"email": "dan@example.com", "password": "short"},
        headers=csrf,
    )
    assert short.status_code == 400, short.text
    dup = admin_client.post(
        "/_admin/api/users",
        json={"email": "boss@example.com", "password": "another-pw"},
        headers=csrf,
    )
    assert dup.status_code == 409, dup.text
    # An admin reset follows the same rule as every other way to set one.
    reset = admin_client.post(
        "/_admin/api/users/boss@example.com/password",
        json={"password": "short"},
        headers=csrf,
    )
    assert reset.status_code == 400, reset.text
    # ...and changes nothing: the old password still signs in.
    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    assert (
        _login(admin_client, "boss@example.com", "bosspw1!", csrf2).status_code == 200
    )
    # A taken address is 409 whatever the password: existence is checked first.
    dup_short = admin_client.post(
        "/_admin/api/users",
        json={"email": "boss@example.com", "password": "short"},
        headers=csrf2,
    )
    assert dup_short.status_code == 409, dup_short.text


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
    assert r.status_code == 403
    assert "alice@example.com" in r.text  # says who they are signed in as
    assert "/auth/login" in r.text  # and offers to switch account


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
    assert r.status_code == 403  # signed in, not an admin


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


# --- admin-minted reset links ----------------------------------------------


def test_admin_mints_a_reset_link_the_user_can_redeem(admin_client):
    """The onboarding path that needs no SMTP and no invented password."""
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "gina@example.com", "password": "placeholder-pw"},
        headers=csrf,
    )

    r = admin_client.post("/_admin/api/users/gina@example.com/reset-link", headers=csrf)
    assert r.status_code == 200, r.text
    url = r.json()["url"]
    assert "/auth/reset-password?token=" in url
    assert r.json()["expires_in_seconds"] > 0

    token = url.split("token=", 1)[1]
    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    confirm = admin_client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "gina-chose-this"},
        headers=csrf2,
    )
    assert confirm.status_code == 200, confirm.text

    admin_client.post("/auth/logout", headers=csrf2)
    csrf3 = _csrf(admin_client)
    assert (
        _login(admin_client, "gina@example.com", "gina-chose-this", csrf3).status_code
        == 200
    )
    assert (
        _login(admin_client, "gina@example.com", "placeholder-pw", csrf3).status_code
        == 401
    )


def test_admin_reset_link_is_single_use(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "hal@example.com", "password": "placeholder-pw"},
        headers=csrf,
    )
    url = admin_client.post(
        "/_admin/api/users/hal@example.com/reset-link", headers=csrf
    ).json()["url"]
    token = url.split("token=", 1)[1]

    first = admin_client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "first-choice"},
        headers=csrf,
    )
    assert first.status_code == 200, first.text
    csrf2 = _csrf(admin_client)
    second = admin_client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "second-choice"},
        headers=csrf2,
    )
    assert second.status_code == 400


def test_admin_reset_link_404s_for_unknown_user(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users/nobody@example.com/reset-link", headers=csrf
    )
    assert r.status_code == 404


def test_reset_link_is_admin_only(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "ivy@example.com", "password": "ivy-pw-1234"},
        headers=csrf,
    )
    # Become a non-admin, then try to mint a link for someone else.
    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    _login(admin_client, "ivy@example.com", "ivy-pw-1234", csrf2)
    r = admin_client.post(
        "/_admin/api/users/boss@example.com/reset-link", headers=csrf2
    )
    assert r.status_code == 403


def test_change_own_password_enforces_minimum_length(admin_client):
    """Same floor as the reset flow — the two ways to set a password agree."""
    csrf = _csrf(admin_client)
    _register(admin_client, "jo@example.com", "starting-pw", csrf)
    r = admin_client.post(
        "/auth/me/password",
        json={"old_password": "starting-pw", "new_password": "short"},
        headers=csrf,
    )
    assert r.status_code == 400
    # And the old password still works.
    admin_client.post("/auth/logout", headers=csrf)
    csrf2 = _csrf(admin_client)
    assert (
        _login(admin_client, "jo@example.com", "starting-pw", csrf2).status_code == 200
    )


# --- connectors declared public are not reported as world-open --------------


def _connector_client(tmp_path, monkeypatch, *, oauth_server=None):
    """Gateway with a `public` app that is really gated by the OAuth allowlist.

    That is the shape of every MCP connector: enlace must not gate it at the
    session layer (the connector validates its own bearer tokens), so its
    app.toml says `access = "public"`. The dashboard has to distinguish that
    from an app anyone can read.
    """
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    connector = apps_dir / "snout_mcp"
    connector.mkdir()
    (connector / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
    )
    (connector / "app.toml").write_text('access = "public"\n')

    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@example.com")
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            "oauth_server": oauth_server
            or {
                "enabled": False,  # the allowlist is read regardless
                "resource_allowlist": {
                    "https://apps.example.com/api/snout_mcp/mcp": [
                        "jack@trufflepig.com",
                        "greg@trufflepig.com",
                    ]
                },
            },
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    config = discover_apps(config)
    client = TestClient(build_backend(config, plugins=[auth_plugin]))
    client.user_store_root = tmp_path / "platform"  # read by _register
    return client


def _apps_by_name(client):
    csrf = _csrf(client)
    _register(client, "boss@example.com", "bosspw1!", csrf)
    r = client.get("/_admin/api/apps")
    assert r.status_code == 200, r.text
    return {a["name"]: a for a in r.json()["apps"]}


def test_public_connector_reports_who_its_oauth_allowlist_admits(tmp_path, monkeypatch):
    apps = _apps_by_name(_connector_client(tmp_path, monkeypatch))
    connector = apps["snout_mcp"]
    assert connector["access"] == "public"  # unchanged — enlace really doesn't gate it
    gates = connector["oauth_resources"]
    assert len(gates) == 1
    assert gates[0]["resource"].endswith("/api/snout_mcp/mcp")
    # Path is parsed server-side; the dashboard renders it verbatim.
    assert gates[0]["path"] == "/api/snout_mcp/mcp"
    assert gates[0]["allowed_users"] == ["greg@trufflepig.com", "jack@trufflepig.com"]


def test_genuinely_public_app_carries_no_oauth_annotation(tmp_path, monkeypatch):
    """The badge must mean something — an app with no allowlist doesn't get it."""
    apps = _apps_by_name(_connector_client(tmp_path, monkeypatch))
    assert "oauth_resources" not in apps["ping"]


def test_dashboard_says_what_an_unlisted_connector_gets(tmp_path, monkeypatch):
    """#39: no row can mark an unlisted connector, so the policy line must say it.

    Also: ``["*"]`` is reported as "every account", not as a user called ``*``;
    a listed resource no app serves is surfaced; and a prefix only claims its own
    path segment (``/api/snout_mcp`` must not claim ``/api/snout_mcp_beta``).
    """
    client = _connector_client(
        tmp_path,
        monkeypatch,
        oauth_server={
            "enabled": True,
            "key_dir": str(tmp_path / "keys"),
            "resource_allowlist": {
                "https://apps.example.com/api/snout_mcp/mcp": ["*"],
                "https://apps.example.com/api/snout_mcp_beta/mcp": ["a@example.com"],
            },
        },
    )
    csrf = _csrf(client)
    _register(client, "boss@example.com", "bosspw1!", csrf)
    body = client.get("/_admin/api/apps").json()
    policy = body["oauth_policy"]
    assert policy["enabled"] is True
    assert policy["unlisted"] == "refused"
    assert [r["path"] for r in policy["unmatched_resources"]] == [
        "/api/snout_mcp_beta/mcp"
    ]
    (gate,) = {a["name"]: a for a in body["apps"]}["snout_mcp"]["oauth_resources"]
    assert gate["any_account"] is True
    assert gate["allowed_users"] == []


def test_dashboard_policy_is_quiet_when_the_oauth_server_is_off(tmp_path, monkeypatch):
    client = _connector_client(tmp_path, monkeypatch)
    csrf = _csrf(client)
    _register(client, "boss@example.com", "bosspw1!", csrf)
    policy = client.get("/_admin/api/apps").json()["oauth_policy"]
    assert policy["enabled"] is False
    assert policy["unlisted"] == "n/a"


def _apps_listing(apps, **router_kwargs):
    """``GET /_admin/api/apps`` from a bare admin router, as an admin."""
    from types import SimpleNamespace

    from fastapi import FastAPI

    from enlace_auth.admin.routes import make_admin_router
    from enlace_auth.auth.sessions import SessionStore

    app = FastAPI()

    @app.middleware("http")
    async def _as_admin(request, call_next):
        request.state.user_email = "boss@example.com"
        return await call_next(request)

    app.include_router(
        make_admin_router(
            user_store={},
            session_store=SessionStore({}),
            admin_emails=("boss@example.com",),
            apps=[
                SimpleNamespace(access="public", allowed_users=[], **a) for a in apps
            ],
            **router_kwargs,
        )
    )
    return TestClient(app).get("/_admin/api/apps").json()


def test_a_nested_connector_gets_its_own_gate_not_its_parents():
    """Review of #39: first-match hung /api/x_mcp's entry on the /api row, so an
    open connector looked unlisted (and so, by the policy line, closed)."""
    body = _apps_listing(
        [
            {"name": "api", "route_prefix": "/api"},
            {"name": "x_mcp", "route_prefix": "/api/x_mcp"},
        ],
        resource_allowlist={"https://apps.example.com/api/x_mcp/mcp": ["*"]},
        oauth_server_enabled=True,
        public_base_url="https://apps.example.com",
    )
    rows = {a["name"]: a for a in body["apps"]}
    assert "oauth_resources" not in rows["api"]
    (gate,) = rows["x_mcp"]["oauth_resources"]
    assert gate["any_account"] is True


def test_a_resource_on_another_origin_is_listed_as_stray():
    """Matching on the path alone would put another host's grant on a local row."""
    body = _apps_listing(
        [{"name": "x_mcp", "route_prefix": "/api/x_mcp"}],
        resource_allowlist={
            "https://elsewhere.example/api/x_mcp/mcp": ["a@example.com"]
        },
        oauth_server_enabled=True,
        public_base_url="https://apps.example.com",
    )
    assert "oauth_resources" not in body["apps"][0]
    assert [r["resource"] for r in body["oauth_policy"]["unmatched_resources"]] == [
        "https://elsewhere.example/api/x_mcp/mcp"
    ]


# --- account operations: disable / enable, last sign-in, sign out everywhere ---

DORA, DORA_PW = "dora@example.com", "dora-password"


def _alive(client: TestClient) -> bool:
    """Whether *client*'s session still opens an any-signed-in-user app."""
    return client.get("/api/lobby/").status_code != 401


def _setup(admin_client):
    """Admin signed in on *admin_client*; Dora signed in on a second browser."""
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users", json={"email": DORA, "password": DORA_PW}, headers=csrf
    )
    assert r.status_code == 200, r.text
    dora = TestClient(admin_client.app)
    assert _login(dora, DORA, DORA_PW, _csrf(dora)).status_code == 200
    assert _alive(dora)
    return csrf, dora


def _users(admin_client) -> dict:
    r = admin_client.get("/_admin/api/users")
    assert r.status_code == 200, r.text
    return {u["email"]: u for u in r.json()["users"]}


def test_last_sign_in_is_listed(admin_client):
    csrf, _ = _setup(admin_client)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "eve@example.com", "password": "eve-password"},
        headers=csrf,
    )
    users = _users(admin_client)
    assert users[DORA]["last_login_at"] is not None
    assert users["eve@example.com"]["last_login_at"] is None
    assert users[DORA]["disabled_at"] is None


def test_sign_out_everywhere_ends_sessions_but_keeps_the_account(admin_client):
    csrf, dora = _setup(admin_client)
    r = admin_client.post(f"/_admin/api/users/{DORA}/sign-out", headers=csrf)
    assert r.status_code == 200, r.text
    assert not _alive(dora)
    assert _alive(admin_client)  # the admin's own session is untouched
    assert _login(dora, DORA, DORA_PW, _csrf(dora)).status_code == 200


def test_disable_blocks_every_sign_in_path_until_enabled(admin_client):
    csrf, dora = _setup(admin_client)
    r = admin_client.post(f"/_admin/api/users/{DORA}/disable", headers=csrf)
    assert r.status_code == 200, r.text
    assert not _alive(dora)
    assert _users(admin_client)[DORA]["disabled_at"] is not None

    dcsrf = _csrf(dora)
    assert _login(dora, DORA, DORA_PW, dcsrf).status_code == 403
    # The wrong password still gets the generic answer: "disabled" is only
    # said to someone who already holds the credentials.
    assert _login(dora, DORA, "wrong-password", dcsrf).status_code == 401

    link = admin_client.post(f"/_admin/api/users/{DORA}/reset-link", headers=csrf)
    token = link.json()["url"].split("token=", 1)[1]
    redeem = dora.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "a-new-password"},
        headers=dcsrf,
    )
    assert redeem.status_code == 403
    assert not _alive(dora)

    r = admin_client.post(f"/_admin/api/users/{DORA}/enable", headers=csrf)
    assert r.status_code == 200, r.text
    assert _login(dora, DORA, DORA_PW, dcsrf).status_code == 200  # old password
    assert _alive(dora)


def test_an_admin_cannot_disable_themselves(admin_client):
    csrf, _ = _setup(admin_client)
    r = admin_client.post("/_admin/api/users/boss@example.com/disable", headers=csrf)
    assert r.status_code == 409
    assert _alive(admin_client)


def test_account_ops_404_on_unknown_and_refuse_non_admins(admin_client):
    csrf, dora = _setup(admin_client)
    for op in ("sign-out", "disable", "enable"):
        r = admin_client.post(f"/_admin/api/users/ghost@example.com/{op}", headers=csrf)
        assert r.status_code == 404, op
        r = dora.post(f"/_admin/api/users/{DORA}/{op}", headers=_csrf(dora))
        assert r.status_code in (401, 403), op
    assert _alive(dora)


def test_a_disabled_account_is_not_active_for_connector_refresh():
    store = {"a@x.io": {"created_at": 0}, "b@x.io": {"disabled_at": 1.0}}
    is_active = _make_is_active(store)
    assert is_active("a@x.io")
    assert not is_active("b@x.io")
    assert not is_active("nobody@x.io")
    assert is_disabled(store["b@x.io"])


def test_new_account_routes_need_the_csrf_token(admin_client):
    csrf, dora = _setup(admin_client)
    for op in ("sign-out", "disable", "enable"):
        r = admin_client.post(f"/_admin/api/users/{DORA}/{op}")
        assert r.status_code == 403, op
    assert _alive(dora)


def test_a_sign_in_racing_a_disable_does_not_keep_its_session():
    """open_session re-checks after creating: the late session is deleted."""
    import pytest
    from fastapi import HTTPException

    from enlace_auth.auth.accounts import open_session, set_disabled
    from enlace_auth.auth.sessions import SessionStore

    users = {DORA: {"created_at": 0}}
    sign_ins = {}

    class RacingStore(SessionStore):
        def create(self, user_id, email=None):
            sid = super().create(user_id, email)
            set_disabled(users, DORA, True)  # the admin's disable lands here
            return sid

    sessions = RacingStore({}, sign_ins=sign_ins)
    with pytest.raises(HTTPException) as exc:
        open_session(sessions, users, DORA)
    assert exc.value.status_code == 403
    assert sessions.revoke_user(DORA) == 0  # nothing left behind

    ok = SessionStore({}, sign_ins=sign_ins)
    set_disabled(users, DORA, False)
    assert ok.get(open_session(ok, users, DORA))["email"] == DORA
    assert ok.last_sign_in(DORA) is not None
    assert "last_login_at" not in users[DORA]


def test_admins_can_be_declared_in_platform_config(tmp_path, monkeypatch):
    """[auth] admin_emails grants admin with no secrets-file edit."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.delenv("ENLACE_ADMIN_EMAILS", raising=False)
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "admin_emails": ["Chief@Example.com"],
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
    )
    client = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))
    _seed_account(tmp_path / "platform", "chief@example.com", "chief-password")
    csrf = _csrf(client)
    assert (
        _login(client, "chief@example.com", "chief-password", csrf).status_code == 200
    )
    r = client.get("/_admin/api/users")
    assert r.status_code == 200, r.text
    assert {u["email"]: u["is_admin"] for u in r.json()["users"]} == {
        "chief@example.com": True
    }


def test_declared_and_env_admins_are_unioned(monkeypatch):
    from enlace_auth.config import AuthConfig
    from enlace_auth.plugin import platform_admin_emails

    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "b@x.io, A@x.io")
    cfg = AuthConfig(admin_emails=["a@x.io", "c@x.io"])
    assert platform_admin_emails(cfg) == ("a@x.io", "c@x.io", "b@x.io")


def test_a_non_admin_still_gets_a_sign_in_answer_from_an_app(admin_client):
    """The 403 is the admin page's; apps keep the sign-in answer (unchanged)."""
    csrf = _csrf(admin_client)
    _register(admin_client, "alice@example.com", "secretpw1", csrf)
    assert admin_client.get("/api/vault/thing").status_code == 401


@pytest.mark.parametrize("bad", ["admin", "a@x.io,b@x.io", "a b@x.io", "a@@x.io"])
def test_declared_admin_entries_must_be_single_addresses(bad):
    from pydantic import ValidationError

    from enlace_auth.config import AuthConfig

    with pytest.raises(ValidationError, match="single email"):
        AuthConfig(admin_emails=[bad])


def test_the_admin_403_page_cannot_be_framed(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "alice@example.com", "secretpw1", csrf)
    r = admin_client.get("/_admin/", headers={"Accept": "text/html"})
    assert r.status_code == 403
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
