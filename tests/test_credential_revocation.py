"""Credential changes end connector sessions and shared-password cookies too.

i2mint/enlace_auth#26: #25 made a password change revoke an account's browser
sessions; these tests pin the two credential kinds it left alive -- the
account's OAuth connector refresh-token families, and ``shared_auth_<app>``
cookies minted under a shared password that has since been rotated -- plus the
bounded session sweep.
"""

from __future__ import annotations

import time

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth import hash_password
from enlace_auth.auth.revocation import (
    make_on_credentials_changed,
    revoke_refresh_subject,
    revoked_family_key,
    shared_cookie_valid,
    shared_password_fingerprint,
)
from enlace_auth.auth.sessions import SessionStore
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import (
    _SIGNING_KEY,
    _csrf,
    _login,
    _register,
    _write_dummy_app,
)
from tests.test_auth_e2e import _make_apps


def _refresh_record(family: str, email: str) -> dict:
    now = int(time.time())
    return {
        "family": family,
        "client_id": "c",
        "resource": "https://x/api/mcp",
        "scope": "mcp:read",
        "email": email,
        "iat": now,
        "exp": now + 3600,
        "family_exp": now + 7200,
        "consumed_at": None,
        "successor": None,
    }


# ---- unit: revocation helpers ------------------------------------------------


def test_revoke_refresh_subject_tombstones_only_that_subjects_families():
    store = {
        "t1": _refresh_record("f1", "Vic@Example.com"),
        "t2": {**_refresh_record("f1", "vic@example.com"), "consumed_at": 1},
        "t3": _refresh_record("f2", "vic@example.com"),
        "t4": _refresh_record("f3", "bob@example.com"),
    }
    codes = {
        "c1": {"email": "VIC@example.com", "exp": 1},
        "c2": {"email": "bob@example.com", "exp": 1},
    }
    n = revoke_refresh_subject(
        store, "vic@EXAMPLE.com", reason="t", tombstone_ttl=100, code_store=codes
    )
    assert n == 2
    assert revoked_family_key("f1") in store and revoked_family_key("f2") in store
    live = {k for k, v in store.items() if "family" in v}
    assert live == {"t4"}, "bob's family must survive"
    assert set(codes) == {"c2"}, "vic's unredeemed codes must go"


def test_revoke_refresh_subject_rejects_empty_email():
    with pytest.raises(ValueError):
        revoke_refresh_subject({}, "", reason="t", tombstone_ttl=1)


def test_hook_revokes_sessions_and_families_and_spares_keep():
    sessions = SessionStore({})
    keep = sessions.create("vic@example.com", "vic@example.com")
    other = sessions.create("vic@example.com", "vic@example.com")
    refresh = {"t1": _refresh_record("f1", "vic@example.com")}
    hook = make_on_credentials_changed(
        sessions, refresh_store=refresh, tombstone_ttl=10
    )
    hook("vic@example.com", keep=keep)
    assert sessions.get(keep) is not None
    assert sessions.get(other) is None
    assert "t1" not in refresh and revoked_family_key("f1") in refresh


def test_hook_requires_a_tombstone_ttl_with_a_refresh_store():
    with pytest.raises(ValueError):
        make_on_credentials_changed(SessionStore({}), refresh_store={})


def test_shared_cookie_fingerprint_binds_the_current_hash():
    fp = shared_password_fingerprint("h1", "k")
    assert shared_cookie_valid(fp, "h1", "k")
    assert not shared_cookie_valid(fp, "h2", "k")
    assert not shared_cookie_valid("1", "h1", "k"), "legacy constant cookie"
    assert not shared_cookie_valid(fp, None, "k")
    assert "h1" not in fp


def test_session_sweep_drops_only_expired_records():
    backend: dict = {}
    sessions = SessionStore(backend, max_age=60, sweep_batch=10)
    backend["old"] = {"user_id": "a", "email": "a", "created_at": time.time() - 120}
    backend["legacy"] = {"user_id": "a", "email": "a"}  # no created_at: kept
    fresh = sessions.create("b", "b")  # create() sweeps
    assert "old" not in backend
    assert "legacy" in backend and fresh in backend


def test_session_sweep_is_bounded_and_walks_the_whole_store():
    backend = {
        f"s{i}": {"user_id": "a", "created_at": time.time() - 999} for i in range(25)
    }
    sessions = SessionStore(backend, max_age=60, sweep_batch=10)
    assert sessions.sweep_expired() == 10
    while backend:
        assert sessions.sweep_expired() <= 10
    assert not backend


def test_session_sweep_is_a_noop_without_max_age():
    backend = {"old": {"user_id": "a", "created_at": 0}}
    SessionStore(backend).create("b")
    assert "old" in backend


# ---- end to end through the plugin -------------------------------------------


@pytest.fixture
def platform(tmp_path, monkeypatch):
    """A gateway with the OAuth server (and so refresh families) enabled."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@example.com")
    store_root = tmp_path / "platform"
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(store_root)},
            "oauth_server": {"enabled": True, "key_dir": str(tmp_path / "keys")},
        },
    )
    app = build_backend(discover_apps(config), plugins=[auth_plugin])
    factory = make_file_store_factory(str(store_root))
    return TestClient(app), factory("oauth_refresh_tokens"), factory("oauth_codes")


def _seed(refresh, codes):
    refresh["tok-vic"] = _refresh_record("fvic", "vic@example.com")
    refresh["tok-bob"] = _refresh_record("fbob", "bob@example.com")
    codes["code-vic"] = {"email": "vic@example.com", "exp": int(time.time()) + 60}


def _families_left(refresh) -> set:
    out = set()
    for k in refresh:
        rec = refresh[k]
        if "family" in rec:
            out.add(rec["family"])
    return out


def test_admin_password_set_revokes_connector_families(platform):
    client, refresh, codes = platform
    csrf = _csrf(client)
    _register(client, "boss@example.com", "bosspw1!", csrf)
    r = client.post(
        "/_admin/api/users",
        json={"email": "vic@example.com", "password": "victim-pw1"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    _seed(refresh, codes)
    r = client.post(
        "/_admin/api/users/vic@example.com/password",
        json={"password": "brand-new-pw1"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    assert _families_left(refresh) == {"fbob"}
    assert refresh.get(revoked_family_key("fvic")) is not None
    assert "code-vic" not in codes


def test_admin_delete_revokes_connector_families(platform):
    client, refresh, codes = platform
    csrf = _csrf(client)
    _register(client, "boss@example.com", "bosspw1!", csrf)
    client.post(
        "/_admin/api/users",
        json={"email": "vic@example.com", "password": "victim-pw1"},
        headers=csrf,
    )
    _seed(refresh, codes)
    r = client.delete("/_admin/api/users/vic@example.com", headers=csrf)
    assert r.status_code == 200, r.text
    assert _families_left(refresh) == {"fbob"}


def test_self_service_password_change_revokes_connector_families(platform):
    client, refresh, codes = platform
    csrf = _csrf(client)
    _register(client, "vic@example.com", "victim-pw1", csrf)
    assert _login(client, "vic@example.com", "victim-pw1", csrf).status_code == 200
    _seed(refresh, codes)
    r = client.post(
        "/auth/me/password",
        json={"old_password": "victim-pw1", "new_password": "brand-new-pw1"},
        headers=_csrf(client),
    )
    assert r.status_code == 200, r.text
    assert _families_left(refresh) == {"fbob"}
    assert client.get("/auth/whoami").json()["email"] == "vic@example.com", (
        "the browser that changed its own password stays signed in"
    )


def _shared_platform(tmp_path, monkeypatch, password: str) -> TestClient:
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir(exist_ok=True)
    if not (apps_dir / "shared_app").exists():
        _make_apps(apps_dir)
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("SHARED_APP_PW", hash_password(password))
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
    )
    return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))


def test_rotating_a_shared_password_ends_old_cookies(tmp_path, monkeypatch):
    before = _shared_platform(tmp_path, monkeypatch, "open-sesame")
    csrf = _csrf_shared(before)
    r = before.post(
        "/auth/shared-login",
        json={"app": "shared_app", "password": "open-sesame"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    cookie = before.cookies.get("shared_auth_shared_app")
    assert cookie
    assert before.get("/api/shared_app/peek").status_code == 200

    # Restart with a rotated password: the old cookie must no longer work.
    after = _shared_platform(tmp_path, monkeypatch, "new-sesame")
    after.cookies.set("shared_auth_shared_app", cookie)
    assert after.get("/api/shared_app/peek").status_code == 401


def _csrf_shared(client: TestClient) -> dict:
    from enlace_auth.auth.cookies import verify_cookie

    client.get("/api/public_app/ping")
    raw = verify_cookie(client.cookies.get("enlace_csrf"), _SIGNING_KEY, salt="csrf")
    return {"X-CSRF-Token": raw}
