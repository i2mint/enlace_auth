"""Sessions must end when the account they belong to changes hands.

A session outlives its cookie's signature only as long as ``session_max_age``
(30 days on a typical deployment). Deleting a user, or resetting a password
because an account was compromised, therefore has to revoke the sessions that
account already holds -- otherwise the person being locked out keeps full
access until the cookie expires on its own.

Each test uses TWO clients: the "holder" whose session should die, and the
actor (admin, or the holder in another browser) who triggers the change.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from enlace_auth.auth.sessions import SessionStore

from tests.test_admin import (  # noqa: F401 - fixture re-export
    _SIGNING_KEY,
    _csrf,
    _login,
    _register,
    admin_client,
)


def _second_client(admin_client: TestClient) -> TestClient:
    """A separate browser against the same app (its own cookie jar)."""
    return TestClient(admin_client.app)


def _setup_admin_and_user(admin_client, email="vic@example.com", pw="victim-pw1"):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users", json={"email": email, "password": pw}, headers=csrf
    )
    assert r.status_code == 200, r.text
    holder = _second_client(admin_client)
    assert _login(holder, email, pw, _csrf(holder)).status_code == 200
    assert holder.get("/auth/whoami").json()["email"] == email
    assert holder.get("/api/lobby/").status_code != 401
    return csrf, holder


def test_deleting_a_user_ends_their_sessions(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client)
    r = admin_client.delete("/_admin/api/users/vic@example.com", headers=csrf)
    assert r.status_code == 200, r.text
    assert holder.get("/api/lobby/").status_code == 401
    assert holder.get("/auth/whoami").json()["email"] is None


def test_admin_password_reset_ends_existing_sessions(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client)
    r = admin_client.post(
        "/_admin/api/users/vic@example.com/password",
        json={"password": "fresh-password"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    assert holder.get("/api/lobby/").status_code == 401


def test_changing_own_password_ends_other_sessions_but_keeps_this_one(admin_client):
    _csrf_admin, holder = _setup_admin_and_user(admin_client)
    other_browser = _second_client(admin_client)
    assert (
        _login(other_browser, "vic@example.com", "victim-pw1", _csrf(other_browser))
        .status_code
        == 200
    )
    r = holder.post(
        "/auth/me/password",
        json={"old_password": "victim-pw1", "new_password": "rotated-pw1"},
        headers=_csrf(holder),
    )
    assert r.status_code == 200, r.text
    # The browser that changed the password stays signed in...
    assert holder.get("/auth/whoami").json()["email"] == "vic@example.com"
    # ...every other session of that account is gone.
    assert other_browser.get("/api/lobby/").status_code == 401


def test_reset_link_ends_existing_sessions(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client)
    r = admin_client.post("/_admin/api/users/vic@example.com/reset-link", headers=csrf)
    assert r.status_code == 200, r.text
    link = r.json()["url"] if "url" in r.json() else r.json()["link"]
    token = link.split("token=", 1)[1]
    from urllib.parse import unquote

    fresh = _second_client(admin_client)
    r = fresh.post(
        "/auth/password-reset/confirm",
        json={"token": unquote(token), "new_password": "brand-new-pw"},
        headers=_csrf(fresh),
    )
    assert r.status_code == 200, r.text
    assert holder.get("/api/lobby/").status_code == 401
    # The reset itself signs the resetting browser in.
    assert fresh.get("/auth/whoami").json()["email"] == "vic@example.com"


def test_other_users_sessions_survive(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client)
    bystander = _second_client(admin_client)
    _register(bystander, "bea@example.com", "bystander1", _csrf(bystander))
    admin_client.delete("/_admin/api/users/vic@example.com", headers=csrf)
    assert bystander.get("/auth/whoami").json()["email"] == "bea@example.com"
    assert admin_client.get("/auth/whoami").json()["email"] == "boss@example.com"


def test_session_store_revoke_user_matches_case_insensitively():
    store = SessionStore({})
    a = store.create(user_id="x@example.com", email="X@Example.com")
    b = store.create(user_id="x@example.com", email="x@example.com")
    c = store.create(user_id="y@example.com", email="y@example.com")
    assert store.revoke_user("x@EXAMPLE.com", keep=b) == 1
    assert store.get(a) is None
    assert store.get(b) is not None
    assert store.get(c) is not None


@pytest.mark.parametrize("bad", ["", None])
def test_session_store_revoke_user_refuses_empty(bad):
    store = SessionStore({})
    store.create(user_id="", email=None)
    with pytest.raises(ValueError):
        store.revoke_user(bad)


def test_cli_set_password_revokes_that_users_sessions(tmp_path, monkeypatch):
    from enlace_auth.__main__ import _load_session_store, _load_user_store, set_password
    from enlace_auth.auth.passwords import hash_password

    from tests.test_cli import _make_platform_toml

    toml = _make_platform_toml(tmp_path)
    _load_user_store(toml)["thor@example.com"] = {
        "password_hash": hash_password("old-secret"),
        "created_at": 0,
    }
    sessions = _load_session_store(toml)
    mine = sessions.create(user_id="thor@example.com", email="thor@example.com")
    theirs = sessions.create(user_id="ann@example.com", email="ann@example.com")

    inputs = iter(["fresh-secret", "fresh-secret"])
    monkeypatch.setattr("enlace_auth.__main__.getpass", lambda _: next(inputs))
    set_password("thor@example.com", toml=str(toml))

    assert sessions.get(mine) is None
    assert sessions.get(theirs) is not None
