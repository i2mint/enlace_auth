"""Tests for the browser-facing auth pages and the password-recovery flow.

Exercises ``make_auth_router`` directly (no middleware) for the sign-in page,
the forgot/reset endpoints, single-use token semantics, and the shared page
renderers in ``enlace_auth.auth.pages``.
"""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from enlace_auth.auth import SessionStore, hash_password, pages
from enlace_auth.auth.routes import make_auth_router

KEY = "recovery-test-key-32bytes-minimum!!!"


def _make(users=None):
    """Build a TestClient over a bare auth router plus a capturing email sink."""
    users = {} if users is None else users
    sessions = SessionStore({})
    sent: list[dict] = []

    def sender(*, to, subject, body):
        sent.append({"to": to, "subject": subject, "body": body})

    router = make_auth_router(
        session_store=sessions,
        user_store=users,
        signing_key=KEY,
        secure_cookies=False,
        can_register=lambda _email: True,
        send_email=sender,
        reset_token_max_age=1800,
    )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), users, sent


def _one_user():
    return {
        "alice@example.com": {
            "password_hash": hash_password("oldpw123"),
            "created_at": 0,
        }
    }


def _token_from(sent: list[dict]) -> str:
    match = re.search(r"token=(\S+)", sent[-1]["body"])
    assert match, f"no token in email body: {sent[-1]['body']!r}"
    return match.group(1)


# --- sign-in page ----------------------------------------------------------


def test_login_page_renders():
    client, _, _ = _make()
    r = client.get("/auth/login")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Sign in" in r.text and 'id="password"' in r.text


def test_login_page_threads_next_into_form():
    client, _, _ = _make()
    r = client.get("/auth/login", params={"next": "/xa/"})
    assert 'NEXT = "/xa/"' in r.text


def test_login_page_rejects_external_next():
    client, _, _ = _make()
    r = client.get("/auth/login", params={"next": "https://evil.example/x"})
    assert "evil.example" not in r.text  # open-redirect guarded


def test_forgot_password_page_renders():
    client, _, _ = _make()
    r = client.get("/auth/forgot-password")
    assert r.status_code == 200
    assert "reset" in r.text.lower()


# --- reset request ---------------------------------------------------------


def test_reset_request_known_user_sends_link():
    client, _, sent = _make(_one_user())
    r = client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert len(sent) == 1
    assert "/auth/reset-password?token=" in sent[0]["body"]


def test_reset_request_unknown_user_is_silent():
    client, _, sent = _make()
    r = client.post(
        "/auth/password-reset/request", json={"email": "nobody@example.com"}
    )
    # Same 200 response, but no email — so it can't be used to enumerate users.
    assert r.status_code == 200 and r.json() == {"ok": True}
    assert sent == []


# --- reset confirm ---------------------------------------------------------


def test_reset_confirm_changes_password_and_signs_in():
    client, _, sent = _make(_one_user())
    client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    token = _token_from(sent)

    r = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "brandnewpw"},
    )
    assert r.status_code == 200
    assert "enlace_session" in r.cookies  # confirm logs the user straight in

    old = client.post(
        "/auth/login", json={"email": "alice@example.com", "password": "oldpw123"}
    )
    assert old.status_code == 401
    new = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "brandnewpw"},
    )
    assert new.status_code == 200


def test_reset_token_is_single_use():
    client, _, sent = _make(_one_user())
    client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    token = _token_from(sent)

    first = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "firstnewpw"},
    )
    assert first.status_code == 200
    # The same token no longer verifies — the password fingerprint changed.
    again = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "secondpw99"},
    )
    assert again.status_code == 400


def test_reset_confirm_rejects_garbage_token():
    client, _, _ = _make(_one_user())
    r = client.post(
        "/auth/password-reset/confirm",
        json={"token": "not-a-real-token", "new_password": "whatever123"},
    )
    assert r.status_code == 400


def test_reset_confirm_rejects_short_password():
    client, _, sent = _make(_one_user())
    client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    token = _token_from(sent)
    r = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "short"},
    )
    assert r.status_code == 400


# --- reset page ------------------------------------------------------------


def test_reset_page_bad_token_shows_notice():
    client, _, _ = _make()
    r = client.get("/auth/reset-password", params={"token": "garbage"})
    assert r.status_code == 400
    assert "invalid or expired" in r.text.lower()


def test_reset_page_good_token_shows_form():
    client, _, sent = _make(_one_user())
    client.post("/auth/password-reset/request", json={"email": "alice@example.com"})
    token = _token_from(sent)
    r = client.get("/auth/reset-password", params={"token": token})
    assert r.status_code == 200
    assert "new password" in r.text.lower()


# --- open-redirect guard ---------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/xa/", "/xa/"),
        ("//evil.com", "/"),
        ("https://evil.com", "/"),
        ("/ok?x=1", "/ok?x=1"),
        (None, "/"),
        ("", "/"),
    ],
)
def test_safe_next_guards_open_redirect(raw, expected):
    assert pages.safe_next(raw) == expected
