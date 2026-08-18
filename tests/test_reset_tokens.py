"""Tests for ``enlace_auth.auth.reset_tokens`` — the reset-link SSOT.

Covers the two properties the shape is built for (single use via the password
fingerprint, per-link lifetime via the embedded expiry) plus the usual
signature/tamper rejections. Exercises the module directly rather than through
HTTP so the token semantics are pinned independently of any route.
"""

from __future__ import annotations

import time

import pytest

from enlace_auth.auth.cookies import sign_cookie
from enlace_auth.auth.passwords import hash_password
from enlace_auth.auth.reset_tokens import (
    MAX_TTL_SECONDS,
    RESET_SALT,
    mint_reset_token,
    password_fingerprint,
    reset_url,
    verify_reset_token,
)

KEY = "reset-token-test-key-32bytes-min!!!!"
OTHER_KEY = "a-completely-different-key-32bytes!!!"


@pytest.fixture
def store():
    return {"alice@example.com": {"password_hash": hash_password("oldpw123")}}


def _mint(store, *, ttl=1800, email="alice@example.com", key=KEY):
    return mint_reset_token(
        record=store[email], email=email, signing_key=key, ttl_seconds=ttl
    )


def test_roundtrip_returns_email_and_record(store):
    email, record = verify_reset_token(_mint(store), signing_key=KEY, user_store=store)
    assert email == "alice@example.com"
    assert record == store["alice@example.com"]


def test_token_is_single_use_via_password_fingerprint(store):
    token = _mint(store)
    # Consuming the link is modelled by the password changing.
    store["alice@example.com"] = {"password_hash": hash_password("newpw456")}
    assert verify_reset_token(token, signing_key=KEY, user_store=store) == (None, None)


def test_any_password_change_invalidates_outstanding_tokens(store):
    first = _mint(store)
    second = _mint(store)
    store["alice@example.com"] = {"password_hash": hash_password("changed-elsewhere")}
    for token in (first, second):
        assert verify_reset_token(token, signing_key=KEY, user_store=store) == (
            None,
            None,
        )


def test_expiry_is_per_link_not_per_verifier(store):
    """The whole point of embedding the expiry: one verifier, two lifetimes."""
    short = _mint(store, ttl=1)
    long = _mint(store, ttl=3600)
    time.sleep(1.1)
    assert verify_reset_token(short, signing_key=KEY, user_store=store) == (None, None)
    email, _ = verify_reset_token(long, signing_key=KEY, user_store=store)
    assert email == "alice@example.com"


def test_ttl_is_clamped_to_the_ceiling(store):
    token = mint_reset_token(
        record=store["alice@example.com"],
        email="alice@example.com",
        signing_key=KEY,
        ttl_seconds=MAX_TTL_SECONDS * 100,
    )
    from enlace_auth.auth.cookies import verify_cookie

    _, expires_raw, _ = verify_cookie(token, KEY, salt=RESET_SALT).split("|", 2)
    assert int(expires_raw) <= time.time() + MAX_TTL_SECONDS + 1


def test_rejects_token_signed_with_another_key(store):
    token = _mint(store, key=OTHER_KEY)
    assert verify_reset_token(token, signing_key=KEY, user_store=store) == (None, None)


def test_rejects_token_minted_under_another_salt(store):
    """A session or CSRF token must never verify as a reset token."""
    payload = "|".join(
        (
            password_fingerprint(store["alice@example.com"]),
            str(int(time.time()) + 600),
            "alice@example.com",
        )
    )
    token = sign_cookie(payload, KEY, salt="session")
    assert verify_reset_token(token, signing_key=KEY, user_store=store) == (None, None)


@pytest.mark.parametrize("token", ["", "garbage", "a.b.c", "x" * 200])
def test_rejects_malformed_tokens(store, token):
    assert verify_reset_token(token, signing_key=KEY, user_store=store) == (None, None)


def test_rejects_wellformed_token_for_unknown_user(store):
    token = mint_reset_token(
        record={"password_hash": hash_password("x")},
        email="nobody@example.com",
        signing_key=KEY,
    )
    assert verify_reset_token(token, signing_key=KEY, user_store=store) == (None, None)


def test_reset_url_encodes_the_token_and_normalizes_the_base():
    url = reset_url("https://apps.example.com/", "tok en+/=")
    assert url.startswith("https://apps.example.com/auth/reset-password?token=")
    assert " " not in url and "+" not in url.split("token=", 1)[1]
