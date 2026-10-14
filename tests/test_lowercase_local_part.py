"""A local part that lowercasing changes by more than case is refused (#57).

Keys are lowercased. For a few letters ``str.lower()`` changes the letter, not
its case: ``İ`` (U+0130) becomes ``i`` plus U+0307, ``ẞ`` (U+1E9E) becomes ``ß``.
A host that compares local parts as bytes reads that as another mailbox, and a
password reset is mailed to the key. Same stance as #51: refuse, never fold.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from enlace_auth.__main__ import _normalized_email
from enlace_auth.auth import SessionStore
from enlace_auth.config import OAuthProviderConfig
from enlace_auth.emails import (
    local_part_problem,
    lowercase_changes_letter,
    normalize_email,
)
from tests.test_admin import _csrf, _register, admin_client  # noqa: F401
from tests.test_admin_registration import _client, env  # noqa: F401

DOTTED_I = "İstanbul@example.com"  # İstanbul
CAPITAL_SHARP_S = "ẞig@example.com"  # ẞig
FOLDING = [DOTTED_I, CAPITAL_SHARP_S]


@pytest.mark.parametrize("email", FOLDING)
def test_normalize_email_refuses_a_letter_lowercasing_changes(email):
    assert "lowercased" in local_part_problem(email)
    with pytest.raises(ValueError, match="lowercased"):
        normalize_email(email)


@pytest.mark.parametrize(
    "email",
    [
        "Ann@Example.com",
        "JOSÉ@example.com",
        "ΟΔΟΣ@example.gr",
        "Ünï@x.de",
        "ß@example.de",
    ],
)
def test_ordinary_case_is_still_folded(email):
    """Plain case maps, Greek final sigma, and an already-lowercase ß are fine."""
    assert local_part_problem(email) is None
    assert normalize_email(email) == email.lower()


def test_only_the_local_part_is_judged():
    """The domain goes through IDNA, which maps it on its own terms."""
    assert lowercase_changes_letter("ann") is None
    assert local_part_problem("ann@İstanbul.example") is None


def test_add_user_refuses_and_says_why(capsys):
    with pytest.raises(SystemExit):
        _normalized_email(DOTTED_I)
    assert "lowercased" in capsys.readouterr().err


def test_register_refuses(env, tmp_path):  # noqa: F811
    env.setenv("ENLACE_REGISTRATION_ALLOWLIST", DOTTED_I)
    client = _client(tmp_path)
    r = _register(client, DOTTED_I, "dotted-i-pw-1", _csrf(client))
    assert r.status_code == 400, r.text
    assert "U+0130" in r.json()["detail"]


def _claims(email):
    return {"email": email, "email_verified": True, "sub": "s"}


def _open_oauth_app(users, claims):
    """An OAuth callback with registration OPEN, so only the new check refuses."""
    os.environ["G_ID"] = "fake-client-id"
    os.environ["G_SECRET"] = "fake-client-secret"
    from enlace_auth.auth.oauth import make_oauth_router

    fake = MagicMock()
    fake.authorize_redirect = AsyncMock(return_value=RedirectResponse("http://e/x"))
    fake.authorize_access_token = AsyncMock(return_value={"userinfo": claims})
    registry = MagicMock()
    registry.google = fake
    providers = {
        "google": OAuthProviderConfig(
            client_id_env="G_ID", client_secret_env="G_SECRET"
        )
    }
    with patch("enlace_auth.auth.oauth._build_oauth_registry", return_value=registry):
        router = make_oauth_router(
            providers=providers,
            session_store=SessionStore({}),
            user_store=users,
            signing_key="k" * 64,
            secure_cookies=False,
            can_register=lambda _email: True,
            admin_emails=(),
        )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.mark.parametrize("email", FOLDING)
def test_oauth_makes_no_account_for_it(email):
    users: dict = {}
    client = _open_oauth_app(
        users, {"email": email, "email_verified": True, "sub": "s"}
    )
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


def test_oauth_still_makes_an_ordinary_account():
    users: dict = {}
    client = _open_oauth_app(
        users, {"email": "Ann@example.com", "email_verified": True, "sub": "s"}
    )
    assert client.get("/auth/callback/google").status_code == 200
    assert list(users) == ["ann@example.com"]


def test_an_existing_account_keyed_so_still_signs_in():
    """Refuse at creation only: an account already keyed this way is not locked out."""
    key = DOTTED_I.lower()
    users = {
        key: {
            "password_hash": None,
            "oauth_provider": "google",
            "oauth_links": {"google": "s"},
        }
    }
    client = _open_oauth_app(
        users, {"email": DOTTED_I, "email_verified": True, "sub": "s"}
    )
    assert client.get("/auth/callback/google").status_code == 200
    assert list(users) == [key]


@pytest.mark.parametrize("sign", ["Ω", "Å"])  # OHM SIGN, ANGSTROM SIGN
def test_compatibility_signs_are_refused(sign):
    with pytest.raises(ValueError):
        normalize_email(f"{sign}x@example.com")


@pytest.mark.parametrize("digraph", ["ǅ", "ǈ", "ǋ", "ǲ"])
def test_titlecase_digraphs_are_a_case_map(digraph):
    assert lowercase_changes_letter(digraph) is None


def test_oauth_address_without_an_at_is_judged_whole():
    users: dict = {}
    client = _open_oauth_app(
        users, {"email": "İstanbul", "email_verified": True, "sub": "s"}
    )
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


def test_a_list_entry_that_lowercasing_changes_is_ignored(monkeypatch, caplog):
    """Lowercased, it names the twin mailbox: honouring it would hand an admin
    slot to whoever holds that twin, now that the real address can make none."""
    from enlace_auth.plugin import read_email_list

    monkeypatch.setenv("T_ADMINS", f"Boss@example.com, {DOTTED_I}")
    with caplog.at_level("WARNING", logger="enlace_auth"):
        assert read_email_list("T_ADMINS") == ("boss@example.com",)
    assert "U+0130" in caplog.text and "stanbul" not in caplog.text
    assert read_email_list("T_ADMINS", keep_unsafe=True) == (
        "boss@example.com",
        DOTTED_I.lower(),
    )


def test_admin_create_user_refuses(admin_client):  # noqa: F811
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users",
        json={"email": DOTTED_I, "password": "dotted-i-pw-1"},
        headers=csrf,
    )
    assert r.status_code == 400, r.text
    assert "lowercased" in r.json()["detail"]
