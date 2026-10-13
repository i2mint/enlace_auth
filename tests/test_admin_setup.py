"""How an admin account may come to exist (i2mint/enlace_auth#38).

Registration (open or allowlisted) never creates an admin account: it proves
nothing about who owns the address. An admin is made by ``enlace-auth
add-user``, by an existing admin through the admin API, or by a first sign-in
through an OAuth provider that itself verified the address. Every account
records how it was made (``created_via``), so ``doctor`` can point at an admin
account that was self-registered before this rule existed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from enlace import doctor as doctor_mod
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import RedirectResponse

from enlace_auth.auth import SessionStore
from enlace_auth.config import OAuthProviderConfig
from enlace_auth.plugin import _build_can_register
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import _csrf, _register
from tests.test_admin_registration import _ADMIN, _INVITED, _admin_check, _client, env

__all__ = ["env"]  # the fixture, re-exported for pytest

_OAUTH_KEY = "oauth-signing-key-32bytes-minlen"


# --- registration ------------------------------------------------------------


@pytest.mark.parametrize("registration_open", [True, False])
def test_registration_never_admits_an_admin_address(registration_open):
    cfg = type(
        "Cfg",
        (),
        {
            "registration_open": registration_open,
            "registration_allowlist_env": "ENLACE_TEST_NO_SUCH_VAR",
        },
    )()
    can_register = _build_can_register(cfg, (_ADMIN,))
    for spelling in (_ADMIN, _ADMIN.upper(), f"  {_ADMIN} "):
        assert not can_register(spelling)
    assert can_register("anyone@example.com") is registration_open


def test_open_registration_refuses_an_admin_address_end_to_end(env, tmp_path):
    from enlace.base import PlatformConfig
    from enlace.compose import build_backend
    from enlace.discover import discover_apps

    from enlace_auth import plugin as auth_plugin
    from tests.test_admin import _write_dummy_app
    from tests.test_admin_registration import _auth

    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    config = PlatformConfig(
        apps_dir=apps_dir, auth=_auth(tmp_path, registration_open=True)
    )
    client = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))
    csrf = _csrf(client)
    assert _register(client, _ADMIN.upper(), "attacker-pw1", csrf).status_code == 403
    assert (
        _register(client, "someone@example.com", "guest-pw-123", csrf).status_code
        == 200
    )


def test_registration_enforces_the_password_minimum(env, tmp_path):
    client = _client(tmp_path)
    csrf = _csrf(client)
    assert _register(client, _INVITED, "short", csrf).status_code == 400


def test_a_registered_account_records_how_it_was_made(env, tmp_path):
    client = _client(tmp_path)
    assert _register(client, _INVITED, "guest-pw-123", _csrf(client)).status_code == 200
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    assert users[_INVITED]["created_via"] == "register"


# --- OAuth first sign-in -----------------------------------------------------


def _oauth_app(users, claims, *, provider="google", provider_cfg=None):
    os.environ["G_ID"] = "fake-client-id"
    os.environ["G_SECRET"] = "fake-client-secret"
    from enlace_auth.auth.oauth import make_oauth_router

    fake_client = MagicMock()
    fake_client.authorize_redirect = AsyncMock(
        return_value=RedirectResponse("http://example.com/fake-authorize")
    )
    fake_client.authorize_access_token = AsyncMock(return_value={"userinfo": claims})
    registry = MagicMock()
    setattr(registry, provider, fake_client)
    providers = {
        provider: OAuthProviderConfig(
            client_id_env="G_ID", client_secret_env="G_SECRET", **(provider_cfg or {})
        )
    }
    with patch("enlace_auth.auth.oauth._build_oauth_registry", return_value=registry):
        router = make_oauth_router(
            providers=providers,
            session_store=SessionStore({}),
            user_store=users,
            signing_key=_OAUTH_KEY,
            secure_cookies=False,
            can_register=lambda _email: False,  # registration closed
            admin_emails=(_ADMIN,),
        )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_an_admin_can_be_set_up_by_a_verified_oauth_sign_in():
    users: dict = {}
    client = _oauth_app(
        users, {"email": _ADMIN.upper(), "email_verified": True, "sub": "g-123"}
    )
    assert client.get("/auth/callback/google").status_code == 200
    assert users[_ADMIN]["created_via"] == "oauth:google"
    assert users[_ADMIN]["password_hash"] is None


def test_the_github_preset_counts_as_verified_for_an_admin():
    users: dict = {}
    client = _oauth_app(users, {"email": _ADMIN, "id": 42}, provider="github")
    assert client.get("/auth/callback/github").status_code == 200
    assert _ADMIN in users


def test_an_admin_sign_in_without_a_provider_subject_is_refused():
    """No subject, no link: the account would open to any identity at the provider."""
    users: dict = {}
    client = _oauth_app(users, {"email": _ADMIN, "email_verified": True})
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


def test_trust_unverified_email_is_not_enough_to_create_an_admin():
    """The operator's opt-in says nothing about who owns the address."""
    users: dict = {}
    client = _oauth_app(
        users, {"email": _ADMIN}, provider_cfg={"trust_unverified_email": True}
    )
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


def test_a_non_admin_still_needs_registration_to_be_open():
    users: dict = {}
    client = _oauth_app(users, {"email": "x@example.com", "email_verified": True})
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


# --- doctor ------------------------------------------------------------------


def test_doctor_warns_about_a_self_registered_admin_account(
    env, tmp_path, single_app_dir
):
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": "x", "created_at": 0, "created_via": "register"}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.WARN
    assert "self-registration" in check.detail


def test_doctor_notes_admin_accounts_that_predate_provenance(
    env, tmp_path, single_app_dir
):
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": "x", "created_at": 0}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.PASS
    assert "predate created_via" in check.detail


# --- add-user ----------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
_RUNNER = """
import sys, getpass
answers = iter(sys.argv[1:3])
getpass.getpass = lambda prompt='': next(answers)
sys.argv = ['enlace-auth', 'add-user', *sys.argv[3:]]
from enlace_auth.__main__ import main
main()
"""


def _add_user(tmp_path, email, password):
    """Run ``enlace-auth add-user`` against a scratch platform.toml and HOME."""
    store = tmp_path / "platform"
    toml = tmp_path / "platform.toml"
    toml.write_text(
        f'[auth]\nenabled = true\n[auth.stores]\nbackend = "file"\npath = "{store}"\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", _RUNNER, password, password, email, "--toml", str(toml)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
        env={"PYTHONPATH": str(_ROOT), "PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
    )
    return result, make_file_store_factory(str(store))("users")


def test_add_user_creates_an_account_and_records_it(tmp_path):
    result, users = _add_user(tmp_path, "  New.Admin@Example.COM ", "long-enough-pw")
    assert result.returncode == 0, result.stderr
    assert users["new.admin@example.com"]["created_via"] == "add-user"


def test_add_user_rejects_a_short_password(tmp_path):
    result, users = _add_user(tmp_path, "a@example.com", "short")
    assert result.returncode == 1
    assert "at least" in result.stderr
    assert "a@example.com" not in users


@pytest.mark.parametrize("bad", ["not-an-email", "a@", "a b@example.com"])
def test_add_user_rejects_an_invalid_email(tmp_path, bad):
    result, _ = _add_user(tmp_path, bad, "long-enough-pw")
    assert result.returncode == 1
    assert "valid email" in result.stderr


# --- review follow-ups (i2mint/enlace_auth#41) ---------------------------------


def test_a_github_named_provider_on_other_endpoints_is_not_trusted():
    """The trust is in github.com, not in the word "github" (#41 item 1)."""
    users: dict = {}
    client = _oauth_app(
        users,
        {"email": _ADMIN, "id": 42},
        provider="github",
        provider_cfg={"userinfo_url": "https://idp.example.com/user"},
    )
    assert client.get("/auth/callback/github").status_code == 401
    assert users == {}


def test_an_oauth_account_records_whether_the_provider_verified_it():
    users: dict = {}
    client = _oauth_app(users, {"email": _ADMIN, "email_verified": True, "sub": "g-1"})
    assert client.get("/auth/callback/google").status_code == 200
    assert users[_ADMIN]["email_verified_by_provider"] is True


@pytest.mark.parametrize(
    "spelling",
    ["boss@ｅｘａｍｐｌｅ.com", "boss@example。com", "boss@\u24d4xample.com"],
)
def test_a_look_alike_spelling_from_the_provider_is_not_the_admin(spelling):
    """Review of #41: normalizing the address a provider sent folded look-alike
    spellings onto the admin's, so a self-hosted IdP could set up the admin."""
    users: dict = {}
    client = _oauth_app(users, {"email": spelling, "email_verified": True, "sub": "x"})
    assert client.get("/auth/callback/google").status_code == 403
    assert users == {}


@pytest.mark.parametrize("key", ["someone@corp.local", "someone@xn--bcher-kva.example"])
def test_an_existing_oauth_account_keeps_its_key(key):
    """Review of #41: accounts made by OAuth sign-in are keyed as the provider
    spelled them; a stricter or normalizing lookup orphaned or locked them out."""
    users = {
        key: {
            "password_hash": None,
            "oauth_provider": "google",
            "oauth_links": {"google": "g-1"},
        }
    }
    client = _oauth_app(users, {"email": key, "email_verified": True, "sub": "g-1"})
    assert client.get("/auth/callback/google").status_code == 200
    assert list(users) == [key]


@pytest.mark.parametrize(
    "record, status, phrase",
    [
        (
            {"created_via": "oauth:google", "email_verified_by_provider": False},
            doctor_mod.WARN,
            "NOT verified by the provider",
        ),
        (
            {"created_via": "oauth:google"},
            doctor_mod.WARN,
            "verification not recorded",
        ),
        (
            {"created_via": "oauth:google", "email_verified_by_provider": True},
            doctor_mod.PASS,
            "verified by the provider",
        ),
        ({"created_via": "add-user"}, doctor_mod.PASS, "add-user"),
    ],
)
def test_doctor_reports_every_admin_accounts_provenance(
    env, tmp_path, single_app_dir, record, status, phrase
):
    """#41 item 2: an OAuth-made admin account the provider did not vouch for is
    as doubtful as a self-registered one."""
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": None, "created_at": 0, **record}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == status
    assert phrase in check.detail


def test_doctor_keeps_the_provenance_note_when_another_warning_fires(
    env, tmp_path, single_app_dir
):
    """The "predates created_via" line used to vanish whenever a warning fired."""
    env.setenv("ENLACE_ADMIN_EMAILS", f"{_ADMIN},second@example.com")
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": "x", "created_at": 0}
    users["second@example.com"] = {"password_hash": "x", "created_via": "register"}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.WARN
    assert "predate created_via" in check.detail


def test_register_does_not_reveal_whether_an_admin_account_exists(env, tmp_path):
    """#41 item 4: 403 for an admin address whether or not it has an account."""
    client = _client(tmp_path)
    csrf = _csrf(client)
    body = {"email": _ADMIN, "password": "attacker-pw1"}
    before = client.post("/auth/register", json=body, headers=csrf).status_code
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": "x", "created_via": "add-user"}
    after = client.post("/auth/register", json=body, headers=csrf).status_code
    assert before == after == 403


def test_doctor_says_how_to_spell_an_admin_entry_add_user_keyed_otherwise(
    env, tmp_path, single_app_dir
):
    """#41 item 5: a punycode admin entry never matches the Unicode-keyed account
    add-user made; rather than silently remapping it, the doctor says so."""
    env.setenv("ENLACE_ADMIN_EMAILS", "boss@xn--bcher-kva.example")
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users["boss@bücher.example"] = {"password_hash": "x", "created_via": "add-user"}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.WARN
    assert "write the admin entry as 'boss@bücher.example'" in check.detail


def test_a_connector_allowlist_entry_admits_both_spellings_of_its_account():
    """#41 item 5 for the allowlist: a punycode entry matches the Unicode-keyed
    account, and a domain EmailStr refuses (.local) still loads (review of #41)."""
    from enlace_auth.resource_policy import parse_resource_allowlist

    res = "https://apps.example.com/api/x_mcp/mcp"
    allowed = parse_resource_allowlist(
        {res: ["Ann@XN--BCHER-KVA.example", "bob@corp.local"]}
    )[res]
    assert {"ann@bücher.example", "ann@xn--bcher-kva.example"} <= allowed
    assert "bob@corp.local" in allowed


@pytest.mark.parametrize(
    "entry", ["ann <mallory@evil.com>", "<mallory@evil.com>", '"a"@example.com']
)
def test_a_display_name_entry_never_grants_another_address(entry):
    """Review of #39: EmailStr parses ``Name <addr>``, so a list entry naming one
    person would have granted another."""
    from enlace_auth.emails import normalize_email
    from enlace_auth.resource_policy import parse_resource_allowlist

    with pytest.raises(ValueError):
        normalize_email(entry)
    with pytest.raises(ValueError, match="not a bare email"):
        parse_resource_allowlist({"https://apps.example.com/api/x_mcp/mcp": [entry]})
