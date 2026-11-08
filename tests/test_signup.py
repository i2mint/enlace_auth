"""Self-service sign-up: verify before create, one answer for every address.

The epic is i2mint/enlace_auth#81; the research behind it is
``misc/docs/research/self-signup-synthesis.md``. Every test builds the real
platform and reads the code out of the mail the platform sent.
"""

from __future__ import annotations

import importlib
import re
import textwrap

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin

plugin_module = importlib.import_module("enlace_auth.plugin")

KEY = "signup-test-key-32bytes-minimum-len!"
ADMIN = "boss@example.com"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/ping")
    def ping():
        return {"ok": True}
    """
).strip()


class Outbox(list):
    """Captures what the platform mails: ``[(to, subject, body), ...]``."""

    def __call__(self, *, to, subject, body):
        self.append((to, subject, body))

    def to(self, address):
        return [m for m in self if m[0] == address]

    def code_for(self, address):
        (_, subject, _) = self.to(address)[-1]
        return re.search(r"\b(\d{6})\b", subject).group(1)

    def link_token_for(self, address):
        (_, _, body) = self.to(address)[-1]
        return re.search(r"/auth/email/link#t=(\S+)", body).group(1)


@pytest.fixture
def outbox(monkeypatch):
    box = Outbox()
    monkeypatch.setattr(plugin_module, "_build_email_sender", lambda: box)
    return box


@pytest.fixture
def platform(tmp_path, monkeypatch, outbox):
    """``make(**signup) -> TestClient`` for a platform with apps game, beta, priv."""
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", ADMIN)
    monkeypatch.delenv("ENLACE_REGISTRATION_ALLOWLIST", raising=False)
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    for name, toml in {
        "game": 'access = "public"\nuser_store = true\n',
        "beta": 'access = "protected:user"\nallowed_users = ["boss@example.com"]\n',
        "priv": 'access = "protected:user"\n',
    }.items():
        d = apps_dir / name
        d.mkdir()
        (d / "server.py").write_text(_SERVER)
        (d / "app.toml").write_text(toml)

    def make(**signup) -> TestClient:
        signup = {"bot_min_seconds": 0, **signup}
        config = PlatformConfig(
            apps_dir=apps_dir,
            auth={
                "enabled": True,
                "secure_cookies": False,
                "stores": {"backend": "file", "path": str(tmp_path / "platform")},
                "signup": signup,
            },
            stores={"user_data": {"backend": "file", "path": str(tmp_path / "ud")}},
        )
        return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))

    make.users_dir = tmp_path / "platform" / "users"
    make.data_dir = tmp_path / "ud" / "user_data"
    return make


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf"]}


def _challenge(client) -> str:
    return client.get("/auth/email/challenge").json()["challenge"]


def _start(client, email, **extra):
    body = {"email": email, "challenge": _challenge(client), **extra}
    return client.post("/auth/email/start", json=body, headers=_csrf(client))


def _verify(client, email, code):
    return client.post(
        "/auth/email/verify", json={"email": email, "code": code}, headers=_csrf(client)
    )


def _users(platform) -> set[str]:
    d = platform.users_dir
    return {p.name for p in d.iterdir()} if d.exists() else set()


# --------------------------------------------------------------------------
# The one-command test (v1 is done when this passes)
# --------------------------------------------------------------------------


def test_start_code_verify_signs_in_and_creates_only_at_verify(platform, outbox):
    client = platform(default="open")
    r = _start(client, "new@example.com", next="/game/")
    assert r.status_code == 202
    assert "new@example.com" not in _users(platform)  # nothing before verify
    code = outbox.code_for("new@example.com")
    r = _verify(client, "new@example.com", code)
    assert r.status_code == 200, r.text
    assert r.json()["created"] is True and r.json()["next"] == "/game/"
    assert client.get("/auth/whoami").json()["email"] == "new@example.com"
    assert "new@example.com" in _users(platform)


def test_start_answers_every_address_byte_for_byte_alike(platform, outbox):
    client = platform(default="closed", apps={"game": "open"})
    _start(client, "known@example.com", app="game")
    _verify(client, "known@example.com", outbox.code_for("known@example.com"))
    client.post("/auth/logout", headers=_csrf(client))
    answers = [
        _start(client, "known@example.com"),  # an account
        _start(client, "fresh@example.com", app="game"),  # admitted, no account
        _start(client, "refused@example.com"),  # the default refuses it
        _start(client, ADMIN, app="game"),  # never self-registered
    ]
    assert {(r.status_code, r.content) for r in answers} == {(202, answers[0].content)}
    # Only the mail differs: a code, or a notice with no code in it.
    assert re.search(r"\d{6}", outbox.to("refused@example.com")[-1][1]) is None
    assert re.search(r"\d{6}", outbox.to(ADMIN)[-1][1]) is None
    assert re.search(r"\d{6}", outbox.to("fresh@example.com")[-1][1])


def test_existing_account_signs_in_with_a_code(platform, outbox):
    client = platform(default="open")
    _start(client, "a@example.com")
    _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    client.post("/auth/logout", headers=_csrf(client))
    _start(client, "a@example.com")
    r = _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    assert r.status_code == 200 and r.json()["created"] is False


# --------------------------------------------------------------------------
# The code: single use, expires on wrong guesses, link spent only by POST
# --------------------------------------------------------------------------


def test_a_code_signs_in_once(platform, outbox):
    client = platform(default="open")
    _start(client, "a@example.com")
    code = outbox.code_for("a@example.com")
    assert _verify(client, "a@example.com", code).status_code == 200
    assert _verify(client, "a@example.com", code).status_code == 400


def test_five_wrong_guesses_kill_the_code(platform, outbox):
    client = platform(default="open")
    _start(client, "a@example.com")
    code = outbox.code_for("a@example.com")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        assert _verify(client, "a@example.com", wrong).status_code == 400
    assert _verify(client, "a@example.com", code).status_code == 400
    assert "a@example.com" not in _users(platform)


def test_wrong_code_and_no_code_read_the_same(platform, outbox):
    client = platform(default="open")
    _start(client, "a@example.com")
    wrong = _verify(client, "a@example.com", "123456")
    none = _verify(client, "nobody@example.com", "123456")
    assert (wrong.status_code, wrong.content) == (none.status_code, none.content)


def test_the_link_page_spends_nothing_and_its_token_signs_in(platform, outbox):
    client = platform(default="open")
    _start(client, "a@example.com")
    token = outbox.link_token_for("a@example.com")
    page = client.get("/auth/email/link")  # what a mail scanner fetches
    assert page.status_code == 200 and token not in page.text
    r = client.post("/auth/email/verify", json={"token": token}, headers=_csrf(client))
    assert r.status_code == 200, r.text
    assert client.get("/auth/whoami").json()["email"] == "a@example.com"
    # The token carries the code, which is now spent.
    again = client.post(
        "/auth/email/verify", json={"token": token}, headers=_csrf(client)
    )
    assert again.status_code == 400


def test_a_forged_link_token_is_refused(platform, outbox):
    client = platform(default="open")
    r = client.post(
        "/auth/email/verify", json={"token": "not.a.token"}, headers=_csrf(client)
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# Policy: per app, invitations, admins, re-checked at verify
# --------------------------------------------------------------------------


def test_closed_default_creates_nothing(platform, outbox):
    client = platform(default="closed")
    _start(client, "a@example.com")
    assert re.search(r"\d{6}", outbox.to("a@example.com")[-1][1]) is None
    assert _verify(client, "a@example.com", "123456").status_code == 400
    assert _users(platform) == set()


def test_per_app_policy_follows_next(platform, outbox):
    client = platform(default="closed", apps={"game": "open"})
    _start(client, "a@example.com", next="/api/game/state")
    r = _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    assert r.status_code == 200
    record_app = client.get("/auth/whoami").json()["email"]
    assert record_app == "a@example.com"


def test_an_unknown_app_name_gets_the_default(platform, outbox):
    client = platform(default="closed", apps={"game": "open"})
    _start(client, "a@example.com", app="no-such-app")
    assert re.search(r"\d{6}", outbox.to("a@example.com")[-1][1]) is None


def test_invite_policy_admits_the_invited_once(platform, outbox):
    from enlace_auth.signup.policy import invite

    client = platform(default="closed", apps={"beta": "invite"})
    store_root = platform.users_dir.parent
    from enlace_auth.stores import make_file_store_factory

    invites = make_file_store_factory(str(store_root))("invites")
    invite(invites, "guest@example.com", apps=["beta"])
    _start(client, "stranger@example.com", app="beta")
    assert re.search(r"\d{6}", outbox.to("stranger@example.com")[-1][1]) is None
    _start(client, "guest@example.com", app="beta")
    r = _verify(client, "guest@example.com", outbox.code_for("guest@example.com"))
    assert r.status_code == 200 and r.json()["created"] is True
    assert "guest@example.com" not in invites  # spent with the account
    # A protected app still decides who opens it: the account is not let in.
    assert client.get("/api/beta/ping").status_code == 403


def test_allowlist_entries_admit_under_allowlist_and_invite(platform, outbox):
    client = platform(
        default="allowlist", apps={"beta": "invite"}, allowlist=["ok@example.com"]
    )
    for app in (None, "beta"):
        outbox.clear()
        _start(client, "ok@example.com", app=app)
        assert re.search(r"\d{6}", outbox.to("ok@example.com")[-1][1])
        _start(client, "no@example.com", app=app)
        assert re.search(r"\d{6}", outbox.to("no@example.com")[-1][1]) is None


def test_an_admin_address_is_never_created(platform, outbox):
    client = platform(default="open", allowlist=[ADMIN])
    _start(client, ADMIN)
    assert re.search(r"\d{6}", outbox.to(ADMIN)[-1][1]) is None
    assert ADMIN not in _users(platform)


def test_policy_closing_between_start_and_verify_creates_nothing(platform, outbox):
    open_client = platform(default="open")
    _start(open_client, "a@example.com")
    code = outbox.code_for("a@example.com")
    closed_client = platform(default="closed")  # same stores, policy changed
    r = _verify(closed_client, "a@example.com", code)
    assert r.status_code == 403
    assert "a@example.com" not in _users(platform)


def test_terms_version_is_stored_on_the_account(platform, outbox):
    import json

    client = platform(default="open", terms_version="2026-11", terms_url="/terms")
    _start(client, "a@example.com")
    _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    record = json.loads((platform.users_dir / "a@example.com").read_text())
    assert record["terms_version"] == "2026-11"
    assert record["created_via"] == "email-code"
    assert record["email_verified_at"] and record["password_hash"] is None


# --------------------------------------------------------------------------
# Abuse: bot check, rate limits, CSRF
# --------------------------------------------------------------------------


def test_a_filled_honeypot_or_missing_challenge_mails_nothing(platform, outbox):
    client = platform(default="open")
    good = _start(client, "a@example.com")
    honeypot = _start(client, "b@example.com", website="http://spam")
    no_challenge = client.post(
        "/auth/email/start", json={"email": "c@example.com"}, headers=_csrf(client)
    )
    assert good.content == honeypot.content == no_challenge.content
    assert outbox.to("b@example.com") == outbox.to("c@example.com") == []


def test_a_form_sent_too_fast_mails_nothing(platform, outbox):
    client = platform(default="open", bot_min_seconds=30)
    assert _start(client, "a@example.com").status_code == 202
    assert outbox.to("a@example.com") == []


def test_mail_to_one_address_is_rate_limited(platform, outbox):
    client = platform(default="open", limits={"mail_per_address": 2})
    assert [_start(client, "a@example.com").status_code for _ in range(3)] == [
        202,
        202,
        429,
    ]
    assert len(outbox.to("a@example.com")) == 2


def test_code_checks_are_rate_limited(platform, outbox):
    client = platform(default="open", limits={"verify_per_address": 2})
    _start(client, "a@example.com")
    codes = [_verify(client, "a@example.com", "999999").status_code for _ in range(3)]
    assert codes[-1] == 429


def test_password_reset_mail_is_rate_limited(platform, outbox):
    client = platform(default="open", limits={"mail_per_address": 1})
    body = {"email": "a@example.com"}
    first = client.post(
        "/auth/password-reset/request", json=body, headers=_csrf(client)
    )
    second = client.post(
        "/auth/password-reset/request", json=body, headers=_csrf(client)
    )
    assert (first.status_code, second.status_code) == (200, 429)


def test_start_without_csrf_is_refused(platform, outbox):
    client = platform(default="open")
    client.get("/auth/csrf")
    r = client.post(
        "/auth/email/start",
        json={"email": "a@example.com", "challenge": _challenge(client)},
    )
    assert r.status_code == 403
    assert outbox == []


# --------------------------------------------------------------------------
# /auth/register: verify first, 15 characters
# --------------------------------------------------------------------------


def _register(client, email, password):
    body = {"email": email, "password": password, "challenge": _challenge(client)}
    return client.post("/auth/register", json=body, headers=_csrf(client))


def test_register_creates_the_account_only_at_verify(platform, outbox):
    client = platform(default="open")
    pw = "fifteen-chars-long"
    r = _register(client, "a@example.com", pw)
    assert r.status_code == 202 and "a@example.com" not in _users(platform)
    _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    client.post("/auth/logout", headers=_csrf(client))
    r = client.post(
        "/auth/login",
        json={"email": "a@example.com", "password": pw},
        headers=_csrf(client),
    )
    assert r.status_code == 200


def test_register_needs_fifteen_characters(platform, outbox):
    client = platform(default="open")
    r = _register(client, "a@example.com", "fourteen-chars")
    assert r.status_code == 400 and "15" in r.json()["detail"]
    assert outbox == []


def test_register_never_changes_an_existing_password(platform, outbox):
    client = platform(default="open")
    _register(client, "a@example.com", "the-original-password")
    _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    client.post("/auth/logout", headers=_csrf(client))
    first, second = _register(client, "a@example.com", "an-attackers-password"), None
    assert first.status_code == 202
    _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    client.post("/auth/logout", headers=_csrf(client))
    ok = client.post(
        "/auth/login",
        json={"email": "a@example.com", "password": "the-original-password"},
        headers=_csrf(client),
    )
    assert ok.status_code == 200 and second is None


def test_register_answers_known_and_unknown_alike(platform, outbox):
    client = platform(default="closed", apps={"game": "open"})
    _register(client, "a@example.com", "the-original-password").status_code
    known = _register(client, "a@example.com", "another-long-password")
    refused = _register(client, "b@example.com", "another-long-password")
    assert (known.status_code, known.content) == (refused.status_code, refused.content)


# --------------------------------------------------------------------------
# Self-service deletion
# --------------------------------------------------------------------------


def _signed_in(platform, outbox, email="a@example.com", **signup):
    client = platform(default="open", **signup)
    _start(client, email)
    assert _verify(client, email, outbox.code_for(email)).status_code == 200
    return client


def test_delete_needs_the_mailed_code_then_removes_everything(platform, outbox):
    client = _signed_in(platform, outbox)
    headers = _csrf(client)
    client.put("/api/game/store/progress", json={"level": 3}, headers=headers)
    assert client.post("/auth/account/delete/start", headers=headers).status_code == 202
    bad = client.post("/auth/account/delete", json={"code": "000000"}, headers=headers)
    assert bad.status_code == 400 and "a@example.com" in _users(platform)
    code = re.search(r"\b(\d{6})\b", outbox.to("a@example.com")[-1][1]).group(1)
    r = client.post("/auth/account/delete", json={"code": code}, headers=headers)
    assert r.status_code == 200, r.text
    assert "a@example.com" not in _users(platform)
    assert client.get("/auth/whoami").json()["email"] is None
    assert not list(platform.data_dir.rglob("*")) or not any(
        p.is_file() for p in platform.data_dir.rglob("*")
    )


def test_delete_ends_every_session_of_the_account(platform, outbox):
    client = _signed_in(platform, outbox)
    other = platform(default="open")  # a second browser
    _start(other, "a@example.com")
    _verify(other, "a@example.com", outbox.code_for("a@example.com"))
    headers = _csrf(client)
    client.post("/auth/account/delete/start", headers=headers)
    code = re.search(r"\b(\d{6})\b", outbox.to("a@example.com")[-1][1]).group(1)
    client.post("/auth/account/delete", json={"code": code}, headers=headers)
    assert other.get("/auth/whoami").json()["email"] is None


def test_delete_needs_a_session(platform, outbox):
    client = platform(default="open")
    r = client.post("/auth/account/delete/start", headers=_csrf(client))
    assert r.status_code == 401


def test_a_sign_in_code_does_not_delete(platform, outbox):
    client = _signed_in(platform, outbox)
    headers = _csrf(client)
    _start(client, "a@example.com")
    signin_code = outbox.code_for("a@example.com")
    r = client.post("/auth/account/delete", json={"code": signin_code}, headers=headers)
    assert r.status_code == 400 and "a@example.com" in _users(platform)


# --------------------------------------------------------------------------
# Configuration: the switch, the page
# --------------------------------------------------------------------------


def test_email_code_false_mounts_nothing(platform, outbox):
    client = platform(default="open", email_code=False)
    assert client.get("/auth/email/challenge").status_code == 404
    r = client.post(
        "/auth/email/start", json={"email": "a@example.com"}, headers=_csrf(client)
    )
    assert r.status_code in (404, 405)
    assert client.post(
        "/auth/register",
        json={"email": "a@example.com", "password": "x" * 20},
        headers=_csrf(client),
    ).status_code in (404, 405)


def test_login_page_offers_email_with_the_age_line(platform, outbox):
    client = platform(default="open", privacy_url="/privacy")
    page = client.get("/auth/login").text
    assert "Continue with email" in page and "15 and over" in page
    assert 'href="/privacy"' in page


def test_login_page_speaks_french(platform, outbox):
    client = platform(default="open")
    page = client.get("/auth/login", headers={"Accept-Language": "fr-FR,fr"}).text
    assert "Continuer avec mon e-mail" in page and '<html lang="fr">' in page


def test_login_page_without_a_sender_offers_no_email(platform, outbox, monkeypatch):
    monkeypatch.setattr(plugin_module, "_build_email_sender", lambda: None)
    client = platform(default="open")
    assert "Continue with email" not in client.get("/auth/login").text


def test_registration_open_is_an_alias_for_open(tmp_path, monkeypatch, outbox):
    from enlace_auth.config import AuthConfig

    assert AuthConfig(registration_open=True).signup_default() == "open"
    assert AuthConfig().signup_default() == "allowlist"
    with pytest.raises(ValueError, match="conflicts"):
        AuthConfig(registration_open=True, signup={"default": "closed"})


def test_a_disabled_account_cannot_sign_in_by_code(platform, outbox):
    from enlace_auth.auth.accounts import make_account_records
    from enlace_auth.stores import make_file_store_factory

    client = _signed_in(platform, outbox)
    client.post("/auth/logout", headers=_csrf(client))
    records = make_account_records(
        make_file_store_factory(str(platform.users_dir.parent))
    )
    records.set_disabled("a@example.com", True)
    _start(client, "a@example.com")
    r = _verify(client, "a@example.com", outbox.code_for("a@example.com"))
    assert r.status_code == 403


# --------------------------------------------------------------------------
# Doctor
# --------------------------------------------------------------------------


def _signup_checks(tmp_path, monkeypatch, *, open_app_access="", **signup):
    from enlace_auth.diagnostics import check_signup

    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    apps_dir = tmp_path / "doctor_apps"
    apps_dir.mkdir(exist_ok=True)
    for name, toml in {
        "game": 'access = "public"\n',
        "vault": 'access = "protected:user"\n' + open_app_access,
    }.items():
        (apps_dir / name).mkdir(exist_ok=True)
        (apps_dir / name / "server.py").write_text(_SERVER)
        (apps_dir / name / "app.toml").write_text(toml)
    config = PlatformConfig(apps_dir=apps_dir, auth={"enabled": True, "signup": signup})
    return {c.name: c.status for c in check_signup(discover_apps(config))}


def test_doctor_fails_open_signup_that_exposes_an_unlisted_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ENLACE_SMTP_HOST", "smtp.example.com")
    checks = _signup_checks(tmp_path, monkeypatch, apps={"game": "open"})
    assert checks["signup_exposes_apps"] == "fail"
    listed = _signup_checks(
        tmp_path,
        monkeypatch,
        apps={"game": "open"},
        privacy_url="/privacy",
        open_app_access='allowed_users = ["boss@example.com"]\n',
    )
    assert listed == {"signup": "pass"}


def test_doctor_fails_open_signup_without_a_sender(tmp_path, monkeypatch):
    monkeypatch.delenv("ENLACE_SMTP_HOST", raising=False)
    checks = _signup_checks(
        tmp_path,
        monkeypatch,
        default="open",
        open_app_access='allowed_users = ["boss@example.com"]\n',
    )
    assert checks["signup_sender"] == "fail" and checks["signup_privacy"] == "warn"


def test_doctor_fails_a_policy_for_an_unknown_app(tmp_path, monkeypatch):
    checks = _signup_checks(tmp_path, monkeypatch, apps={"gmae": "open"})
    assert checks["signup_apps"] == "fail"


def test_doctor_is_quiet_for_the_legacy_default(tmp_path, monkeypatch):
    monkeypatch.delenv("ENLACE_REGISTRATION_ALLOWLIST", raising=False)
    assert _signup_checks(tmp_path, monkeypatch) == {"signup": "pass"}


def test_cli_invite_admits_the_address_through_the_platform(
    platform, outbox, tmp_path, monkeypatch
):
    from enlace_auth.__main__ import invite, uninvite

    toml = tmp_path / "platform.toml"
    toml.write_text(
        f'[auth]\nenabled = true\n[auth.stores]\npath = "{tmp_path / "platform"}"\n'
    )
    invite("Guest@Example.com", apps="beta", toml=str(toml))
    client = platform(default="closed", apps={"beta": "invite"})
    _start(client, "guest@example.com", app="beta")
    assert re.search(r"\d{6}", outbox.to("guest@example.com")[-1][1])
    uninvite("guest@example.com", toml=str(toml))
    outbox.clear()
    _start(client, "guest@example.com", app="beta")
    assert re.search(r"\d{6}", outbox.to("guest@example.com")[-1][1]) is None
