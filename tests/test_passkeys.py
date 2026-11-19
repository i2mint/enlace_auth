"""Passkeys (#82): add from the account page, sign in, step up, redeem, policy.

A real platform (``build_backend`` + the auth plugin) and a software
authenticator (:mod:`tests.passkey_helpers`) that makes real P-256 signatures,
so py_webauthn's checks run unmodified. Every allowed path has its refusal
beside it: a stale session, a foreign origin, a replayed or re-targeted answer,
an unverified user, another account's passkey, a spent or re-purposed proof.
"""

from __future__ import annotations

import logging
import textwrap
import time

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth.cookies import verify_cookie
from enlace_auth.stores import make_file_store_factory
from tests.passkey_helpers import SoftAuthenticator
from tests.test_admin import _seed_account

KEY = "passkeys-test-key-32bytes-minimum-len!"
ORIGIN = "https://testserver"
OWNER = "owner@example.com"
ALICE = "alice@example.com"
PW = "correct horse battery staple"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/ping")
    def ping():
        return {"ok": True}
    """
).strip()


class _Mail(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@pytest.fixture
def mail():
    handler = _Mail()
    logger = logging.getLogger("enlace_auth.email")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler.messages
    logger.removeHandler(handler)


@pytest.fixture
def platform(tmp_path, monkeypatch):
    """``make(**passkeys) -> TestClient``; the platform store root is ``.root``."""
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", OWNER)
    apps_dir = tmp_path / "apps"
    (apps_dir / "desk").mkdir(parents=True)
    (apps_dir / "desk" / "server.py").write_text(_SERVER)
    (apps_dir / "desk" / "app.toml").write_text('access = "protected:user"\n')
    root = tmp_path / "platform"
    _seed_account(root, OWNER, PW)
    _seed_account(root, ALICE, PW)

    def make(**passkeys) -> TestClient:
        cfg = {"enabled": True, "origins": [ORIGIN], **passkeys}
        config = PlatformConfig(
            apps_dir=apps_dir,
            auth={
                "enabled": True,
                "secure_cookies": False,
                "stores": {"backend": "file", "path": str(root)},
                "passkeys": cfg,
            },
        )
        backend = build_backend(discover_apps(config), plugins=[auth_plugin])
        return TestClient(backend, base_url=ORIGIN)

    make.root = root
    return make


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf"]}


def _sign_in(client, email=OWNER, password=PW):
    r = client.post(
        "/auth/login",
        json={"email": email, "password": password},
        headers=_csrf(client),
    )
    return r


def _enrol(client, device: SoftAuthenticator, name="Mac"):
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/register/options", json={}, headers=csrf)
    assert options.status_code == 200, options.text
    return client.post(
        "/auth/passkeys/register/verify",
        json={"credential": device.create(options.json()), "name": name},
        headers=csrf,
    )


def _passkey_sign_in(client, device, **kw):
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/login/options", json={}, headers=csrf).json()
    return client.post(
        "/auth/passkeys/login/verify",
        json={"credential": device.get(options, **kw), "next": "/desk/"},
        headers=csrf,
    )


def _step_up(client, device, action, *, answer_for=None, **kw):
    csrf = _csrf(client)
    options = client.post(
        "/auth/passkeys/step-up/options", json={"action": action}, headers=csrf
    )
    assert options.status_code == 200, options.text
    return client.post(
        "/auth/passkeys/step-up/verify",
        json={
            "action": answer_for or action,
            "credential": device.get(options.json(), **kw),
        },
        headers=csrf,
    )


def _age_session(platform, client, seconds: float) -> None:
    """Make the client's session look *seconds* old."""
    sid = verify_cookie(client.cookies.get("enlace_session"), KEY, salt="session")
    sessions = make_file_store_factory(str(platform.root))("sessions")
    sessions[sid] = {**sessions[sid], "created_at": time.time() - seconds}


def _enrolled(platform, devices=1, email=OWNER, **soft):
    """A signed-in client for *email* with *devices* passkeys; returns both.

    The first passkey is added from a password sign-in; every later one needs a
    sign-in with a passkey, so the client signs in again with the first (and
    is left signed in that way).
    """
    client = platform()
    assert _sign_in(client, email).status_code == 200
    made = []
    for i in range(devices):
        if i == 1:
            assert _passkey_sign_in(client, made[0]).status_code == 200
        device = SoftAuthenticator(ORIGIN, **soft)
        assert _enrol(client, device, name=f"device {i}").status_code == 200
        made.append(device)
    # End on a passkey sign-in, as an account with a passkey changes them.
    assert _passkey_sign_in(client, made[0]).status_code == 200
    return client, made


def _redeem(client, proof, action=None, email=OWNER):
    return client.post(
        "/auth/passkeys/step-up/redeem",
        json={"proof": proof, "action": action or ACTION, "email": email},
    )


# ----- registration -------------------------------------------------------


def test_a_signed_in_account_adds_a_passkey_and_is_mailed(platform, mail):
    client, _ = _enrolled(platform)
    listed = client.get("/auth/passkeys").json()
    assert [p["name"] for p in listed["passkeys"]] == ["device 0"]
    assert listed["required"] is False
    assert "public_key" not in listed["passkeys"][0]
    assert any(OWNER in m and "passkey" in m.lower() for m in mail)


def test_adding_needs_a_sign_in(platform):
    client = platform()
    r = client.post("/auth/passkeys/register/options", json={}, headers=_csrf(client))
    assert r.status_code == 401


def test_adding_needs_a_fresh_sign_in(platform):
    client = platform()
    assert _sign_in(client).status_code == 200
    _age_session(platform, client, 3600)
    r = client.post("/auth/passkeys/register/options", json={}, headers=_csrf(client))
    assert r.status_code == 403
    assert r.headers.get("X-Enlace-Reauth") == "1"


def test_adding_is_csrf_checked(platform):
    client = platform()
    assert _sign_in(client).status_code == 200
    r = client.post("/auth/passkeys/register/options", json={})
    assert r.status_code == 403
    assert r.json()["detail"] == "CSRF check failed"


def test_a_registration_from_another_origin_is_refused(platform):
    client = platform()
    assert _sign_in(client).status_code == 200
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/register/options", json={}, headers=csrf)
    phished = SoftAuthenticator("https://evil.example")
    r = client.post(
        "/auth/passkeys/register/verify",
        json={"credential": phished.create(options.json()), "name": "x"},
        headers=csrf,
    )
    assert r.status_code == 400
    assert client.get("/auth/passkeys").json()["passkeys"] == []


def test_registration_options_are_bound_to_the_account(platform):
    """Options minted for one account cannot register a passkey on another."""
    owner, alice = platform(), platform()
    assert _sign_in(owner).status_code == 200
    assert _sign_in(alice, ALICE).status_code == 200
    options = owner.post(
        "/auth/passkeys/register/options", json={}, headers=_csrf(owner)
    ).json()
    r = alice.post(
        "/auth/passkeys/register/verify",
        json={"credential": SoftAuthenticator(ORIGIN).create(options), "name": "x"},
        headers=_csrf(alice),
    )
    assert r.status_code == 400


# ----- sign-in ---------------------------------------------------------------


def test_sign_in_with_a_passkey(platform):
    _, (device,) = _enrolled(platform)
    fresh = platform()
    r = _passkey_sign_in(fresh, device)
    assert r.status_code == 200, r.text
    assert r.json()["email"] == OWNER and r.json()["next"] == "/desk/"
    assert fresh.get("/auth/whoami").json()["email"] == OWNER
    assert fresh.get("/api/desk/ping").status_code == 200


def test_a_sign_in_answer_cannot_be_replayed(platform):
    _, (device,) = _enrolled(platform)
    client = platform()
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/login/options", json={}, headers=csrf).json()
    answer = device.get(options)
    first = client.post(
        "/auth/passkeys/login/verify", json={"credential": answer}, headers=csrf
    )
    assert first.status_code == 200
    other = platform()
    again = other.post(
        "/auth/passkeys/login/verify", json={"credential": answer}, headers=_csrf(other)
    )
    assert again.status_code == 400
    assert other.get("/auth/whoami").json()["email"] is None


@pytest.mark.parametrize(
    "tamper",
    [
        dict(origin="https://evil.example"),  # phishing origin
        dict(user_handle=False),  # usernameless sign-in must name its account
    ],
)
def test_a_sign_in_answer_that_does_not_check_out_is_refused(platform, tamper):
    _, (device,) = _enrolled(platform)
    client = platform()
    assert _passkey_sign_in(client, device, **tamper).status_code == 400
    assert client.get("/auth/whoami").json()["email"] is None


def test_a_sign_in_without_user_verification_is_refused(platform):
    _, (device,) = _enrolled(platform)
    device.uv = False
    client = platform()
    assert _passkey_sign_in(client, device).status_code == 400


def test_an_unknown_passkey_is_refused(platform):
    _enrolled(platform)
    stranger = SoftAuthenticator(ORIGIN)
    stranger.create(
        {"rp": {"id": "testserver"}, "user": {"id": "eA"}, "challenge": "AA"}
    )
    assert _passkey_sign_in(platform(), stranger).status_code == 400


def test_a_disabled_account_cannot_sign_in_with_its_passkey(platform):
    from enlace_auth.auth.accounts import make_account_records

    _, (device,) = _enrolled(platform)
    users = make_account_records(make_file_store_factory(str(platform.root)))
    users.set_disabled(OWNER, True)
    client = platform()
    assert _passkey_sign_in(client, device).status_code == 403
    assert client.get("/auth/whoami").json()["email"] is None


# ----- step-up and redeem ------------------------------------------------------


ACTION = "start job: thorwhalen/equerry, 'fix the thing'"


def test_step_up_proof_is_redeemed_once_by_a_backend(platform):
    client, (device,) = _enrolled(platform)
    r = _step_up(client, device, ACTION)
    assert r.status_code == 200, r.text
    proof = r.json()["proof"]
    assert r.json()["expires_in"] > 0

    backend = platform()  # no cookie, no CSRF token: a connector backend
    first = _redeem(backend, proof)
    assert first.status_code == 200, first.text
    assert first.json()["email"] == OWNER and first.json()["action"] == ACTION
    assert first.json()["method"] == "passkey"
    again = _redeem(backend, proof)
    assert again.status_code == 400


def test_a_proof_is_only_good_for_its_action(platform):
    client, (device,) = _enrolled(platform)
    proof = _step_up(client, device, ACTION).json()["proof"]
    assert _redeem(platform(), proof, "start job: another repo").status_code == 400
    assert _redeem(platform(), proof + "x").status_code == 400
    # The backend names the account it expects: a proof by anyone else fails.
    assert _redeem(platform(), proof, email=ALICE).status_code == 400
    missing = platform().post(
        "/auth/passkeys/step-up/redeem", json={"proof": proof, "action": ACTION}
    )
    assert missing.status_code == 422
    assert _redeem(platform(), proof).status_code == 200  # still unspent until now


def test_a_step_up_answer_is_bound_to_its_action(platform):
    """An answer signed for one action cannot be turned into a proof of another."""
    client, (device,) = _enrolled(platform)
    r = _step_up(client, device, ACTION, answer_for="start job: something else")
    assert r.status_code == 400


def test_step_up_needs_a_sign_in_and_a_passkey(platform):
    anonymous = platform()
    r = anonymous.post(
        "/auth/passkeys/step-up/options",
        json={"action": ACTION},
        headers=_csrf(anonymous),
    )
    assert r.status_code == 401
    alice = platform()
    assert _sign_in(alice, ALICE).status_code == 200
    r = alice.post(
        "/auth/passkeys/step-up/options", json={"action": ACTION}, headers=_csrf(alice)
    )
    assert r.status_code == 409


def test_step_up_with_another_accounts_passkey_is_refused(platform):
    _, (owners_device,) = _enrolled(platform)
    alice, _ = _enrolled(platform, email=ALICE)
    csrf = _csrf(alice)
    options = alice.post(
        "/auth/passkeys/step-up/options", json={"action": ACTION}, headers=csrf
    ).json()
    answer = owners_device.get(options, cred=owners_device.creds[0])
    r = alice.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": answer},
        headers=csrf,
    )
    assert r.status_code == 400


def test_step_up_requires_user_verification(platform):
    client, (device,) = _enrolled(platform)
    device.uv = False
    assert _step_up(client, device, ACTION).status_code == 400


def test_step_up_verify_is_csrf_checked_but_redeem_is_not(platform):
    client, (device,) = _enrolled(platform)
    options = client.post(
        "/auth/passkeys/step-up/options", json={"action": ACTION}, headers=_csrf(client)
    ).json()
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": device.get(options)},
    )
    assert r.status_code == 403 and r.json()["detail"] == "CSRF check failed"


def test_an_expired_proof_is_refused():
    from enlace_auth.passkeys.core import PasskeyError, PasskeyService, RelyingParty

    now = [1000.0]
    service = PasskeyService({}, signing_key=KEY, clock=lambda: now[0], proof_ttl=60)
    rp = RelyingParty("testserver", "t", (ORIGIN,))
    device = SoftAuthenticator(ORIGIN)
    service.register(OWNER, device.create(service.registration_options(OWNER, rp)), rp)
    proof = service.step_up(
        OWNER, ACTION, device.get(service.step_up_options(OWNER, ACTION, rp)), rp
    )["proof"]
    now[0] += 61
    with pytest.raises(PasskeyError, match="expired"):
        service.redeem(proof, ACTION, email=OWNER)


def test_a_proof_dies_with_its_passkey(platform):
    client, (device,) = _enrolled(platform)
    proof = _step_up(client, device, ACTION).json()["proof"]
    pid = client.get("/auth/passkeys").json()["passkeys"][0]["id"]
    assert (
        client.delete(f"/auth/passkeys/{pid}", headers=_csrf(client)).status_code == 200
    )
    assert _redeem(platform(), proof).status_code == 400


# ----- removal -----------------------------------------------------------------


def test_removing_a_passkey_ends_the_other_sessions(platform, mail):
    client, (device, _) = _enrolled(platform, devices=2)
    elsewhere = platform()
    assert _passkey_sign_in(elsewhere, device).status_code == 200
    pid = client.get("/auth/passkeys").json()["passkeys"][0]["id"]
    mail.clear()
    r = client.delete(f"/auth/passkeys/{pid}", headers=_csrf(client))
    assert r.status_code == 200, r.text
    assert len(client.get("/auth/passkeys").json()["passkeys"]) == 1
    assert client.get("/auth/whoami").json()["email"] == OWNER  # kept
    assert elsewhere.get("/auth/whoami").json()["email"] is None  # ended
    assert any("removed" in m for m in mail)
    assert _passkey_sign_in(platform(), device).status_code == 400


def test_removal_needs_a_fresh_sign_in(platform):
    client, _ = _enrolled(platform)
    pid = client.get("/auth/passkeys").json()["passkeys"][0]["id"]
    _age_session(platform, client, 3600)
    r = client.delete(f"/auth/passkeys/{pid}", headers=_csrf(client))
    assert r.status_code == 403
    assert len(client.get("/auth/passkeys").json()["passkeys"]) == 1


def test_an_account_cannot_remove_another_accounts_passkey(platform):
    owner, _ = _enrolled(platform)
    pid = owner.get("/auth/passkeys").json()["passkeys"][0]["id"]
    alice = platform()
    assert _sign_in(alice, ALICE).status_code == 200
    assert (
        alice.delete(f"/auth/passkeys/{pid}", headers=_csrf(alice)).status_code == 404
    )
    assert len(owner.get("/auth/passkeys").json()["passkeys"]) == 1


# ----- policy --------------------------------------------------------------------


def test_a_required_account_keeps_its_password_until_it_has_enough_passkeys(platform):
    platform_ = platform  # enforce_from = 2 by default
    client, _ = _enrolled(platform_, devices=1)
    make = lambda: platform_(required=["@admins"])  # noqa: E731
    assert _sign_in(make()).status_code == 200  # one passkey: not yet enforced
    assert make().get("/auth/passkeys").status_code == 401


def test_a_required_account_signs_in_only_with_a_passkey(platform):
    _, devices = _enrolled(platform, devices=2)
    make = lambda: platform(required=["@admins"])  # noqa: E731
    refused = _sign_in(make())
    assert refused.status_code == 403
    assert "passkey" in refused.json()["detail"]
    client = make()
    assert _passkey_sign_in(client, devices[0]).status_code == 200
    state = client.get("/auth/passkeys").json()
    assert state["required"] and state["enforced"]


def test_the_policy_leaves_other_accounts_alone(platform):
    _enrolled(platform, devices=2)
    _enrolled(platform, devices=2, email=ALICE)
    assert _sign_in(platform(required=["@admins"]), ALICE).status_code == 200


def test_a_required_account_cannot_remove_its_last_passkey(platform):
    _, (device,) = _enrolled(platform, devices=1)
    client = platform(required=[OWNER])
    assert _passkey_sign_in(client, device).status_code == 200
    pid = client.get("/auth/passkeys").json()["passkeys"][0]["id"]
    assert (
        client.delete(f"/auth/passkeys/{pid}", headers=_csrf(client)).status_code == 409
    )


def test_open_session_refuses_an_unnamed_method_for_a_required_account():
    from fastapi import HTTPException

    from enlace_auth.auth.accounts import open_session
    from enlace_auth.auth.sessions import SessionStore
    from enlace_auth.passkeys.core import PasskeyPolicy

    policy = PasskeyPolicy(frozenset({OWNER}), count=lambda _e: 2)
    sessions = SessionStore({}, admit=policy.refusal)
    users = {OWNER: {}, ALICE: {}}
    with pytest.raises(HTTPException) as e:
        open_session(sessions, users, OWNER)
    assert e.value.status_code == 403
    assert sessions.list_all() == []
    assert open_session(sessions, users, OWNER, method="passkey")
    assert open_session(sessions, users, ALICE)


def test_an_unreadable_passkey_store_fails_closed():
    from enlace_auth.passkeys.core import PasskeyPolicy

    def broken(_email):
        raise OSError("disk gone")

    policy = PasskeyPolicy(frozenset({OWNER}), count=broken)
    assert policy.refusal(OWNER, "password")
    assert policy.refusal(ALICE, "password") is None


# ----- pages, wiring, deletion ------------------------------------------------------


def test_the_pages_offer_passkeys(platform):
    client = platform()
    page = client.get("/auth/login").text
    assert "/auth/passkeys/passkeys.js" in page and 'id="pk-signin"' in page
    assert _sign_in(client).status_code == 200
    account = client.get("/auth/account").text
    assert 'id="pk-card"' in account
    js = client.get("/auth/passkeys/passkeys.js")
    assert js.status_code == 200 and "enlacePasskeys" in js.text


def test_passkeys_are_off_unless_enabled(platform):
    client = platform(enabled=False)
    assert "pk-signin" not in client.get("/auth/login").text
    assert client.get("/auth/passkeys/passkeys.js").status_code == 404
    assert (
        client.post(
            "/auth/passkeys/step-up/redeem", json={"proof": "x", "action": "y"}
        ).status_code
        == 403
    )  # not mounted, and not CSRF-exempt either


def test_a_misconfigured_relying_party_mounts_nothing(platform, caplog):
    client = platform(rp_id="other.example")
    assert client.get("/auth/passkeys/passkeys.js").status_code == 404
    assert any("MISSING" in r.getMessage() for r in caplog.records)


def test_deleting_an_account_removes_its_passkeys():
    from enlace_auth.auth.accounts import make_account_deleter
    from enlace_auth.passkeys.core import PasskeyService, RelyingParty

    service = PasskeyService({}, signing_key=KEY)
    rp = RelyingParty("testserver", "t", (ORIGIN,))
    for email in (OWNER, ALICE):
        device = SoftAuthenticator(ORIGIN)
        service.register(
            email, device.create(service.registration_options(email, rp)), rp
        )
    users = {OWNER: {}, ALICE: {}}
    delete = make_account_deleter(
        user_store=users, credentials_changed=lambda *a, **k: None, passkeys=service
    )
    delete(ALICE)
    assert service.count(ALICE) == 0 and service.count(OWNER) == 1


def test_a_damaged_record_does_not_break_a_listing():
    from enlace_auth.passkeys.core import PasskeyService

    service = PasskeyService(
        {"bad": "not a dict", "worse": {"email": 3}}, signing_key=KEY
    )
    assert service.list(OWNER) == [] and service.count(OWNER) == 0


def test_the_cli_lists_and_removes_a_lost_devices_passkey(platform, tmp_path, capsys):
    from enlace_auth.__main__ import list_passkeys, remove_passkey

    client, _ = _enrolled(platform, devices=2)
    toml = tmp_path / "platform.toml"
    toml.write_text(
        f'[auth]\nenabled = true\n[auth.stores]\npath = "{platform.root}"\n'
    )
    list_passkeys(OWNER, json=True, toml=str(toml))
    import json

    rows = json.loads(capsys.readouterr().out)
    assert [r["name"] for r in rows] == ["device 0", "device 1"]
    remove_passkey(OWNER, rows[0]["id"], toml=str(toml))
    assert "Removed 1 passkey" in capsys.readouterr().out
    assert client.get("/auth/whoami").json()["email"] is None  # sessions ended
    with pytest.raises(SystemExit):
        remove_passkey(OWNER, rows[0]["id"], toml=str(toml))
    remove_passkey(OWNER, all=True, toml=str(toml))
    list_passkeys(OWNER, toml=str(toml))
    assert capsys.readouterr().out.strip().endswith("revoked.")


# ----- the adversarial review's findings ------------------------------------


def test_a_password_sign_in_cannot_add_a_passkey_once_there_is_one(platform):
    """Whoever holds the password must not plant a passkey and then step up."""
    _enrolled(platform)
    thief = platform()
    assert _sign_in(thief).status_code == 200  # a fresh, password sign-in
    r = thief.post("/auth/passkeys/register/options", json={}, headers=_csrf(thief))
    assert r.status_code == 403 and r.headers.get("X-Enlace-Reauth") == "1"
    pid = thief.get("/auth/passkeys").json()["passkeys"][0]["id"]
    assert (
        thief.delete(f"/auth/passkeys/{pid}", headers=_csrf(thief)).status_code == 403
    )


def test_a_synced_passkey_meets_the_threshold(platform):
    """iPhone and Mac on one Apple ID share one passkey: it counts as enough."""
    _, (device,) = _enrolled(platform, synced=True)
    make = lambda: platform(required=["@admins"])  # noqa: E731
    assert _sign_in(make()).status_code == 403
    assert _passkey_sign_in(make(), device).status_code == 200


def test_reaching_the_threshold_ends_password_sessions(platform):
    client = platform(required=["@admins"])
    assert _sign_in(client).status_code == 200
    old = platform(required=["@admins"])
    assert _sign_in(old).status_code == 200  # an earlier password session
    first = SoftAuthenticator(ORIGIN)
    assert _enrol(client, first).status_code == 200
    assert old.get("/auth/whoami").json()["email"] == OWNER  # not enforced yet
    assert _passkey_sign_in(client, first).status_code == 200
    assert _enrol(client, SoftAuthenticator(ORIGIN), name="two").status_code == 200
    assert old.get("/auth/whoami").json()["email"] is None  # enforced: it ends
    assert client.get("/auth/whoami").json()["email"] == OWNER  # this one stays


def test_an_enforced_account_cannot_drop_below_the_threshold(platform):
    _, devices = _enrolled(platform, devices=2)
    client = platform(required=["@admins"])
    assert _passkey_sign_in(client, devices[0]).status_code == 200
    pid = client.get("/auth/passkeys").json()["passkeys"][1]["id"]
    assert (
        client.delete(f"/auth/passkeys/{pid}", headers=_csrf(client)).status_code == 409
    )


def test_a_reset_for_an_enforced_account_changes_nothing(platform):
    from enlace_auth.auth.accounts import make_account_records
    from enlace_auth.auth.reset_tokens import mint_reset_token

    owner, _ = _enrolled(platform, devices=2)
    users = make_account_records(make_file_store_factory(str(platform.root)))
    before = users[OWNER]["password_hash"]
    token = mint_reset_token(record=users[OWNER], email=OWNER, signing_key=KEY)
    client = platform(required=["@admins"])
    r = client.post(
        "/auth/password-reset/confirm",
        json={"token": token, "new_password": "a brand new long password"},
        headers=_csrf(client),
    )
    assert r.status_code == 403
    assert users[OWNER]["password_hash"] == before
    assert owner.get("/auth/whoami").json()["email"] == OWNER  # not logged out


def test_passkeys_for_another_rp_id_do_not_count(platform):
    """After an rp_id change, old passkeys cannot sign in, so they must not lock out."""
    _enrolled(platform, devices=2)
    moved = platform(
        required=["@admins"],
        rp_id="example.org",
        origins=["https://example.org"],
    )
    assert _sign_in(moved).status_code == 200


def test_a_misconfigured_relying_party_turns_the_policy_off(platform):
    _enrolled(platform, devices=2)
    broken = platform(required=["@admins"], rp_id="other.example")
    assert _sign_in(broken).status_code == 200  # not locked out of every method


def test_an_unknown_group_in_required_is_reported(platform, caplog):
    platform(required=["@nosuchgroup"])
    assert any("resolve to no account" in r.getMessage() for r in caplog.records)
