# ruff: noqa: F811 -- the platform fixture is imported from test_passkeys, and
# pytest injects it by parameter name, which ruff reads as a redefinition.
"""Step-up requested by a backend, confirmed on the platform's page (#95).

A backend holding its audience key creates a request naming the account, the
action and its audience; the platform's own page shows that text and mints a
proof that only a redeem naming that audience accepts. A page can still run the
older page-driven step-up, but its proof has no audience, so a backend that names
one refuses it. Proofs are method-agnostic (``auth/step_up.py``).
"""

from __future__ import annotations

import pytest

from enlace_auth.auth.step_up import StepUpError, StepUpProofs, audience_key
from enlace_auth.passkeys.pages import PROOF_FRAGMENT
from tests.test_passkeys import (  # noqa: F401 - fixture re-export
    ALICE,
    KEY,
    OWNER,
    _csrf,
    _enrolled,
    _sign_in,
    _step_up,
    platform,
)

APP = "jobs"
ACTION = "jobs: start job 42 on the Mac"


def _request(client, *, key=None, email=OWNER, action=ACTION, audience=APP, **kw):
    return client.post(
        "/auth/passkeys/step-up/request",
        json={"email": email, "action": action, "audience": audience, **kw},
        headers={"Authorization": f"Bearer {key or audience_key(KEY, audience)}"},
    )


def _confirm(client, device, request_id):
    """What the confirmation page's script does: options for a request, then verify."""
    csrf = _csrf(client)
    options = client.post(
        "/auth/passkeys/step-up/options", json={"request": request_id}, headers=csrf
    )
    assert options.status_code == 200, options.text
    return client.post(
        "/auth/passkeys/step-up/verify",
        json={"request": request_id, "credential": device.get(options.json())},
        headers=csrf,
    )


def _redeem(client, proof, *, audience=APP, action=ACTION, **kw):
    return client.post(
        "/auth/passkeys/step-up/redeem",
        json={
            "proof": proof,
            "action": action,
            "email": OWNER,
            "audience": audience,
            **kw,
        },
    )


def test_a_backend_request_confirmed_on_the_platform_page_redeems_for_its_audience(
    platform,
):
    client, (device,) = _enrolled(platform)
    backend = platform()  # no cookie, no CSRF token
    made = _request(backend, return_url="/desk/after")
    assert made.status_code == 200, made.text
    request_id = made.json()["request"]
    assert "/auth/passkeys/confirm?r=" in made.json()["confirm_url"]

    page = client.get("/auth/passkeys/confirm", params={"r": request_id})
    assert page.status_code == 200
    assert ACTION in page.text and APP in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert f"#{PROOF_FRAGMENT}=" in page.text and "/desk/after" in page.text

    confirmed = _confirm(client, device, request_id)
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["audience"] == APP
    proof = confirmed.json()["proof"]

    redeemed = _redeem(backend, proof)
    assert redeemed.status_code == 200, redeemed.text
    assert redeemed.json()["audience"] == APP
    assert redeemed.json()["method"] == "passkey"
    assert _redeem(backend, proof).status_code == 400  # once


def test_a_proof_for_one_audience_does_not_redeem_at_another(platform):
    client, (device,) = _enrolled(platform)
    request_id = _request(platform()).json()["request"]
    proof = _confirm(client, device, request_id).json()["proof"]
    other = _redeem(platform(), proof, audience="billing")
    assert other.status_code == 400
    assert "audience" in other.json()["detail"]
    nameless = _redeem(platform(), proof, audience=None)
    assert nameless.status_code == 400


def test_a_page_driven_proof_does_not_redeem_where_an_audience_is_named(platform):
    """The page chose the text; a backend that names its audience never accepts it."""
    client, (device,) = _enrolled(platform)
    proof = _step_up(client, device, ACTION).json()["proof"]
    assert _redeem(platform(), proof).status_code == 400
    # The older flow keeps working for a backend that names no audience.
    assert _redeem(platform(), proof, audience=None).status_code == 200


def test_a_page_cannot_name_an_audience(platform):
    client, (device,) = _enrolled(platform)
    csrf = _csrf(client)
    options = client.post(
        "/auth/passkeys/step-up/options",
        json={"action": ACTION, "audience": APP},
        headers=csrf,
    )
    assert "audience" not in options.json()  # ignored: only a request carries one
    proof = client.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": device.get(options.json())},
        headers=csrf,
    ).json()["proof"]
    assert _redeem(platform(), proof).status_code == 400


def test_an_answer_for_a_request_cannot_be_presented_as_a_page_step_up(platform):
    """The challenge commits to the audience as well as the action."""
    client, (device,) = _enrolled(platform)
    request_id = _request(platform()).json()["request"]
    csrf = _csrf(client)
    options = client.post(
        "/auth/passkeys/step-up/options", json={"request": request_id}, headers=csrf
    ).json()
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": device.get(options)},
        headers=csrf,
    )
    assert r.status_code == 400


def test_a_request_needs_its_audiences_key(platform):
    backend = platform()
    assert _request(backend, key=audience_key(KEY, "billing")).status_code == 401
    assert _request(backend, key="nope").status_code == 401
    unauthenticated = backend.post(
        "/auth/passkeys/step-up/request",
        json={"email": OWNER, "action": ACTION, "audience": APP},
    )
    assert unauthenticated.status_code == 401


def test_a_request_returns_only_to_this_site(platform):
    r = _request(platform(), return_url="https://evil.example.com/")
    assert r.status_code == 400


def test_the_page_is_for_the_requested_account_only(platform):
    request_id = _request(platform()).json()["request"]
    alice = platform()
    assert _sign_in(alice, ALICE).status_code == 200
    page = alice.get("/auth/passkeys/confirm", params={"r": request_id})
    assert page.status_code == 403
    assert OWNER in page.text
    options = alice.post(
        "/auth/passkeys/step-up/options",
        json={"request": request_id},
        headers=_csrf(alice),
    )
    assert options.status_code == 403


def test_a_signed_out_visit_is_sent_to_sign_in_and_back(platform):
    request_id = _request(platform()).json()["request"]
    r = platform().get(
        "/auth/passkeys/confirm", params={"r": request_id}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"].startswith("/auth/login?login_required=1&next=")


def test_a_forged_or_tampered_request_is_refused(platform):
    client, _ = _enrolled(platform)
    request_id = _request(platform()).json()["request"]
    page = client.get("/auth/passkeys/confirm", params={"r": request_id[:-2] + "xx"})
    assert page.status_code == 400
    assert ACTION not in page.text


def test_step_up_returns_the_assertion_it_verified_in_js():
    """``stepUp`` resolves with the credential too (#95 comment)."""
    from importlib.resources import files

    script = files("enlace_auth.passkeys").joinpath("passkeys.js").read_text()
    assert "out.credential = credential" in script
    assert "{ request: actionOrRequest.request }" in script


# -- the proof component itself ------------------------------------------------


def test_redeem_can_refuse_a_weaker_method():
    proofs = StepUpProofs("k" * 32, clock=lambda: 1000)
    minted = proofs.mint(OWNER, ACTION, method="email-code", audience=APP)
    with pytest.raises(StepUpError, match="email-code"):
        proofs.redeem(
            minted["proof"], ACTION, email=OWNER, audience=APP, methods=["passkey"]
        )
    assert proofs.redeem(minted["proof"], ACTION, email=OWNER, audience=APP)


def test_a_proof_minted_before_audiences_still_redeems():
    """Payloads without ``m``/``u`` (from before #95) read as audience-less passkey."""
    from itsdangerous import URLSafeSerializer

    old = URLSafeSerializer(b"k" * 32, salt="enlace-passkey-step-up").dumps(
        {"e": OWNER, "a": ACTION, "k": "x", "j": "j1", "t": 1000}
    )
    proofs = StepUpProofs("k" * 32, clock=lambda: 1001)
    assert proofs.redeem(old, ACTION, email=OWNER)["method"] == "passkey"


def test_an_expired_request_is_refused():
    now = [1000.0]
    proofs = StepUpProofs("k" * 32, request_ttl=60, clock=lambda: now[0])
    rid = proofs.create_request(
        email=OWNER, action=ACTION, audience=APP, key=audience_key("k" * 32, APP)
    )
    now[0] += 61
    with pytest.raises(StepUpError, match="expired"):
        proofs.read_request(rid)


def test_the_cli_prints_the_audience_key(tmp_path, monkeypatch, capsys):
    from enlace_auth.__main__ import step_up_key
    from tests.test_cli import _make_platform_toml

    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    step_up_key(APP, toml=str(_make_platform_toml(tmp_path)))
    assert capsys.readouterr().out.strip() == audience_key(KEY, APP)
