# ruff: noqa: F811 -- the platform fixture is imported from test_passkeys, and
# pytest injects it by parameter name, which ruff reads as a redefinition.
"""Purpose-bound passkeys (#97): one passkey per purpose, named for it, never a sign-in.

The system sheet never shows a WebAuthn challenge, but it shows the credential's
name. A passkey enrolled for one purpose ("Start a job on my Mac") is named for it
and kept beside the sign-in passkey (its own user handle). Sign-in refuses it, a
step-up uses it only when it names that purpose, and a general step-up never
offers it.
"""

from __future__ import annotations

from enlace_auth.stores import make_file_store_factory
from tests.test_passkeys import (  # noqa: F401 - fixture re-export
    ALICE,
    OWNER,
    _csrf,
    _enrolled,
    _passkey_sign_in,
    _sign_in,
    platform,
)
from tests.test_step_up_requests import APP, _request

PURPOSE = "confirm-jobs"
APP_PURPOSE = f"{APP}.confirm"  # a purpose a backend may ask for: its own
LABEL = "Start a job on my Mac"
ACTION = "jobs: start job 42"


def _enrol_for_purpose(client, device, purpose=PURPOSE, label=LABEL):
    csrf = _csrf(client)
    options = client.post(
        "/auth/passkeys/register/options",
        json={"purpose": purpose, "label": label},
        headers=csrf,
    )
    assert options.status_code == 200, options.text
    return options.json(), client.post(
        "/auth/passkeys/register/verify",
        json={
            "credential": device.create(options.json()),
            "name": label,
            "purpose": purpose,
        },
        headers=csrf,
    )


def _with_purpose_passkey(platform):
    """An account with a sign-in passkey and a purpose passkey, on one device."""
    client, (device,) = _enrolled(platform)
    options, added = _enrol_for_purpose(client, device)
    assert added.status_code == 200, added.text
    return client, device, options


def _step_up_options(client, purpose=None, action=ACTION):
    body = {"action": action}
    if purpose:
        body["purpose"] = purpose
    return client.post(
        "/auth/passkeys/step-up/options", json=body, headers=_csrf(client)
    )


def test_enrolment_names_the_purpose_and_keeps_the_sign_in_passkey(platform):
    client, device, options = _with_purpose_passkey(platform)
    assert options["user"]["name"] == LABEL
    assert options["user"]["displayName"] == LABEL
    assert len(device.creds) == 2
    handles = {c["user_handle"] for c in device.creds}
    assert len(handles) == 2  # its own handle: the authenticator keeps both
    listed = client.get("/auth/passkeys").json()["passkeys"]
    assert {p["purpose"] for p in listed} == {None, PURPOSE}


def test_a_purpose_passkey_cannot_sign_in(platform):
    client, device, _ = _with_purpose_passkey(platform)
    purpose_cred = device.creds[-1]
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/login/options", json={}, headers=csrf).json()
    r = client.post(
        "/auth/passkeys/login/verify",
        json={"credential": device.get(options, cred=purpose_cred)},
        headers=csrf,
    )
    assert r.status_code == 400
    assert r.json()["detail"] == "This passkey cannot sign in."  # names nothing


def test_the_sign_in_passkey_still_signs_in(platform):
    client, device, _ = _with_purpose_passkey(platform)
    sign_in_cred = device.creds[0]
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/login/options", json={}, headers=csrf).json()
    r = client.post(
        "/auth/passkeys/login/verify",
        json={"credential": device.get(options, cred=sign_in_cred)},
        headers=csrf,
    )
    assert r.status_code == 200, r.text


def test_a_general_step_up_never_offers_the_purpose_passkey(platform):
    client, device, _ = _with_purpose_passkey(platform)
    options = _step_up_options(client).json()
    offered = {c["id"] for c in options["allowCredentials"]}
    stored = {
        r["credential_id"]: r.get("purpose")
        for r in make_file_store_factory(str(platform.root))("passkeys").values()
    }
    assert offered and all(stored[i] is None for i in offered)


def test_a_purpose_step_up_offers_only_that_passkey_and_confirms(platform):
    client, device, _ = _with_purpose_passkey(platform)
    options = _step_up_options(client, purpose=PURPOSE)
    assert options.status_code == 200, options.text
    offered = [c["id"] for c in options.json()["allowCredentials"]]
    pinned = client.get("/auth/passkeys", params={"purpose": PURPOSE}).json()
    assert offered == [p["credential_id"] for p in pinned["passkeys"]]
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={
            "action": ACTION,
            "purpose": PURPOSE,
            "credential": device.get(options.json()),
        },
        headers=_csrf(client),
    )
    assert r.status_code == 200, r.text


def test_a_general_step_up_answered_with_the_purpose_passkey_is_refused(platform):
    client, device, _ = _with_purpose_passkey(platform)
    options = _step_up_options(client).json()
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={
            "action": ACTION,
            "credential": device.get(options, cred=device.creds[-1]),
        },
        headers=_csrf(client),
    )
    assert r.status_code == 400


def test_a_purpose_step_up_answered_with_the_sign_in_passkey_is_refused(platform):
    client, device, _ = _with_purpose_passkey(platform)
    options = _step_up_options(client, purpose=PURPOSE).json()
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={
            "action": ACTION,
            "purpose": PURPOSE,
            "credential": device.get(options, cred=device.creds[0]),
        },
        headers=_csrf(client),
    )
    assert r.status_code == 400


def test_a_backend_request_can_name_the_purpose_and_the_page_cannot_swap_it(
    platform,
):
    client, (device,) = _enrolled(platform)
    _enrol_for_purpose(client, device, purpose=APP_PURPOSE)
    request_id = _request(platform(), purpose=APP_PURPOSE).json()["request"]
    options = client.post(
        "/auth/passkeys/step-up/options",
        json={"request": request_id, "purpose": None},
        headers=_csrf(client),
    ).json()
    assert options["purpose"] == APP_PURPOSE
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={"request": request_id, "credential": device.get(options)},
        headers=_csrf(client),
    )
    assert r.status_code == 200, r.text
    assert r.json()["audience"] == APP


def test_the_pinning_listing_gives_the_public_key_of_own_purpose_passkeys(platform):
    client, _, _ = _with_purpose_passkey(platform)
    listed = client.get("/auth/passkeys", params={"purpose": PURPOSE}).json()
    (one,) = listed["passkeys"]
    assert one["public_key"] and one["purpose"] == PURPOSE
    general = client.get("/auth/passkeys").json()["passkeys"]
    assert all("public_key" not in p for p in general)  # only when asked by purpose


def test_a_purpose_passkey_does_not_count_toward_the_policy(platform):
    client, (device,) = _enrolled(platform)
    _enrol_for_purpose(client, device)
    strict = platform(required=[OWNER], enforce_from=2)

    # One general passkey (+1 purpose one): below enforce_from, so the password
    # still signs in.
    assert _sign_in(strict).status_code == 200


def test_a_purpose_step_up_with_no_such_passkey_is_409(platform):
    client, _ = _enrolled(platform)
    r = _step_up_options(client, purpose=PURPOSE)
    assert r.status_code == 409


def test_another_account_cannot_list_or_use_my_purpose_passkey(platform):
    _with_purpose_passkey(platform)
    alice, _ = _enrolled(platform, email=ALICE)
    listed = alice.get("/auth/passkeys", params={"purpose": PURPOSE}).json()
    assert listed["passkeys"] == []


# -- review of #105 ---------------------------------------------------------------


def test_a_password_session_cannot_add_beside_or_remove_a_purpose_passkey(platform):
    """Blocker 1: purpose passkeys count as "this account has a passkey"."""
    client, device, _ = _with_purpose_passkey(platform)
    thief = platform()
    assert _sign_in(thief).status_code == 200  # the password only
    assert (
        thief.post(
            "/auth/passkeys/register/options",
            json={"purpose": PURPOSE, "label": "x"},
            headers=_csrf(thief),
        ).status_code
        == 403
    )
    purpose_id = next(
        p["id"] for p in client.get("/auth/passkeys").json()["passkeys"] if p["purpose"]
    )
    gone = thief.delete(f"/auth/passkeys/{purpose_id}", headers=_csrf(thief))
    assert gone.status_code == 403


def test_the_last_general_passkey_stays_while_purpose_ones_exist(platform):
    client, _, _ = _with_purpose_passkey(platform)
    listed = client.get("/auth/passkeys").json()["passkeys"]
    general = next(p["id"] for p in listed if not p["purpose"])
    bound = next(p["id"] for p in listed if p["purpose"])
    refused = client.delete(f"/auth/passkeys/{general}", headers=_csrf(client))
    assert refused.status_code == 409
    assert (
        client.delete(f"/auth/passkeys/{bound}", headers=_csrf(client)).status_code
        == 200
    )


def _purpose_proof(client, device, purpose=PURPOSE):
    options = _step_up_options(client, purpose=purpose)
    return client.post(
        "/auth/passkeys/step-up/verify",
        json={
            "action": ACTION,
            "purpose": purpose,
            "credential": device.get(options.json()),
        },
        headers=_csrf(client),
    ).json()["proof"]


def test_a_purpose_proof_never_redeems_as_a_general_step_up(platform):
    """Blocker 2: the proof records the purpose; redeem must name it exactly."""
    client, device, _ = _with_purpose_passkey(platform)
    proof = _purpose_proof(client, device)
    body = {"proof": proof, "action": ACTION, "email": OWNER}
    general = platform().post("/auth/passkeys/step-up/redeem", json=body)
    assert general.status_code == 400
    named = platform().post(
        "/auth/passkeys/step-up/redeem", json={**body, "purpose": PURPOSE}
    )
    assert named.status_code == 200, named.text


def test_a_general_proof_never_redeems_where_a_purpose_is_named(platform):
    client, (device,) = _enrolled(platform)
    options = _step_up_options(client).json()
    proof = client.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": device.get(options)},
        headers=_csrf(client),
    ).json()["proof"]
    r = platform().post(
        "/auth/passkeys/step-up/redeem",
        json={"proof": proof, "action": ACTION, "email": OWNER, "purpose": PURPOSE},
    )
    assert r.status_code == 400


def test_options_for_a_purpose_cannot_be_verified_without_it(platform):
    """The challenge commits to the purpose too."""
    client, device, _ = _with_purpose_passkey(platform)
    options = _step_up_options(client, purpose=PURPOSE).json()
    r = client.post(
        "/auth/passkeys/step-up/verify",
        json={"action": ACTION, "credential": device.get(options)},
        headers=_csrf(client),
    )
    assert r.status_code == 400


def test_a_backend_cannot_ask_for_another_apps_purpose(platform):
    """Major 3: a purpose belongs to the audience whose name it starts with."""
    r = _request(platform(), purpose=PURPOSE)  # "confirm-jobs" is not jobs.*
    assert r.status_code == 400
    assert "audience" in r.json()["detail"]


def test_removing_a_purpose_passkey_is_not_held_by_the_sign_in_floor(platform):
    client, (device,) = _enrolled(platform)
    _enrol_for_purpose(client, device)
    strict = platform(required=[OWNER], enforce_from=1)
    _passkey_sign_in(strict, device, cred=device.creds[0])
    bound = next(
        p["id"] for p in strict.get("/auth/passkeys").json()["passkeys"] if p["purpose"]
    )
    assert (
        strict.delete(f"/auth/passkeys/{bound}", headers=_csrf(strict)).status_code
        == 200
    )


def test_an_empty_purpose_filter_lists_without_key_material(platform):
    client, _, _ = _with_purpose_passkey(platform)
    listed = client.get("/auth/passkeys", params={"purpose": ""}).json()["passkeys"]
    assert all("public_key" not in p for p in listed)


def test_a_purpose_passkey_needs_a_sign_in_passkey_first(platform):
    """So an account always keeps a passkey it can sign in with to change them."""
    client = platform()
    assert _sign_in(client).status_code == 200
    r = client.post(
        "/auth/passkeys/register/options",
        json={"purpose": PURPOSE, "label": LABEL},
        headers=_csrf(client),
    )
    assert r.status_code == 409
