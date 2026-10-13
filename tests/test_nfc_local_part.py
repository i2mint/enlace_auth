"""A decomposed local part is refused, never composed onto another key (#51).

``EmailStr`` NFC-composes the local part. A mail system that compares local parts
as bytes delivers ``josé`` composed and ``josé`` decomposed to two mailboxes, so
keying both under the composed form would merge two people into one account.
``add-user``, the admin API and ``/auth/register`` refuse the decomposed form
with a message saying why; the composed form is accepted as before.
"""

from __future__ import annotations

import unicodedata

import pytest

from enlace_auth.__main__ import _normalized_email
from enlace_auth.emails import account_spellings, local_part_problem, normalize_email
from tests.test_admin import _csrf, _register, admin_client  # noqa: F401
from tests.test_admin_registration import _client, env  # noqa: F401

COMPOSED = "josé@example.com"
DECOMPOSED = unicodedata.normalize("NFD", COMPOSED)
assert COMPOSED != DECOMPOSED


def test_normalize_email_refuses_a_decomposed_local_part():
    assert local_part_problem(COMPOSED) is None
    assert "NFC" in local_part_problem(DECOMPOSED)
    assert normalize_email(COMPOSED) == COMPOSED
    with pytest.raises(ValueError, match="NFC"):
        normalize_email(DECOMPOSED)


def test_a_decomposed_domain_is_still_one_dns_name():
    """Only the local part is a mailbox name; IDNA maps the domain itself."""
    decomposed_domain = unicodedata.normalize("NFD", "ann@bücher.example")
    assert normalize_email(decomposed_domain) == "ann@bücher.example"


def test_a_decomposed_list_entry_is_still_not_widened():
    assert account_spellings(DECOMPOSED) == (DECOMPOSED,)


def test_add_user_refuses_and_says_why(capsys):
    with pytest.raises(SystemExit):
        _normalized_email(DECOMPOSED)
    assert "NFC" in capsys.readouterr().err
    assert _normalized_email(COMPOSED) == COMPOSED


def test_register_refuses_a_decomposed_local_part(env, tmp_path):  # noqa: F811
    env.setenv("ENLACE_REGISTRATION_ALLOWLIST", f"{COMPOSED},{DECOMPOSED}")
    client = _client(tmp_path)
    csrf = _csrf(client)
    r = _register(client, DECOMPOSED, "decomposed-pw1", csrf)
    assert r.status_code == 400, r.text
    assert "NFC" in r.json()["detail"]
    assert _register(client, COMPOSED, "composed-pw-1", csrf).status_code == 200


def test_register_refuses_the_display_name_form(env, tmp_path):  # noqa: F811
    """EmailStr would key ``ann <x@y>`` as ``x@y``; the account key refuses it."""
    env.setenv("ENLACE_REGISTRATION_ALLOWLIST", "guest@example.com")
    client = _client(tmp_path)
    r = _register(client, "ann <guest@example.com>", "guest-pw-123", _csrf(client))
    assert r.status_code == 400, r.text


def test_admin_create_user_refuses_a_decomposed_local_part(admin_client):  # noqa: F811
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(
        "/_admin/api/users",
        json={"email": DECOMPOSED, "password": "decomposed-pw1"},
        headers=csrf,
    )
    assert r.status_code == 400, r.text
    assert "NFC" in r.json()["detail"]
    ok = admin_client.post(
        "/_admin/api/users",
        json={"email": COMPOSED, "password": "composed-pw-1"},
        headers=csrf,
    )
    assert ok.status_code == 200, ok.text


def test_the_message_names_the_culprit_and_stays_short():
    assert "U+0301" in local_part_problem(DECOMPOSED)
    with pytest.raises(ValueError) as e:
        normalize_email("x" * 3000 + "@example.com")
    assert len(str(e.value)) < 200


@pytest.mark.parametrize(
    "path, body",
    [
        ("/_admin/api/grants", {"app_id": "vault", "email": DECOMPOSED}),
        (
            "/_admin/api/shares",
            {"app_id": "vault", "owner": "boss@example.com", "grantee": DECOMPOSED},
        ),
    ],
)
def test_admin_grants_and_shares_refuse_a_decomposed_address(
    admin_client,  # noqa: F811
    path,
    body,
):
    """A grant or share must not land on the composed account either."""
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.post(path, json=body, headers=csrf)
    assert r.status_code == 422, r.text
    assert "NFC" in r.text
