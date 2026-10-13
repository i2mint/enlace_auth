"""Written email lists admit both canonical spellings of an address (#45).

A punycode domain and its Unicode form are one mailbox, but an account is keyed in
whichever spelling made it: ``add-user`` and ``/auth/register`` store the Unicode
form, an OAuth sign-in the provider's spelling. Every list someone writes (an
app's ``allowed_users`` and ``@admins``, runtime grants, shares, app-meta editors,
the admin API's ``/users/{email}`` paths) must therefore match either spelling.

The other half of the rule: only a list entry is widened, never the key an
account is stored under, and widening never folds a look-alike (fullwidth
letters, a decomposed accent) onto a real address.
"""

from __future__ import annotations

import unicodedata

import pytest

from enlace_auth.appmeta import make_appmeta_can_edit
from enlace_auth.auth.grants import GrantStore
from enlace_auth.auth.shares import ShareStore
from enlace_auth.emails import account_spellings, resolve_account
from enlace_auth.plugin import ADMINS_ALIAS, _expand_allowed_users
from tests.test_admin import _csrf, _register, admin_client  # noqa: F401

PUNY = "ann@xn--bcher-kva.example"
UNI = "ann@bücher.example"
FULLWIDTH = "ann@ｂücher.example"  # fullwidth b: a look-alike of UNI
DECOMPOSED = unicodedata.normalize("NFD", UNI)  # u + combining diaeresis


# --- the rule ----------------------------------------------------------------


@pytest.mark.parametrize(
    "written, expected",
    [
        (PUNY, (PUNY, UNI)),
        (PUNY.upper(), (PUNY, UNI)),
        (UNI, (UNI, PUNY)),
        (" Ann@Bücher.Example ", (UNI, PUNY)),
        ("ann@example.com", ("ann@example.com",)),
        ("ann@corp.local", ("ann@corp.local",)),  # EmailStr refuses .local
        ("@admins", ("@admins",)),
    ],
)
def test_account_spellings(written, expected):
    assert account_spellings(written) == expected


@pytest.mark.parametrize("look_alike", [FULLWIDTH, DECOMPOSED])
def test_a_look_alike_entry_is_never_folded_onto_the_real_address(look_alike):
    assert UNI not in account_spellings(look_alike)
    assert PUNY not in account_spellings(look_alike)


def test_resolve_account_prefers_the_exact_key():
    both = {UNI, PUNY}.__contains__
    assert resolve_account(PUNY, both) == PUNY
    assert resolve_account(UNI, both) == UNI
    assert resolve_account(PUNY, {UNI}.__contains__) == UNI
    assert resolve_account(FULLWIDTH, {UNI}.__contains__) is None


# --- allowed_users and @admins -----------------------------------------------


def test_allowed_users_admit_both_spellings():
    assert set(_expand_allowed_users([PUNY], ())) == {PUNY, UNI}


def test_admins_alias_means_exactly_the_admin_list():
    """``@admins`` must not admit a non-admin account in another spelling."""
    out = _expand_allowed_users([ADMINS_ALIAS, PUNY], (UNI,))
    assert out == [UNI, PUNY]
    assert _expand_allowed_users([ADMINS_ALIAS], (PUNY,)) == [PUNY]


def test_admins_alias_with_no_admins_still_admits_nobody():
    assert _expand_allowed_users([ADMINS_ALIAS], ()) == [ADMINS_ALIAS]


def test_a_look_alike_allowed_user_does_not_admit_the_real_account():
    assert UNI not in _expand_allowed_users([FULLWIDTH], ())


# --- runtime grants ----------------------------------------------------------


def test_a_grant_in_one_spelling_admits_the_other():
    store = GrantStore({})
    store.grant("app", PUNY)
    assert {PUNY, UNI} <= store.active_emails_for_app("app")
    assert store.get("app", UNI)["email"] == PUNY


def test_revoke_by_either_spelling():
    store = GrantStore({})
    store.grant("app", UNI)
    assert store.revoke("app", PUNY)
    assert store.active_emails_for_app("app") == set()
    assert not store.revoke("app", PUNY)


def test_a_look_alike_grant_does_not_admit_the_real_account():
    store = GrantStore({})
    store.grant("app", FULLWIDTH)
    assert UNI not in store.active_emails_for_app("app")
    assert store.get("app", UNI) is None


# --- shares ------------------------------------------------------------------


def test_a_share_is_stored_under_the_grantees_actual_key():
    users = {UNI, "owner@example.com"}
    shares = ShareStore({}, account_exists=users.__contains__)
    record = shares.share("app", "owner@example.com", PUNY)
    assert record["grantee"] == UNI
    assert shares.access("app", "owner@example.com", UNI) == "rw"


def test_reading_a_share_compares_the_session_key_exactly():
    """The grantee at read time is a session's own key: never widened."""
    users = {UNI, PUNY, "owner@example.com"}
    shares = ShareStore({}, account_exists=users.__contains__)
    shares.share("app", "owner@example.com", UNI)
    assert shares.access("app", "owner@example.com", PUNY) is None


def test_a_look_alike_grantee_is_refused_not_folded():
    users = {UNI, "owner@example.com"}
    shares = ShareStore({}, account_exists=users.__contains__)
    with pytest.raises(ValueError, match="No account"):
        shares.share("app", "owner@example.com", FULLWIDTH)


# --- app-meta editors --------------------------------------------------------


def test_editors_admit_both_spellings():
    can_edit = make_appmeta_can_edit((PUNY,))
    assert can_edit(UNI) and can_edit(PUNY)


def test_a_look_alike_editor_does_not_admit_the_real_account():
    assert not make_appmeta_can_edit((FULLWIDTH,))(UNI)


# --- admin API /users/{email} ------------------------------------------------


def test_admin_paths_resolve_either_spelling(admin_client):  # noqa: F811
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    made = admin_client.post(
        "/_admin/api/users",
        json={"email": PUNY, "password": "long-enough-pw"},
        headers=csrf,
    )
    assert made.status_code == 200, made.text
    assert made.json()["email"] == UNI  # EmailStr keyed it in Unicode

    reset = admin_client.post(
        f"/_admin/api/users/{PUNY}/password",
        json={"password": "another-long-pw"},
        headers=csrf,
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["email"] == UNI

    gone = admin_client.delete(f"/_admin/api/users/{PUNY}", headers=csrf)
    assert gone.status_code == 200, gone.text
    assert (
        admin_client.delete(f"/_admin/api/users/{UNI}", headers=csrf).status_code == 404
    )


# --- registration ------------------------------------------------------------


def test_register_refuses_the_other_spelling_of_an_existing_account(
    admin_client,  # noqa: F811
):
    """Open registration must not claim the spelling a list now also admits."""
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    admin_client.post(
        "/_admin/api/users",
        json={"email": UNI, "password": "long-enough-pw"},
        headers=csrf,
    )
    r = admin_client.post(
        "/auth/register",
        json={"email": PUNY, "password": "long-enough-pw"},
        headers=csrf,
    )
    assert r.status_code == 409, r.text


# --- adversarial review of #50 ------------------------------------------------


def test_registration_refuses_every_spelling_of_an_admin_address():
    """Else open registration could claim the admin's other spelling."""
    from types import SimpleNamespace

    from enlace_auth.plugin import _build_can_register

    can_register = _build_can_register(SimpleNamespace(registration_open=True), (PUNY,))
    assert not can_register(UNI) and not can_register(PUNY)
    assert can_register("someone@example.com")


def test_registration_allowlist_admits_both_spellings(monkeypatch):
    from types import SimpleNamespace

    from enlace_auth.plugin import _build_can_register

    monkeypatch.setenv("TEST_REG_ALLOW", PUNY)
    cfg = SimpleNamespace(
        registration_open=False, registration_allowlist_env="TEST_REG_ALLOW"
    )
    can_register = _build_can_register(cfg, ())
    assert can_register(UNI) and can_register(PUNY)
    assert not can_register(FULLWIDTH)


def test_the_admin_default_editor_list_is_not_widened():
    can_edit = make_appmeta_can_edit((PUNY,), widen=False)
    assert can_edit(PUNY) and not can_edit(UNI)


def test_a_lowercase_fold_is_not_widened():
    assert account_spellings("Kate@bücher.example") == ("kate@bücher.example",)


def test_an_over_long_entry_is_returned_as_written():
    long = "a" * 300 + "@example.com"
    assert account_spellings(long) == (long,)


def test_a_share_owner_is_never_resolved():
    users = {UNI, "bob@example.com"}
    shares = ShareStore({}, account_exists=users.__contains__)
    with pytest.raises(ValueError, match="No account"):
        shares.share("app", PUNY, "bob@example.com")
