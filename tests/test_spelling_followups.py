"""Follow-ups to the two-spelling lists of #50 (i2mint/enlace_auth#52).

A list entry admits both canonical spellings of its address, so:

- ``doctor`` reports an account admitted only through the other spelling when it
  was self-registered, and, with open registration, a punycode entry whose
  Unicode spelling anyone could still register;
- revoking a grant or share says what it removed (the two spellings may be two
  distinct accounts), and a typed side of a share is matched in either spelling
  while a session's own side never is;
- the per-request grant check does not depend on the shared spelling cache.
"""

from __future__ import annotations

import pytest
from enlace.base import PlatformConfig

from enlace_auth import emails
from enlace_auth.auth import grants as grants_mod
from enlace_auth.auth.grants import GrantStore
from enlace_auth.auth.shares import ShareStore
from enlace_auth.diagnostics import check_widened_spellings
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import _csrf, _grant, _register, admin_client  # noqa: F401

PUNY = "ann@xn--bcher-kva.example"
UNI = "ann@bücher.example"
OWNER = "owner@example.com"


def _config(tmp_path, **auth):
    return PlatformConfig(
        apps_dir=tmp_path / "apps",
        auth={
            "enabled": True,
            "stores": {"backend": "file", "path": str(tmp_path / "store")},
            **auth,
        },
    )


def _stores(tmp_path):
    factory = make_file_store_factory(str(tmp_path / "store"))
    grants = GrantStore(factory("grants"), root=tmp_path / "store" / "grants")
    return factory("users"), grants


def _statuses(tmp_path, **auth):
    return [
        (c.status, c.detail) for c in check_widened_spellings(_config(tmp_path, **auth))
    ]


# --- doctor --------------------------------------------------------------------


def test_doctor_warns_about_a_self_registered_other_spelling(tmp_path):
    (tmp_path / "apps").mkdir()
    users, grants = _stores(tmp_path)
    grants.grant("vault", PUNY)
    users[UNI] = {"password_hash": "x", "created_via": "register"}
    [(status, detail)] = _statuses(tmp_path)
    assert status == "warn" and UNI in detail and "self-registered" in detail


def test_doctor_trusts_an_operator_made_other_spelling(tmp_path):
    (tmp_path / "apps").mkdir()
    users, grants = _stores(tmp_path)
    grants.grant("vault", PUNY)
    users[UNI] = {"password_hash": "x", "created_via": "admin"}
    [(status, _)] = _statuses(tmp_path)
    assert status == "pass"


@pytest.mark.parametrize("registration_open", [True, False])
def test_doctor_warns_about_a_claimable_punycode_entry(tmp_path, registration_open):
    (tmp_path / "apps").mkdir()
    _, grants = _stores(tmp_path)
    grants.grant("vault", PUNY)
    [(status, detail)] = _statuses(tmp_path, registration_open=registration_open)
    if registration_open:
        assert status == "warn" and PUNY in detail and "register" in detail
    else:
        assert status == "pass"


def test_doctor_reads_connector_allowlists_too(tmp_path):
    (tmp_path / "apps").mkdir()
    _stores(tmp_path)
    statuses = _statuses(
        tmp_path,
        registration_open=True,
        oauth_server={"resource_allowlist": {"https://x.example/mcp": [PUNY]}},
    )
    [(status, detail)] = statuses
    assert status == "warn" and "https://x.example/mcp" in detail


def test_a_unicode_entry_is_not_the_new_exposure(tmp_path):
    """Registration keys the Unicode form, so a Unicode entry is first-come as
    any ASCII entry always was; only punycode entries changed with #50."""
    (tmp_path / "apps").mkdir()
    _, grants = _stores(tmp_path)
    grants.grant("vault", UNI)
    [(status, _)] = _statuses(tmp_path, registration_open=True)
    assert status == "pass"


def test_doctor_checks_the_other_spelling_even_when_the_written_one_has_an_account(
    tmp_path,
):
    """The realistic shape: the real user signed in through OAuth in punycode,
    a squatter had registered the Unicode form before #50 refused it."""
    (tmp_path / "apps").mkdir()
    users, grants = _stores(tmp_path)
    grants.grant("vault", PUNY)
    users[PUNY] = {"created_via": "oauth:google"}
    users[UNI] = {"password_hash": "x", "created_via": "register"}
    [(status, detail)] = _statuses(tmp_path)
    assert status == "warn" and UNI in detail


def test_doctor_survives_a_corrupt_account_record(tmp_path):
    (tmp_path / "apps").mkdir()
    _, grants = _stores(tmp_path)
    grants.grant("vault", PUNY)
    (tmp_path / "store" / "users" / UNI).write_text("not json {")
    [(status, detail)] = _statuses(tmp_path)
    assert status == "warn" and "unreadable" in detail


def test_doctor_creates_no_store(tmp_path):
    (tmp_path / "apps").mkdir()
    [(status, _)] = _statuses(tmp_path)
    assert status == "skip"
    assert not (tmp_path / "store").exists()


# --- revoke reporting ----------------------------------------------------------


def test_grant_revoke_reports_both_spellings():
    store = GrantStore({})
    store.grant("app", PUNY)
    store.grant("app", UNI)
    assert sorted(store.revoke("app", UNI)) == sorted([PUNY, UNI])
    assert store.revoke("app", UNI) == []


def _shares():
    users = {UNI, PUNY, OWNER}
    return ShareStore({}, account_exists=users.__contains__)


def test_a_typed_grantee_matches_either_spelling():
    shares = _shares()
    shares.share("app", OWNER, UNI)
    assert shares.revoke("app", OWNER, PUNY) == []  # exact by default
    assert shares.revoke("app", OWNER, PUNY, widen_grantee=True) == [(OWNER, UNI)]


def test_a_session_side_is_never_widened():
    """PUNY and UNI are two accounts here; leaving as UNI must not end PUNY's share."""
    shares = _shares()
    shares.share("app", OWNER, PUNY)
    assert shares.revoke("app", OWNER, UNI, widen_owner=True) == []
    assert shares.access("app", OWNER, PUNY) == "rw"


def test_remove_account_still_counts():
    shares = _shares()
    shares.share("app", OWNER, UNI)
    assert shares.remove_account(OWNER) == 1


# --- hot path --------------------------------------------------------------------


def test_the_grant_hot_path_survives_shared_cache_churn():
    store = GrantStore({})
    store.grant("app", PUNY)
    grants_mod._grant_spellings.cache_clear()
    assert {PUNY, UNI} <= store.active_emails_for_app("app")
    emails._canonical_spellings.cache_clear()  # what attacker strings would do
    before = emails._canonical_spellings.cache_info().misses
    assert {PUNY, UNI} <= store.active_emails_for_app("app")
    assert emails._canonical_spellings.cache_info().misses == before


def test_admin_grant_revoke_lists_what_it_removed(admin_client):  # noqa: F811
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    _grant(admin_client, "vault", "carl@example.com", csrf)
    r = admin_client.delete("/_admin/api/grants/vault/carl@example.com", headers=csrf)
    assert r.status_code == 200, r.text
    assert r.json()["removed"] == ["carl@example.com"]


def test_leaving_names_one_owner_even_if_both_spellings_shared():
    """PUNY and UNI are two owners here; leaving one must not leave the other."""
    shares = _shares()
    me = OWNER
    shares.share("app", UNI, me)
    shares.share("app", PUNY, me)
    removed = shares.revoke("app", UNI, me, widen_owner=True, first_only=True)
    assert removed == [(UNI, me)]
    assert shares.access("app", PUNY, me) == "rw"
    # Typed in the other spelling with only one share left, it still finds it.
    assert shares.revoke("app", UNI, me, widen_owner=True, first_only=True) == [
        (PUNY, me)
    ]
