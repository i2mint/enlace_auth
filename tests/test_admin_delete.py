# ruff: noqa: F811 -- the admin_client fixture is imported from test_admin, and
# pytest injects it by parameter name, which ruff reads as a redefinition.
"""An admin deleting an account erases what the account would erase itself (#92).

The self-service deletion removed the record, sessions, shares, grants, per-user
data, last sign-in and passkeys; the admin page removed only the first three, so an
erasure done on someone's behalf left their data on disk and a grant that re-admits
the address if it is registered again. Both now go through one deleter, and so does
``enlace-auth delete-user``.
"""

from __future__ import annotations

import time

import pytest

from enlace_auth.__main__ import _load_grant_store, _load_user_store, delete_user
from enlace_auth.auth.grants import GrantStore
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import (  # noqa: F401 - fixture re-export
    _csrf,
    _login,
    _register,
    admin_client,
)
from tests.test_cli import _make_platform_toml
from tests.test_session_revocation import _second_client, _setup_admin_and_user

VIC = "vic@example.com"


def _files_naming(root, email):
    return [p for p in root.rglob("*") if p.is_file() and email in str(p)]


def test_admin_delete_removes_data_grants_and_last_sign_in(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client, email=VIC)
    root = admin_client.user_store_root
    data_root = root.parent / "data"
    put = holder.put(
        "/api/lobby/store/progress", json={"level": 3}, headers=_csrf(holder)
    )
    assert put.status_code in (200, 201, 204), put.text
    assert _files_naming(data_root, VIC)
    grants = GrantStore(make_file_store_factory(str(root))("grants"))
    grants.grant("vault", VIC)
    sign_ins = make_file_store_factory(str(root))("sign_ins")
    assert VIC in sign_ins

    r = admin_client.delete(f"/_admin/api/users/{VIC}", headers=csrf)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["failed"] == []
    assert body["removed"]["grants"] == 1
    assert body["removed"]["user data"] >= 1
    assert body["removed"]["last sign-in"] == 1
    assert not _files_naming(data_root, VIC)
    assert grants.get("vault", VIC) is None
    assert VIC not in sign_ins
    assert holder.get("/api/lobby/").status_code == 401


def test_admin_delete_leaves_everyone_elses_data(admin_client):
    csrf, vic = _setup_admin_and_user(admin_client, email=VIC)
    other = _second_client(admin_client)
    admin_client.post(
        "/_admin/api/users",
        json={"email": "ann@example.com", "password": "ann-pw1-long-enough"},
        headers=csrf,
    )
    signed_in = _login(other, "ann@example.com", "ann-pw1-long-enough", _csrf(other))
    assert signed_in.status_code == 200
    for client in (vic, other):
        client.put("/api/lobby/store/p", json={"v": 1}, headers=_csrf(client))
    assert (
        admin_client.delete(f"/_admin/api/users/{VIC}", headers=csrf).status_code == 200
    )
    assert other.get("/api/lobby/store/p").status_code == 200
    data_root = admin_client.user_store_root.parent / "data"
    assert _files_naming(data_root, "ann@example.com")


def test_a_non_admin_still_cannot_delete_anyone(admin_client):
    csrf, holder = _setup_admin_and_user(admin_client, email=VIC)
    r = holder.delete("/_admin/api/users/boss@example.com", headers=_csrf(holder))
    assert r.status_code == 403
    users = make_file_store_factory(str(admin_client.user_store_root))("users")
    assert "boss@example.com" in users


def test_admin_delete_of_an_unknown_account_is_404(admin_client):
    csrf = _csrf(admin_client)
    _register(admin_client, "boss@example.com", "bosspw1!", csrf)
    r = admin_client.delete("/_admin/api/users/ghost@example.com", headers=csrf)
    assert r.status_code == 404


# -- the CLI ---------------------------------------------------------------


def _cli_platform(tmp_path):
    toml = _make_platform_toml(tmp_path)
    data_path = tmp_path / "user_data"
    toml.write_text(
        toml.read_text() + f'\n\n[stores.user_data]\nbackend = "file"\n'
        f'path = "{data_path}"\n'
    )
    store_root = tmp_path / "platform_store"
    _load_user_store(toml)[VIC] = {"password_hash": "x", "created_at": time.time()}
    _load_grant_store(toml).grant("vault", VIC)
    make_file_store_factory(str(store_root))("sign_ins")[VIC] = time.time()
    data = make_file_store_factory(str(data_path))("user_data")
    data[f"{VIC}/game/progress"] = {"level": 2}
    data["ann@example.com/game/progress"] = {"level": 5}
    return toml, data


def test_cli_delete_user_removes_everything(tmp_path, capsys):
    toml, data = _cli_platform(tmp_path)
    delete_user(VIC, toml=str(toml))
    out = capsys.readouterr().out
    assert f"Deleted {VIC}." in out
    assert "grants: 1" in out and "user data: 1" in out and "last sign-in: 1" in out
    assert VIC not in _load_user_store(toml)
    assert _load_grant_store(toml).get("vault", VIC) is None
    assert sorted(data) == ["ann@example.com/game/progress"]


def test_cli_delete_user_keep_data(tmp_path, capsys):
    toml, data = _cli_platform(tmp_path)
    delete_user(VIC, keep_data=True, toml=str(toml))
    assert "user data: kept" in capsys.readouterr().out
    assert VIC not in _load_user_store(toml)
    assert f"{VIC}/game/progress" in data


def test_cli_delete_user_unknown_account_exits_1(tmp_path):
    toml, data = _cli_platform(tmp_path)
    with pytest.raises(SystemExit) as e:
        delete_user("ghost@example.com", toml=str(toml))
    assert e.value.code == 1
    assert f"{VIC}/game/progress" in data


def test_cli_delete_user_deletes_the_spelling_typed_not_a_look_alike(tmp_path):
    """Normalizing first would fold a fullwidth letter onto another account."""
    toml, _ = _cli_platform(tmp_path)
    users = _load_user_store(toml)
    plain, look_alike = "ann@bücher.example", "ann@ｂücher.example"
    users[plain] = {"password_hash": "x"}
    users[look_alike] = {"password_hash": "y"}
    delete_user(look_alike, toml=str(toml))
    users = _load_user_store(toml)
    assert plain in users and look_alike not in users


def test_cli_delete_user_takes_an_address_email_validation_refuses(tmp_path):
    toml, _ = _cli_platform(tmp_path)
    _load_user_store(toml)["ann@corp.local"] = {"password_hash": "x"}
    delete_user("ann@corp.local", toml=str(toml))
    assert "ann@corp.local" not in _load_user_store(toml)


def test_a_grant_in_the_other_spelling_goes_with_the_account(tmp_path):
    toml, _ = _cli_platform(tmp_path)
    _load_user_store(toml)["ann@bücher.example"] = {"password_hash": "x"}
    grants = _load_grant_store(toml)
    grants.grant("vault", "ann@xn--bcher-kva.example")
    delete_user("ann@bücher.example", toml=str(toml))
    assert _load_grant_store(toml).get("vault", "ann@xn--bcher-kva.example") is None


def test_a_grant_in_the_other_spelling_stays_when_that_spelling_is_an_account(
    tmp_path,
):
    toml, _ = _cli_platform(tmp_path)
    users = _load_user_store(toml)
    users["ann@bücher.example"] = {"password_hash": "x"}
    users["ann@xn--bcher-kva.example"] = {"password_hash": "y"}
    _load_grant_store(toml).grant("vault", "ann@xn--bcher-kva.example")
    delete_user("ann@bücher.example", toml=str(toml))
    grants = _load_grant_store(toml)
    assert grants.get("vault", "ann@xn--bcher-kva.example") is not None
