"""Admin addresses must not be claimable by self-registration (i2mint/enlace_auth#35).

``/auth/register`` checks only "no account yet" plus the registration predicate,
with no proof that the registrant owns the address. So an admin address with no
account must not be in the self-registration allow-set: whoever registers it
first would pass every ``@admins`` gate. Admin accounts are made with the CLI
(``enlace-auth add-user``), and ``doctor`` warns about admin addresses that have
no account yet.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from enlace import doctor as doctor_mod
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from fastapi.testclient import TestClient

from enlace_auth import diagnostics as auth_diag
from enlace_auth import plugin as auth_plugin
from enlace_auth.plugin import _build_can_register
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import _SIGNING_KEY, _csrf, _register, _write_dummy_app

_ADMIN = "boss@example.com"
_INVITED = "guest@example.com"


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", _ADMIN)
    monkeypatch.setenv("ENLACE_REGISTRATION_ALLOWLIST", _INVITED)
    return monkeypatch


def _auth(tmp_path, **extra):
    return {
        "enabled": True,
        "secure_cookies": False,
        "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        **extra,
    }


def _client(tmp_path):
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_dummy_app(apps_dir)
    config = PlatformConfig(apps_dir=apps_dir, auth=_auth(tmp_path))
    return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))


def test_admin_address_is_not_in_the_allow_set(env):
    can_register = _build_can_register(
        SimpleNamespace(registration_allowlist_env="ENLACE_REGISTRATION_ALLOWLIST"),
        (_ADMIN,),
    )
    assert not can_register(_ADMIN)
    assert not can_register(_ADMIN.upper())
    assert can_register(_INVITED)


def test_unclaimed_admin_address_cannot_be_self_registered(env, tmp_path):
    client = _client(tmp_path)
    csrf = _csrf(client)
    assert _register(client, _ADMIN, "attacker-pw1", csrf).status_code == 403
    # The allowlist itself still works.
    assert _register(client, _INVITED, "guest-pw-123", csrf).status_code == 200


def _admin_check(tmp_path, single_app_dir, *, registration_open=False):
    cfg = PlatformConfig(
        apps_dir=single_app_dir,
        auth=_auth(tmp_path, registration_open=registration_open),
    )
    report = doctor_mod.run_doctor(
        discover_apps(cfg), extra_static_checks=auth_diag.static_checks
    )
    return [c for c in report.checks if c.name == "admin_accounts"]


def test_doctor_warns_about_admin_address_with_no_account(
    env, tmp_path, single_app_dir
):
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.WARN
    assert _ADMIN in check.detail
    assert "add-user" in check.detail


def test_doctor_names_the_exposure_when_registration_is_open(
    env, tmp_path, single_app_dir
):
    [check] = _admin_check(tmp_path, single_app_dir, registration_open=True)
    assert check.status == doctor_mod.WARN
    assert "registration_open" in check.detail


def test_doctor_passes_once_every_admin_has_an_account(env, tmp_path, single_app_dir):
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[_ADMIN] = {"password_hash": "x", "created_at": 0}
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.PASS


def test_doctor_skips_when_no_admins_are_configured(env, tmp_path, single_app_dir):
    env.delenv("ENLACE_ADMIN_EMAILS")
    [check] = _admin_check(tmp_path, single_app_dir)
    assert check.status == doctor_mod.SKIP
