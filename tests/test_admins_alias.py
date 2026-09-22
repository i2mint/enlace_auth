"""``allowed_users = ["@admins"]`` gates an app to the platform admins.

The alias lets an owner-only app be declared without committing an email
address, and must fail CLOSED: with no admins configured the app admits nobody
(an empty ``allowed_users`` would mean "any signed-in user").
"""

from __future__ import annotations

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.plugin import ADMINS_ALIAS, _expand_allowed_users
from tests.test_admin import _SIGNING_KEY, _csrf, _login, _register  # noqa: F401


def _client(
    tmp_path,
    monkeypatch,
    *,
    admins: str,
    access_line: str = 'access = "protected:user"\n',
) -> TestClient:
    apps_dir = tmp_path / "apps"
    (apps_dir / "ping").mkdir(parents=True)
    (apps_dir / "ping" / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/ping')\ndef ping():\n    return {'ok': True}\n"
    )
    (apps_dir / "owner_tool").mkdir()
    (apps_dir / "owner_tool" / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/x')\ndef x():\n    return {'ok': True}\n"
    )
    (apps_dir / "owner_tool" / "app.toml").write_text(
        access_line + 'allowed_users = ["@admins"]\n'
    )
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", admins)
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))


def _signed_in(client, email):
    csrf = _csrf(client)
    assert _register(client, email, "password-123", csrf).status_code == 200
    return client


def _app_names(client):
    body = client.get("/_apps").json()
    apps = body["apps"] if isinstance(body, dict) else body
    return {a["name"] for a in apps}


def test_admin_reaches_admins_only_app(tmp_path, monkeypatch):
    c = _signed_in(
        _client(tmp_path, monkeypatch, admins="Boss@example.com"), "boss@example.com"
    )
    assert c.get("/api/owner_tool/x").status_code == 200
    assert "owner_tool" in _app_names(c)


def test_other_user_is_refused_and_does_not_see_it(tmp_path, monkeypatch):
    c = _signed_in(
        _client(tmp_path, monkeypatch, admins="boss@example.com"), "eve@example.com"
    )
    assert c.get("/api/owner_tool/x").status_code == 401
    assert "owner_tool" not in _app_names(c)


def test_anonymous_is_refused(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, admins="boss@example.com")
    assert c.get("/api/owner_tool/x").status_code == 401


def test_no_admins_configured_fails_closed(tmp_path, monkeypatch):
    c = _signed_in(_client(tmp_path, monkeypatch, admins=""), "eve@example.com")
    assert c.get("/api/owner_tool/x").status_code == 401


@pytest.mark.parametrize(
    "allowed, admins, expected",
    [
        ([], ("a@x.io",), []),
        (["u@x.io"], ("a@x.io",), ["u@x.io"]),
        ([ADMINS_ALIAS], ("a@x.io", "b@x.io"), ["a@x.io", "b@x.io"]),
        (["a@x.io", ADMINS_ALIAS], ("a@x.io",), ["a@x.io"]),
        ([ADMINS_ALIAS], (), [ADMINS_ALIAS]),
    ],
)
def test_expand_allowed_users(allowed, admins, expected):
    assert _expand_allowed_users(allowed, admins) == expected


@pytest.mark.parametrize(
    "access_line", ["", 'access = "public"\n', 'access = "protected:shared"\n']
)
def test_alias_without_user_gate_still_fails_closed(tmp_path, monkeypatch, access_line):
    """allowed_users is only enforced for protected:user; the alias forces it."""
    c = _client(
        tmp_path, monkeypatch, admins="boss@example.com", access_line=access_line
    )
    assert c.get("/api/owner_tool/x").status_code == 401
    assert "owner_tool" not in _app_names(c)
    _signed_in(c, "eve@example.com")
    assert c.get("/api/owner_tool/x").status_code == 401
    assert "owner_tool" not in _app_names(c)


def test_no_admins_configured_hides_the_app(tmp_path, monkeypatch):
    c = _signed_in(_client(tmp_path, monkeypatch, admins=""), "eve@example.com")
    assert "owner_tool" not in _app_names(c)
