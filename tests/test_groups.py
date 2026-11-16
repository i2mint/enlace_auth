"""``[auth.groups]``: one named list of emails, written ``@name`` in an app's
``allowed_users`` and in a connector's ``resource_allowlist`` entry."""

from __future__ import annotations

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.config import AuthConfig
from enlace_auth.groups import expand_groups, is_group_ref, parse_groups
from enlace_auth.plugin import _expand_allowed_users
from tests.test_admin import _SIGNING_KEY, _csrf, _register  # noqa: F401

ACME = {"acme": ["ann@acme.com", "bob@acme.com"]}
MCP = "https://x.test/api/acme_mcp/mcp"


# -- the pure functions ------------------------------------------------------------


def test_expand_keeps_order_and_dedupes():
    got = expand_groups(["@acme", "cy@x.com", "bob@acme.com"], ACME)
    assert got == ["ann@acme.com", "bob@acme.com", "cy@x.com"]


def test_admins_and_wildcard_pass_through():
    assert expand_groups(["@admins", "*"], ACME, unknown="keep") == ["@admins", "*"]
    assert expand_groups(["*"], ACME) == ["*"]


def test_unknown_group_raises_or_is_kept():
    with pytest.raises(ValueError, match="@nope"):
        expand_groups(["@nope"], ACME)
    assert expand_groups(["@nope"], ACME, unknown="keep") == ["@nope"]


@pytest.mark.parametrize(
    "raw",
    [
        {"admins": ["a@x.io"]},
        {"Acme": ["a@x.io"]},
        {"acme": "a@x.io"},
        {"acme": ["@other"]},
        {"acme": ["*"]},
        {"acme": ["Ann <a@x.io>"]},
    ],
)
def test_parse_groups_refuses_malformed(raw):
    with pytest.raises(ValueError):
        parse_groups(raw)


def test_is_group_ref():
    assert is_group_ref("@acme") and not is_group_ref("a@acme.com")


# -- the connector allowlist -------------------------------------------------------


def _auth(**extra):
    return AuthConfig(
        oauth_server={
            "enabled": True,
            "issuer": "https://x.test",
            "resource_allowlist": {MCP: ["@acme", "owner@x.io"]},
        },
        **extra,
    )


def test_allowlist_names_the_group():
    allowlist = _auth(groups=ACME).oauth_server.resource_allowlist
    assert allowlist[MCP] == ["ann@acme.com", "bob@acme.com", "owner@x.io"]


def test_allowlist_with_an_unknown_group_does_not_load():
    with pytest.raises(ValueError, match="@acme"):
        _auth()


def test_a_dumped_config_loads_again_unchanged():
    once = _auth(groups=ACME)
    again = AuthConfig(**once.model_dump())
    assert again.oauth_server.resource_allowlist == once.oauth_server.resource_allowlist


# -- app allowed_users -------------------------------------------------------------


def test_expand_allowed_users_with_groups():
    got = _expand_allowed_users(["@acme"], (), groups=ACME)
    assert {"ann@acme.com", "bob@acme.com"} <= set(got)
    assert _expand_allowed_users(["@nope"], (), groups=ACME) == ["@nope"]


def _client(
    tmp_path, monkeypatch, *, groups, access_line='access = "protected:user"\n'
):
    apps_dir = tmp_path / "apps"
    (apps_dir / "room").mkdir(parents=True)
    (apps_dir / "room" / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/x')\ndef x():\n    return {'ok': True}\n"
    )
    (apps_dir / "room" / "app.toml").write_text(
        access_line + 'allowed_users = ["@acme"]\n'
    )
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@x.io")
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            "groups": groups,
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    client = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))
    client.user_store_root = tmp_path / "platform"
    return client


def _signed_in(client, email):
    assert (
        _register(client, email, "password-123-long-enough", _csrf(client)).status_code
        == 200
    )
    return client


def test_a_member_reaches_the_app(tmp_path, monkeypatch):
    c = _signed_in(_client(tmp_path, monkeypatch, groups=ACME), "ann@acme.com")
    assert c.get("/api/room/x").status_code == 200


def test_anyone_else_is_refused(tmp_path, monkeypatch):
    c = _signed_in(_client(tmp_path, monkeypatch, groups=ACME), "eve@x.io")
    assert c.get("/api/room/x").status_code == 403


def test_an_undefined_group_admits_nobody(tmp_path, monkeypatch):
    c = _signed_in(_client(tmp_path, monkeypatch, groups={}), "ann@acme.com")
    assert c.get("/api/room/x").status_code == 403


def test_a_group_forces_the_user_gate(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, groups=ACME, access_line='access = "public"\n')
    assert c.get("/api/room/x").status_code == 401


def test_an_empty_group_is_refused():
    with pytest.raises(ValueError, match="empty"):
        parse_groups({"acme": []})


def test_an_empty_group_never_opens_an_app():
    assert _expand_allowed_users(["@acme"], (), groups={"acme": []}) == ["@acme"]


def test_admins_in_an_allowlist_says_what_to_do():
    with pytest.raises(ValueError, match="@admins"):
        expand_groups(["@admins"], ACME)
