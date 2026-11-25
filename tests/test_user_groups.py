"""``request.state.user_groups``: the signed-in account's groups, for app backends.

i2mint/enlace_auth#108: a ``public`` app that lets a few people edit decides in its own
backend whether the caller may write. The platform already knows (``[auth.groups]`` and
the admins), so it hands the app a ``frozenset`` of group names beside ``user_email``,
and membership lives in platform config only. Nothing a client sends can add a name.
"""

from __future__ import annotations

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.plugin import user_groups_resolver
from tests.test_admin import _SIGNING_KEY, _csrf, _register

ADMIN = "boss@x.io"
GROUPS = {"editors": ["ann@x.io"], "other": ["bob@x.io"]}
_SERVER = (
    "from fastapi import FastAPI, Request\napp = FastAPI()\n"
    "@app.get('/me')\ndef me(request: Request):\n"
    "    g = request.state.user_groups\n"
    "    assert isinstance(g, frozenset)\n"
    "    return {'groups': sorted(g), 'email': request.state.user_email}\n"
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    for name, toml in {
        "pub": 'access = "public"\n',
        "priv": 'access = "protected:user"\n',
    }.items():
        (apps_dir / name).mkdir(parents=True)
        (apps_dir / name / "server.py").write_text(_SERVER)
        (apps_dir / name / "app.toml").write_text(toml)
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", ADMIN)
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            "groups": GROUPS,
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    c = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))
    c.user_store_root = tmp_path / "platform"
    return c


def _sign_in(client, email):
    r = _register(client, email, "password-123-long-enough", _csrf(client))
    assert r.status_code == 200
    return client


@pytest.mark.parametrize("app", ["pub", "priv"])
def test_a_member_sees_its_group(client, app):
    _sign_in(client, "ann@x.io")
    assert client.get(f"/api/{app}/me").json()["groups"] == ["editors"]


def test_an_admin_is_in_admins(client):
    _sign_in(client, ADMIN)
    assert client.get("/api/pub/me").json()["groups"] == ["admins"]


def test_a_non_member_is_in_no_group(client):
    _sign_in(client, "eve@x.io")
    assert client.get("/api/priv/me").json()["groups"] == []


def test_anonymous_on_a_public_app_is_in_no_group(client):
    assert client.get("/api/pub/me").json() == {"groups": [], "email": None}


def test_whoami_lists_the_groups(client):
    _sign_in(client, "ann@x.io")
    assert client.get("/auth/whoami").json()["groups"] == ["editors"]


# -- a client cannot forge them ----------------------------------------------------


_FORGED = {
    "X-User-Groups": "editors,admins",
    "X-Forwarded-Groups": "editors,admins",
    "X-User-Email": "ann@x.io",
}


def test_headers_cannot_add_a_group_anonymously(client):
    r = client.get("/api/pub/me", headers=_FORGED)
    assert r.json() == {"groups": [], "email": None}


def test_headers_cannot_add_a_group_to_a_signed_in_account(client):
    _sign_in(client, "eve@x.io")
    r = client.get("/api/priv/me", headers=_FORGED)
    assert r.json() == {"groups": [], "email": "eve@x.io"}


def test_a_tampered_session_cookie_gives_no_group(client):
    _sign_in(client, "ann@x.io")
    token = client.cookies.get("enlace_session")
    forged = token[:-2] + ("AA" if token[-2:] != "AA" else "BB")
    client.cookies.set("enlace_session", forged)
    assert client.get("/api/pub/me").json() == {"groups": [], "email": None}
    assert client.get("/api/priv/me").status_code == 401  # the gate still denies


def test_the_resolver_matches_the_gate_spelling():
    of = user_groups_resolver(GROUPS, (ADMIN,))
    assert of("ANN@X.IO") == {"editors"}
    assert of("") == of(None) == frozenset()
    assert user_groups_resolver({}, ())("ann@x.io") == frozenset()
    # an empty group (refused by the config, possible by hand) has no members
    assert user_groups_resolver({"e": []}, ())("@e") == frozenset()
