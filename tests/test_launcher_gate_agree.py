"""The gate and the ``/_apps`` launcher agree on who may reach an app (enlace #35).

A runtime grant used to let a user OPEN a ``protected:user`` app without ever
SEEING it in the launcher: the gate unioned static ``allowed_users`` with live
grants, the launcher read only the static list. Both now call enlace core's
``enlace.access.is_user_allowed``, fed by the one grants resolver this plugin
builds.

These tests run the real gate and the real launcher side by side, so they fail
if either side changes alone. They assert the equivalence — opens ⟺ listed —
for static-only, grant-only, both and neither, and not merely "a granted user
sees the app", which a launcher hard-wired to ``True`` would pass.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth import GrantStore
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import _SIGNING_KEY, _csrf, _register

STATIC = "static@example.com"
GRANTED = "granted@example.com"
BOTH = "both@example.com"
NEITHER = "neither@example.com"


def _platform(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    (apps_dir / "ping").mkdir(parents=True)
    (apps_dir / "ping" / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/ping')\ndef ping():\n    return {'ok': True}\n"
    )
    (apps_dir / "gated").mkdir()
    (apps_dir / "gated" / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/x')\ndef x():\n    return {'ok': True}\n"
    )
    (apps_dir / "gated" / "app.toml").write_text(
        f'access = "protected:user"\nallowed_users = ["{STATIC}", "{BOTH}"]\n'
    )
    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    platform_store = tmp_path / "platform"
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(platform_store)},
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "data")}},
    )
    backend = build_backend(discover_apps(config), plugins=[auth_plugin])
    grants = GrantStore(
        make_file_store_factory(str(platform_store))("grants"),
        root=Path(platform_store) / "grants",
    )
    return backend, grants


def _signed_in(backend, email):
    client = TestClient(backend)
    assert _register(client, email, "password-123", _csrf(client)).status_code == 200
    return client


def _opens(client) -> bool:
    status = client.get("/api/gated/x").status_code
    assert status in (200, 401), status
    return status == 200


def _listed(client) -> bool:
    return "gated" in {a["name"] for a in client.get("/_apps").json()["apps"]}


@pytest.mark.parametrize(
    "email, expected",
    [(STATIC, True), (GRANTED, True), (BOTH, True), (NEITHER, False)],
)
def test_opens_iff_listed(tmp_path, monkeypatch, email, expected):
    """For each kind of user, the launcher and the gate return the same verdict."""
    backend, grants = _platform(tmp_path, monkeypatch)
    grants.grant("gated", GRANTED)
    grants.grant("gated", BOTH)
    client = _signed_in(backend, email)
    assert _opens(client) is _listed(client) is expected


def test_anonymous_neither_opens_nor_sees(tmp_path, monkeypatch):
    backend, _ = _platform(tmp_path, monkeypatch)
    client = TestClient(backend)
    assert _opens(client) is _listed(client) is False


def test_grant_and_expiry_reach_both_sides_without_restart(tmp_path, monkeypatch):
    """Granted at runtime → opens AND listed; expired → neither. No restart."""
    backend, grants = _platform(tmp_path, monkeypatch)
    client = _signed_in(backend, GRANTED)
    assert _opens(client) is _listed(client) is False

    grants.grant("gated", GRANTED, expires_at=time.time() + 3600)
    assert _opens(client) is _listed(client) is True

    grants.grant("gated", GRANTED, expires_at=time.time() - 1)
    assert _opens(client) is _listed(client) is False
