"""Fail-fast behavior when [auth].enabled and the signing key is unusable.

Covers the silent-degradation regression from i2mint/enlace#11: if the signing
key env var is missing, the gateway used to boot with /auth/* un-mounted. It
now refuses to start unless the operator sets ENLACE_ALLOW_UNSIGNED=1.

Since auth was extracted out of enlace, the fail-fast happens inside
``enlace_auth.plugin.wire`` and raises ``EnlaceAuthConfigError`` (not
``EnlaceConfigError``).
"""

from __future__ import annotations

import pytest

from enlace import build_backend
from enlace.base import PlatformConfig
from enlace.discover import discover_apps
from enlace_auth import EnlaceAuthConfigError
from enlace_auth import plugin as auth_plugin
from enlace_auth.config import AuthConfig

_KEY_ENV = "ENLACE_TEST_SIGNING_KEY"
_OPT_OUT = "ENLACE_ALLOW_UNSIGNED"
_GOOD_KEY = "x" * 48


@pytest.fixture
def auth_config():
    return AuthConfig(enabled=True, signing_key_env=_KEY_ENV, secure_cookies=False)


@pytest.fixture
def clean_env(monkeypatch):
    for var in (_KEY_ENV, _OPT_OUT):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


def _config_with_auth(single_app_dir, auth_cfg):
    cfg = PlatformConfig(apps_dir=single_app_dir, auth=auth_cfg.model_dump())
    return discover_apps(cfg)


def test_missing_signing_key_raises(clean_env, single_app_dir, auth_config):
    """No ENLACE_SIGNING_KEY + auth enabled → fail-fast at build time."""
    cfg = _config_with_auth(single_app_dir, auth_config)
    with pytest.raises(EnlaceAuthConfigError) as exc_info:
        build_backend(cfg, plugins=[auth_plugin])
    msg = str(exc_info.value)
    assert _KEY_ENV in msg


def test_empty_signing_key_raises(clean_env, single_app_dir, auth_config):
    clean_env.setenv(_KEY_ENV, "   ")
    cfg = _config_with_auth(single_app_dir, auth_config)
    with pytest.raises(EnlaceAuthConfigError):
        build_backend(cfg, plugins=[auth_plugin])


def test_short_signing_key_raises(clean_env, single_app_dir, auth_config):
    clean_env.setenv(_KEY_ENV, "too-short")
    cfg = _config_with_auth(single_app_dir, auth_config)
    with pytest.raises(EnlaceAuthConfigError) as exc_info:
        build_backend(cfg, plugins=[auth_plugin])
    assert "too short" in str(exc_info.value)


def test_opt_out_env_keeps_current_behavior(
    clean_env, single_app_dir, auth_config, caplog
):
    """ENLACE_ALLOW_UNSIGNED=1 suppresses the raise and logs a loud error."""
    clean_env.setenv(_OPT_OUT, "1")
    cfg = _config_with_auth(single_app_dir, auth_config)
    with caplog.at_level("ERROR", logger="enlace_auth"):
        app = build_backend(cfg, plugins=[auth_plugin])
    assert app is not None
    joined = "\n".join(r.message for r in caplog.records)
    assert "auth" in joined.lower()
    assert "disabled" in joined.lower() or "unsigned" in joined.lower()


def test_good_key_builds_normally(clean_env, single_app_dir, auth_config):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _config_with_auth(single_app_dir, auth_config)
    app = build_backend(cfg, plugins=[auth_plugin])
    from starlette.testclient import TestClient

    client = TestClient(app)
    resp = client.get("/auth/csrf")
    assert resp.status_code == 200
    assert "csrf" in resp.json()


def test_auth_disabled_is_unaffected_by_missing_key(clean_env, single_app_dir):
    """When [auth].enabled=False, missing key is fine — plugin is a no-op."""
    cfg = PlatformConfig(
        apps_dir=single_app_dir,
        auth=AuthConfig(enabled=False, signing_key_env=_KEY_ENV).model_dump(),
    )
    cfg = discover_apps(cfg)
    app = build_backend(cfg, plugins=[auth_plugin])
    assert app is not None
