"""Tests for enlace_auth.diagnostics — auth-specific doctor checks plugged
into ``enlace.doctor.run_doctor`` via ``extra_static_checks`` /
``extra_http_checks``.
"""

from __future__ import annotations

import pytest
from enlace import doctor as doctor_mod
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps

from enlace_auth import diagnostics as auth_diag
from enlace_auth import plugin as auth_plugin
from enlace_auth.config import AuthConfig

_KEY_ENV = "ENLACE_TEST_SIGNING_KEY"
_GOOD_KEY = "x" * 48


@pytest.fixture
def clean_env(monkeypatch):
    for v in (_KEY_ENV, "ENLACE_ALLOW_UNSIGNED"):
        monkeypatch.delenv(v, raising=False)
    yield monkeypatch


def _auth_enabled_config(single_app_dir):
    cfg = PlatformConfig(
        apps_dir=single_app_dir,
        auth=AuthConfig(
            enabled=True, signing_key_env=_KEY_ENV, secure_cookies=False
        ).model_dump(),
    )
    return discover_apps(cfg)


def _doctor(cfg, *, base_url=None):
    return doctor_mod.run_doctor(
        cfg,
        base_url=base_url,
        extra_static_checks=auth_diag.static_checks,
        extra_http_checks=auth_diag.http_checks,
    )


def test_static_missing_signing_key_is_fail(clean_env, single_app_dir):
    """Static check catches the original incident regardless of HTTP probing."""
    cfg = _auth_enabled_config(single_app_dir)
    report = _doctor(cfg, base_url=None)
    sk = [c for c in report.checks if c.name == "signing_key"][0]
    assert sk.status == doctor_mod.FAIL
    assert _KEY_ENV in sk.detail
    assert not report.ok


def test_static_good_signing_key_passes(clean_env, single_app_dir):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)
    report = _doctor(cfg, base_url=None)
    sk = [c for c in report.checks if c.name == "signing_key"][0]
    assert sk.status == doctor_mod.PASS
    assert report.ok


def test_static_skip_when_auth_disabled(clean_env, single_app_dir):
    cfg = PlatformConfig(
        apps_dir=single_app_dir,
        auth=AuthConfig(enabled=False, signing_key_env=_KEY_ENV).model_dump(),
    )
    cfg = discover_apps(cfg)
    report = _doctor(cfg, base_url=None)
    sk = [c for c in report.checks if c.name == "signing_key"][0]
    assert sk.status == doctor_mod.SKIP
    assert report.ok


def test_report_format_text_renders(clean_env, single_app_dir):
    cfg = _auth_enabled_config(single_app_dir)
    report = _doctor(cfg, base_url=None)
    text = report.format_text()
    assert "enlace doctor" in text
    assert "signing_key" in text
    assert "Result:" in text


def test_report_as_dict_shape(clean_env, single_app_dir):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)
    report = _doctor(cfg, base_url=None)
    data = report.as_dict()
    assert "ok" in data and "summary" in data and "checks" in data
    assert isinstance(data["checks"], list)
    assert all({"name", "status", "detail"} <= c.keys() for c in data["checks"])


# ---------------------------------------------------------------------------
# HTTP probe checks — use a patched _http_get rather than a live server.
# ---------------------------------------------------------------------------


def _fake_http(map_: dict):
    """Build a fake _http_get returning canned responses keyed by URL."""

    def _get(url, *, timeout):  # noqa: ARG001
        resp = map_.get(url)
        if resp is None:
            return None, {}, None, f"unexpected URL in test: {url}"
        return resp  # (status, headers, body, error)

    return _get


def test_csrf_probe_catches_spa_fallthrough(clean_env, single_app_dir, monkeypatch):
    """The canonical regression: /auth/csrf returns the SPA's index.html."""
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)

    spa_html = b"<!doctype html><html><body>SPA</body></html>"
    monkeypatch.setattr(
        doctor_mod,
        "_http_get",
        _fake_http(
            {
                "http://x/auth/csrf": (
                    200,
                    {"content-type": "text/html"},
                    spa_html,
                    None,
                ),
                "http://x/foo/": (
                    200,
                    {"content-type": "text/html"},
                    b"<html/>",
                    None,
                ),
                "http://x/api/foo/": (
                    200,
                    {"content-type": "application/json"},
                    b"{}",
                    None,
                ),
            }
        ),
    )
    report = _doctor(cfg, base_url="http://x")
    csrf = [c for c in report.checks if c.name == "http:/auth/csrf"][0]
    assert csrf.status == doctor_mod.FAIL
    assert "auth silently disabled" in csrf.detail or "expected JSON" in csrf.detail
    assert not report.ok


def test_csrf_probe_accepts_valid_json(clean_env, single_app_dir, monkeypatch):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)

    monkeypatch.setattr(
        doctor_mod,
        "_http_get",
        _fake_http(
            {
                "http://x/auth/csrf": (
                    200,
                    {"content-type": "application/json"},
                    b'{"csrf": "abc123"}',
                    None,
                ),
                "http://x/api/foo/": (
                    200,
                    {"content-type": "application/json"},
                    b"{}",
                    None,
                ),
            }
        ),
    )
    report = _doctor(cfg, base_url="http://x")
    csrf = [c for c in report.checks if c.name == "http:/auth/csrf"][0]
    assert csrf.status == doctor_mod.PASS
    assert report.ok


def test_api_probe_fails_on_5xx(clean_env, single_app_dir, monkeypatch):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)

    monkeypatch.setattr(
        doctor_mod,
        "_http_get",
        _fake_http(
            {
                "http://x/auth/csrf": (
                    200,
                    {"content-type": "application/json"},
                    b'{"csrf": "ok"}',
                    None,
                ),
                "http://x/api/foo/": (503, {}, b"", None),
            }
        ),
    )
    report = _doctor(cfg, base_url="http://x")
    assert not report.ok
    api = [c for c in report.checks if c.name == "http:/api/foo/"][0]
    assert api.status == doctor_mod.FAIL


def test_live_gateway_roundtrip(clean_env, single_app_dir):
    """Smoke: with a good key, /auth/csrf returns JSON when the auth plugin is wired."""
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)
    app = build_backend(cfg, plugins=[auth_plugin])
    from starlette.testclient import TestClient

    client = TestClient(app)
    resp = client.get("/auth/csrf")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert "csrf" in resp.json()


# ---------------------------------------------------------------------- #
# Connector session longevity
#
# The checks that would have caught "the reelee connector has been down all
# day": an authorization server issuing access tokens nothing can renew.
# ---------------------------------------------------------------------- #


def _oauth_config(single_app_dir, **oauth_server):
    cfg = PlatformConfig(
        apps_dir=single_app_dir,
        auth=AuthConfig(
            enabled=True,
            signing_key_env=_KEY_ENV,
            secure_cookies=False,
            oauth_server={"enabled": True, **oauth_server},
        ).model_dump(),
    )
    return discover_apps(cfg)


def _check(cfg, name, **kw):
    (found,) = [c for c in _doctor(cfg, **kw).checks if c.name == name]
    return found


def test_refresh_disabled_is_a_doctor_failure(clean_env, single_app_dir):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _oauth_config(single_app_dir, refresh_token_ttl_seconds=0)
    check = _check(cfg, "oauth_refresh")
    assert check.status == doctor_mod.FAIL
    assert "refresh" in check.detail.lower()


def test_refresh_enabled_passes(clean_env, single_app_dir):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _oauth_config(single_app_dir, refresh_token_ttl_seconds=2592000)
    assert _check(cfg, "oauth_refresh").status == doctor_mod.PASS


def test_longevity_check_skips_when_oauth_server_is_off(clean_env, single_app_dir):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _auth_enabled_config(single_app_dir)
    assert _check(cfg, "oauth_refresh").status == doctor_mod.SKIP


def test_http_check_catches_a_deployed_build_older_than_its_config(
    clean_env, single_app_dir, monkeypatch
):
    """Config says refresh; the running server says otherwise. Config lies."""
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _oauth_config(single_app_dir, refresh_token_ttl_seconds=2592000)
    monkeypatch.setattr(
        doctor_mod,
        "_http_get",
        lambda url, timeout=None: (
            200,
            {"content-type": "application/json"},
            b'{"grant_types_supported": ["authorization_code"]}',
            None,
        ),
    )
    check = _check(
        cfg,
        "http:/.well-known/oauth-authorization-server",
        base_url="http://testserver",
    )
    assert check.status == doctor_mod.FAIL
    assert "older than the config" in check.detail


def test_http_check_passes_when_the_server_advertises_refresh(
    clean_env, single_app_dir, monkeypatch
):
    clean_env.setenv(_KEY_ENV, _GOOD_KEY)
    cfg = _oauth_config(single_app_dir, refresh_token_ttl_seconds=2592000)
    monkeypatch.setattr(
        doctor_mod,
        "_http_get",
        lambda url, timeout=None: (
            200,
            {"content-type": "application/json"},
            b'{"grant_types_supported": ["authorization_code", "refresh_token"]}',
            None,
        ),
    )
    check = _check(
        cfg,
        "http:/.well-known/oauth-authorization-server",
        base_url="http://testserver",
    )
    assert check.status == doctor_mod.PASS
