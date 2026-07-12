"""Tests for the editable app-metadata overlay (PATCH/DELETE /_apps/{name}/meta).

Sets up a full enlace gateway with the auth plugin and an editor allowlist, then
exercises the overlay endpoints end-to-end: editor authz, CSRF, additive keyword
edits, scalar overrides + clears, empty-record deletion, and that the resolved
``/_apps`` listing reflects the overlay. Also unit-tests the pure patch logic.
"""

from __future__ import annotations

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.appmeta import _apply_patch, _MetaPatchBody, make_appmeta_can_edit

_SIGNING_KEY = "appmeta-test-key-thirtytwobyteslong!"


# ---------------------------------------------------------------------------
# Pure unit tests: can-edit + patch logic
# ---------------------------------------------------------------------------


def test_can_edit_normalizes_and_fails_closed():
    can = make_appmeta_can_edit(("Boss@Example.com",))
    assert can("boss@example.com") is True
    assert can("BOSS@example.com ".strip()) is True
    assert can("other@example.com") is False
    assert can(None) is False
    # empty editor set ⇒ nobody can edit
    assert make_appmeta_can_edit(())("boss@example.com") is False


def test_apply_patch_adds_and_removes_keywords():
    body = _MetaPatchBody(add_keywords=["Music", "music", "chords"])
    rec = _apply_patch({}, body)
    assert rec["keywords"] == ["Music", "chords"]  # casefold-deduped
    rec2 = _apply_patch(rec, _MetaPatchBody(remove_keywords=["chords"]))
    assert rec2["keywords"] == ["Music"]


def test_apply_patch_scalar_set_and_clear():
    rec = _apply_patch({}, _MetaPatchBody(icon="emoji:🎸", display_name="Cool"))
    assert rec["icon"] == "emoji:🎸"
    assert rec["display_name"] == "Cool"
    # explicit null clears; omitted leaves as-is
    rec2 = _apply_patch(rec, _MetaPatchBody(icon=None))
    assert "icon" not in rec2
    assert rec2["display_name"] == "Cool"


def test_apply_patch_empty_record_is_falsy():
    assert _apply_patch({}, _MetaPatchBody()) == {}
    # removing the last keyword empties the record
    rec = _apply_patch({}, _MetaPatchBody(add_keywords=["only"]))
    assert _apply_patch(rec, _MetaPatchBody(remove_keywords=["only"])) == {}


# ---------------------------------------------------------------------------
# Integration: full gateway with the plugin
# ---------------------------------------------------------------------------


def _write_public_app(apps_dir, name="widget"):
    app = apps_dir / name
    app.mkdir()
    (app / "server.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/ping')\ndef ping():\n    return {'ok': True}\n"
    )
    (app / "app.toml").write_text(
        'access = "public"\ndisplay_name = "Widget"\nkeywords = ["base"]\n'
    )


@pytest.fixture
def gw(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    _write_public_app(apps_dir)

    monkeypatch.setenv("ENLACE_SIGNING_KEY", _SIGNING_KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", "boss@example.com")

    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
        # editors falls back to ENLACE_ADMIN_EMAILS (no [app_meta] editors set)
    )
    config = discover_apps(config)
    app = build_backend(config, plugins=[auth_plugin])
    return TestClient(app)


def _csrf(client):
    client.get("/api/widget/ping")
    from enlace_auth.auth.cookies import verify_cookie

    raw = verify_cookie(client.cookies.get("enlace_csrf"), _SIGNING_KEY, salt="csrf")
    return {"X-CSRF-Token": raw}


def _register(client, email, password, csrf):
    return client.post(
        "/auth/register", json={"email": email, "password": password}, headers=csrf
    )


def test_anonymous_cannot_edit(gw):
    csrf = _csrf(gw)
    r = gw.patch("/_apps/widget/meta", json={"add_keywords": ["x"]}, headers=csrf)
    assert r.status_code == 403


def test_non_editor_cannot_edit(gw):
    csrf = _csrf(gw)
    _register(gw, "alice@example.com", "secretpw1", csrf)  # logs alice in
    r = gw.patch("/_apps/widget/meta", json={"add_keywords": ["x"]}, headers=csrf)
    assert r.status_code == 403


def test_patch_requires_csrf(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)  # admin -> editor
    # missing X-CSRF-Token header ⇒ blocked by CSRF middleware (not 200)
    r = gw.patch("/_apps/widget/meta", json={"add_keywords": ["x"]})
    assert r.status_code == 403


def test_editor_adds_keywords_and_listing_reflects_it(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    r = gw.patch(
        "/_apps/widget/meta", json={"add_keywords": ["Extra", "tag"]}, headers=csrf
    )
    assert r.status_code == 200, r.text
    item = r.json()
    assert item["keyword_sources"]["app"] == ["base"]
    assert item["keyword_sources"]["overlay"] == ["Extra", "tag"]
    assert item["keywords"] == ["base", "Extra", "tag"]

    # the /_apps listing reflects the overlay too
    listing = gw.get("/_apps").json()
    widget = next(a for a in listing["apps"] if a["name"] == "widget")
    assert widget["keywords"] == ["base", "Extra", "tag"]
    assert listing["can_edit_meta"] is True


def test_overlay_icon_override_serves_via_icon_endpoint(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    gw.patch("/_apps/widget/meta", json={"icon": "emoji:⭐"}, headers=csrf)
    r = gw.get("/_apps/widget/icon")
    assert r.status_code == 200
    assert "⭐" in r.content.decode("utf-8")


def test_delete_clears_overlay(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    gw.patch("/_apps/widget/meta", json={"add_keywords": ["temp"]}, headers=csrf)
    r = gw.delete("/_apps/widget/meta", headers=csrf)
    assert r.status_code == 200
    assert r.json()["keyword_sources"]["overlay"] == []
    widget = next(a for a in gw.get("/_apps").json()["apps"] if a["name"] == "widget")
    assert widget["keywords"] == ["base"]


def test_unknown_app_404(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    r = gw.patch("/_apps/nope/meta", json={"add_keywords": ["x"]}, headers=csrf)
    assert r.status_code == 404


def test_remove_keyword_persists_across_requests(gw):
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    gw.patch("/_apps/widget/meta", json={"add_keywords": ["a", "b"]}, headers=csrf)
    gw.patch("/_apps/widget/meta", json={"remove_keywords": ["a"]}, headers=csrf)
    widget = next(a for a in gw.get("/_apps").json()["apps"] if a["name"] == "widget")
    assert widget["keyword_sources"]["overlay"] == ["b"]


def test_patch_item_shape_matches_listing_item(gw):
    """The PATCH/DELETE response item has the IDENTICAL key set as a /_apps item.

    Both are built by enlace.compose.build_launcher_item — this pins that SSOT so
    the frontend can drop a PATCH response straight into the store, and App.parse
    (which validates it with the same zod schema as the listing) can't drift.
    """
    csrf = _csrf(gw)
    _register(gw, "boss@example.com", "bosspw1!", csrf)
    listing_item = next(
        a for a in gw.get("/_apps").json()["apps"] if a["name"] == "widget"
    )
    patched = gw.patch(
        "/_apps/widget/meta", json={"add_keywords": ["z"]}, headers=csrf
    ).json()
    assert set(patched.keys()) == set(listing_item.keys())
