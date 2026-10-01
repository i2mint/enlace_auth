"""Owner-granted data shares (ADR 0001): the store, the routes, and the per-user store honouring them."""

from __future__ import annotations

import textwrap
import time

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from fastapi import FastAPI
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth import ShareError, ShareStore, hash_password
from enlace_auth.auth.cookies import verify_cookie
from enlace_auth.stores import make_store_router
from enlace_auth.stores.backends import make_file_store_factory
from enlace_auth.stores.prefixed import PrefixedStore

KEY = "shares-key-32bytes-minimumlength!"
KID, MUM, DAD, STRANGER = (
    "kid@example.com",
    "mum@example.com",
    "dad@example.com",
    "x@example.com",
)


# --- ShareStore -------------------------------------------------------------------


def _store(accounts=(KID, MUM, DAD)):
    return ShareStore({}, account_exists=set(accounts).__contains__)


def test_share_names_existing_accounts_only():
    shares = _store()
    with pytest.raises(ShareError, match="No account"):
        shares.share("practice", KID, STRANGER)
    with pytest.raises(ShareError, match="No account"):
        shares.share("practice", STRANGER, KID)
    with pytest.raises(ShareError, match="themselves"):
        shares.share("practice", KID, KID)
    with pytest.raises(ShareError, match="access"):
        shares.share("practice", KID, MUM, access="admin")


def test_access_levels_expiry_and_normalisation():
    shares = _store()
    shares.share("practice", "Kid@Example.com", MUM)
    shares.share("practice", KID, DAD, access="ro", label="Kid")
    assert shares.access("practice", KID, MUM) == "rw"
    assert shares.access("practice", KID, DAD) == "ro"
    assert shares.access("practice", MUM, KID) is None, "a share is one-way"
    assert shares.access("other", KID, MUM) is None, "a share is per app"
    now = time.time()
    shares.share("practice", KID, MUM, expires_at=now + 10)
    assert shares.access("practice", KID, MUM, now=now + 20) is None
    assert [r["grantee"] for r in shares.received("practice", MUM, now=now + 20)] == []
    granted = {
        r["grantee"]: r["active"] for r in shares.granted("practice", KID, now=now + 20)
    }
    assert granted == {MUM: False, DAD: True}
    assert shares.received("practice", DAD)[0]["label"] == "Kid"


def test_remove_account_deletes_both_directions():
    shares = _store()
    shares.share("practice", KID, MUM)
    shares.share("practice", KID, DAD)
    shares.share("practice", MUM, DAD)
    assert shares.remove_account(MUM) == 2
    assert {(r["owner"], r["grantee"]) for r in shares.list_all()} == {(KID, DAD)}


def test_file_backend_lists_one_app_by_directory(tmp_path):
    factory = make_file_store_factory(str(tmp_path))
    shares = ShareStore(factory("shares"), root=tmp_path / "shares")
    shares.share("practice", KID, MUM)
    shares.share("other", KID, DAD)
    assert [r["grantee"] for r in shares.received("practice", MUM)] == [MUM]
    assert shares.received("practice", DAD) == []


# --- the store router -----------------------------------------------------------


def _router_client(base, shares, *, user):
    app = FastAPI()

    @app.middleware("http")
    async def _fake_auth(request, call_next):
        request.state.user_id = user
        return await call_next(request)

    app.include_router(
        make_store_router(
            base_store_getter=lambda: base,
            protected_apps={"practice"},
            share_access=shares.access,
        )
    )
    return TestClient(app)


def test_owner_param_needs_an_active_share():
    base, shares = {}, _store()
    base[f"{KID}/practice/attempts/a1"] = {"id": "a1"}
    shares.share("practice", KID, MUM)
    shares.share("practice", KID, DAD, access="ro")

    mum = _router_client(base, shares, user=MUM)
    assert mum.get(f"/api/practice/store/attempts/a1?owner={KID}").json()["value"] == {
        "id": "a1"
    }
    assert (
        mum.put(
            f"/api/practice/store/attempts/a2?owner={KID}", json={"value": {"id": "a2"}}
        ).status_code
        == 200
    )
    assert base[f"{KID}/practice/attempts/a2"] == {"id": "a2"}, (
        "written into the owner's data"
    )

    dad = _router_client(base, shares, user=DAD)
    assert dad.get(f"/api/practice/store/attempts/a1?owner={KID}").status_code == 200
    assert (
        dad.put(
            f"/api/practice/store/attempts/a3?owner={KID}", json={"value": 1}
        ).status_code
        == 404
    ), "ro: no writes"
    assert dad.delete(f"/api/practice/store/attempts/a1?owner={KID}").status_code == 404

    stranger = _router_client(base, shares, user=STRANGER)
    assert (
        stranger.get(f"/api/practice/store/attempts/a1?owner={KID}").status_code == 404
    )
    assert stranger.get(f"/api/practice/store?owner={KID}").status_code == 404
    # Own data is still the default, and ?owner= naming oneself is the same thing.
    assert mum.get("/api/practice/store/attempts/a1").status_code == 404
    assert (
        mum.put(
            f"/api/practice/store/x?owner={MUM.upper()}", json={"value": 1}
        ).status_code
        == 200
    )
    assert base[f"{MUM}/practice/x"] == 1

    shares.revoke("practice", KID, MUM)
    assert mum.get(f"/api/practice/store/attempts/a1?owner={KID}").status_code == 404, (
        "revocation is immediate"
    )


def test_list_route_and_conditional_writes():
    base, shares = {}, _store()
    me = _router_client(base, shares, user=KID)
    first = me.put("/api/practice/store/attempts/a1", json={"value": {"rev": 1}})
    etag = first.headers["etag"]
    me.put("/api/practice/store/attempts/a2", json={"value": {"rev": 1}})
    me.put("/api/practice/store/marks/removed", json={"value": []})

    listed = me.get("/api/practice/store?prefix=attempts/").json()
    assert (
        set(listed["items"]) == {"attempts/a1", "attempts/a2"}
        and not listed["truncated"]
    )
    assert listed["items"]["attempts/a1"] == {"value": {"rev": 1}, "etag": etag}
    assert me.get("/api/practice/store/attempts/a1").headers["etag"] == etag

    # A writer holding the current etag wins; a stale one gets 412 with what is there now.
    second = me.put(
        "/api/practice/store/attempts/a1",
        json={"value": {"rev": 2}},
        headers={"If-Match": etag},
    )
    assert second.status_code == 200
    stale = me.put(
        "/api/practice/store/attempts/a1",
        json={"value": {"rev": 3}},
        headers={"If-Match": etag},
    )
    assert stale.status_code == 412
    assert stale.json()["detail"] == {
        "value": {"rev": 2},
        "etag": second.headers["etag"],
    }
    assert base[f"{KID}/practice/attempts/a1"] == {"rev": 2}
    # Create-only.
    assert (
        me.put(
            "/api/practice/store/attempts/a1",
            json={"value": 0},
            headers={"If-None-Match": "*"},
        ).status_code
        == 412
    )
    assert (
        me.put(
            "/api/practice/store/attempts/a9",
            json={"value": 0},
            headers={"If-None-Match": "*"},
        ).status_code
        == 200
    )
    assert (
        me.delete(
            "/api/practice/store/attempts/a9", headers={"If-Match": etag}
        ).status_code
        == 412
    )
    assert me.delete("/api/practice/store/attempts/a9").status_code == 200


def test_list_is_capped():
    base, shares = {f"{KID}/practice/k{i}": i for i in range(5)}, _store()
    app = FastAPI()

    @app.middleware("http")
    async def _fake_auth(request, call_next):
        request.state.user_id = KID
        return await call_next(request)

    app.include_router(
        make_store_router(
            base_store_getter=lambda: base, protected_apps={"practice"}, max_items=3
        )
    )
    body = TestClient(app).get("/api/practice/store").json()
    assert len(body["items"]) == 3 and body["truncated"]


def test_prefixed_keys_under_walks_only_the_owner(tmp_path):
    base = make_file_store_factory(str(tmp_path))("user_data")
    base[f"{KID}/practice/attempts/a1"] = 1
    base[f"{MUM}/practice/attempts/b1"] = 2
    store = PrefixedStore(base, f"{KID}/practice/")
    assert list(store.keys_under("attempts/")) == ["attempts/a1"]
    assert list(base.keys_under(f"{KID}/practice/att")) == [
        f"{KID}/practice/attempts/a1"
    ]


# --- end to end: a PUBLIC app with user_store = true ---------------------------------


@pytest.fixture
def platform(tmp_path, monkeypatch):
    apps_dir = tmp_path / "apps"
    (apps_dir / "practice").mkdir(parents=True)
    (apps_dir / "practice" / "server.py").write_text(
        textwrap.dedent(
            """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/ping")
            def ping():
                return {"ok": True}
            """
        ).strip()
    )
    (apps_dir / "practice" / "app.toml").write_text(
        'access = "public"\nuser_store = true\n'
    )
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    monkeypatch.setenv("ENLACE_ADMIN_EMAILS", DAD)
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform_store")},
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "user_data")}},
    )
    return build_backend(discover_apps(config), plugins=[auth_plugin])


def _signed_in(app, email):
    client = TestClient(app)
    client.get("/api/practice/ping")
    raw = verify_cookie(client.cookies.get("enlace_csrf"), KEY, salt="csrf")
    client.headers["X-CSRF-Token"] = raw
    r = client.post("/auth/register", json={"email": email, "password": "secretpw123"})
    assert r.status_code == 200, r.text
    return client


def test_public_app_store_shares_and_csrf(platform):
    anonymous = TestClient(platform)
    assert anonymous.get("/api/practice/ping").status_code == 200, (
        "the app stays public"
    )
    assert anonymous.get("/api/practice/store?prefix=attempts/").status_code == 401

    kid, mum = _signed_in(platform, KID), _signed_in(platform, MUM)
    assert (
        kid.put(
            "/api/practice/store/attempts/a1", json={"value": {"id": "a1"}}
        ).status_code
        == 200
    )

    # CSRF is enforced on store writes even though /api/ is otherwise exempt.
    bare = kid.put(
        "/api/practice/store/attempts/a2",
        json={"value": 1},
        headers={"X-CSRF-Token": ""},
    )
    assert bare.status_code == 403

    # No share yet: Mum sees nothing of the kid's, and cannot share to a stranger.
    assert (
        mum.get(f"/api/practice/store?prefix=attempts/&owner={KID}").status_code == 404
    )
    assert kid.put(f"/auth/shares/practice/{STRANGER}", json={}).status_code == 409
    assert kid.put(f"/auth/shares/nostore/{MUM}", json={}).status_code == 404

    r = kid.put(f"/auth/shares/practice/{MUM}", json={"label": "Kid"})
    assert r.status_code == 200, r.text
    received = mum.get("/auth/shares/practice").json()["received"]
    assert [(s["owner"], s["label"]) for s in received] == [(KID, "Kid")]
    items = mum.get(f"/api/practice/store?prefix=attempts/&owner={KID}").json()["items"]
    assert list(items) == ["attempts/a1"]

    # Mum leaves; the route for "received" is not mistaken for a grantee.
    assert mum.delete(f"/auth/shares/practice/received/{KID}").status_code == 200
    assert kid.get("/auth/shares/practice").json()["granted"] == []


def test_deleting_an_account_removes_its_shares(platform):
    kid, mum, dad = (
        _signed_in(platform, KID),
        _signed_in(platform, MUM),
        _signed_in(platform, DAD),
    )
    # Dad is the admin: he seeds the kid's share without her password.
    r = dad.post(
        "/_admin/api/shares", json={"app_id": "practice", "owner": KID, "grantee": MUM}
    )
    assert r.status_code == 200, r.text
    assert len(dad.get("/_admin/api/shares").json()["shares"]) == 1
    assert dad.delete(f"/_admin/api/users/{MUM}").status_code == 200
    assert dad.get("/_admin/api/shares").json()["shares"] == []
    _ = kid, mum


# --- review fixes -------------------------------------------------------------------


def test_unsafe_values_never_break_a_collection():
    base, shares = {}, _store()
    me = _router_client(base, shares, user=KID)
    me.put("/api/practice/store/a", json={"value": {"t": "fine"}})
    # A lone surrogate (a browser can send one) is refused, so the collection stays readable.
    lone = me.put(
        "/api/practice/store/z",
        content=b'{"value": {"t": "\\ud800"}}',
        headers={"Content-Type": "application/json"},
    )
    assert lone.status_code == 400, lone.text
    assert me.get("/api/practice/store").status_code == 200
    assert me.get("/api/practice/store/").json()["items"].keys() == {"a"}, (
        "the trailing slash lists too"
    )
    # Non-finite numbers are refused before anything is written.
    nan = me.put(
        "/api/practice/store/b",
        content=b'{"value": NaN}',
        headers={"Content-Type": "application/json"},
    )
    assert nan.status_code == 400 and "b" not in {k.split("/")[-1] for k in base}


def test_404_details_tell_no_access_from_no_key():
    base, shares = {}, _store()
    shares.share("practice", KID, MUM)
    mum = _router_client(base, shares, user=MUM)
    assert mum.get(f"/api/practice/store/nope?owner={KID}").json()["detail"] == "no_key"
    assert (
        mum.get(f"/api/practice/store/nope?owner={DAD}").json()["detail"] == "no_access"
    )


def test_label_is_capped_and_trimmed():
    shares = _store()
    assert shares.share("practice", KID, MUM, label="  Kid ")["label"] == "Kid"
    assert shares.share("practice", KID, DAD, label="   ")["label"] is None
    with pytest.raises(ShareError, match="label"):
        shares.share("practice", KID, MUM, label="x" * 81)
    with pytest.raises(ShareError) as missing:
        shares.share("practice", KID, STRANGER)
    assert missing.value.code == "no_account"
