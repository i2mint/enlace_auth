"""Handles (usernames): the registry's rules, its races, and the platform surface.

The email is the account's private key; the handle is what others see. So beside
the rules, every route test also checks that no email comes back.
"""

from __future__ import annotations

import textwrap
import threading

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.handles import (
    HandleError,
    HandleRegistry,
    file_lock,
    handle_problem,
    normalize,
)
from enlace_auth.stores import make_file_store_factory
from tests.test_admin import _seed_account

DAY = 86400.0


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _registry(clock=None, **kw) -> HandleRegistry:
    return HandleRegistry(
        {}, {}, account_exists=lambda a: True, clock=clock or Clock(), **kw
    )


# ----------------------------------------------------------------- the rules


@pytest.mark.parametrize(
    "typed, stored",
    [
        ("ThorWhalen", "thorwhalen"),
        ("@ann", "ann"),
        ("ｊｏｅ", "joe"),
        (" a.b ", "a.b"),
    ],
)
def test_input_is_normalised_before_it_is_judged(typed, stored):
    assert normalize(typed) == stored


@pytest.mark.parametrize(
    "handle", ["аdmin", "jоe", "thor whalen", "_ann", "ann.", "a..b", "1234", "ab"]
)
def test_invalid_handles_are_refused(handle):
    # The first two hold a Cyrillic letter: ASCII-only removes confusables outright.
    assert handle_problem(normalize(handle)) is not None


def test_default_is_the_local_part_then_numbered_suffixes():
    reg = _registry()
    got = [reg.ensure(f"sam@example{i}.com")["handle"] for i in range(12)]
    assert got == ["sam"] + [f"sam{i}" for i in range(1, 12)]
    assert all(not reg.record_of(f"sam@example{i}.com")["chosen"] for i in range(12))


def test_lookalikes_cannot_pose_as_a_name():
    reg = _registry()
    reg.claim("thor@example.com", "thorwhalen")
    for fake in ("th0rwhalen", "thor.whalen", "Thor-Whalen"):
        assert reg.check(fake)["code"] == "taken"


def test_separators_do_not_make_a_new_name():
    reg = _registry()
    reg.claim("john.smith@example.com", "john.smith")
    assert reg.ensure("johnsmith@example.org")["handle"] == "johnsmith1"
    check = reg.check("john_smith")
    assert check["code"] == "taken" and check["suggestions"]


def test_plus_tag_and_accents_never_reach_the_handle():
    reg = _registry()
    assert reg.ensure("José+shop@example.com")["handle"] == "jose"


def test_reserved_and_group_names_are_refused_unless_forced():
    reg = _registry(policy=_registry().policy.with_reserved(["family"]))
    for name in ("admin", "Family", "no.reply"):
        with pytest.raises(HandleError) as e:
            reg.claim("a@example.com", name)
        assert e.value.code == "reserved"
    assert reg.claim("a@example.com", "family", force=True)["handle"] == "family"


# ------------------------------------------------------- choice and renames


def test_first_choice_is_free_then_renames_wait_for_the_cooldown():
    clock = Clock()
    reg = _registry(clock)
    reg.ensure("ann@example.com")
    assert reg.claim("ann@example.com", "AnnPlays") == {
        "handle": "annplays",
        "chosen": True,
    }
    with pytest.raises(HandleError) as e:
        reg.claim("ann@example.com", "annsings")
    assert e.value.code == "cooldown"
    clock.t += 31 * DAY
    assert reg.claim("ann@example.com", "annsings")["handle"] == "annsings"


def test_confirming_the_default_keeps_it_and_marks_it_chosen():
    reg = _registry()
    reg.ensure("ann@example.com")
    assert reg.claim("ann@example.com", "ANN") == {"handle": "ann", "chosen": True}


def test_a_renamed_name_redirects_and_is_held_for_its_quarantine():
    clock = Clock()
    reg = _registry(clock)
    reg.claim("ann@example.com", "first")
    clock.t += 31 * DAY
    reg.claim("ann@example.com", "second")
    assert reg.resolve("first") == {"handle": "second", "renamed_from": "first"}
    assert reg.account_of("first") is None
    with pytest.raises(HandleError) as e:
        reg.claim("bob@example.com", "first")
    assert e.value.code == "taken"
    clock.t += 91 * DAY
    assert reg.resolve("first") is None
    assert reg.claim("bob@example.com", "first")["handle"] == "first"


def test_deleting_an_account_erases_its_email_and_holds_its_name():
    clock = Clock()
    reg = _registry(clock)
    reg.claim("ann@example.com", "annplays")
    assert reg.release_account("ann@example.com") == 1
    assert "ann@example.com" not in reg.owners
    assert all(e.get("account") is None for e in reg.handles.values())
    assert reg.resolve("annplays") is None
    assert not reg.is_free("annplays")
    clock.t += 91 * DAY
    assert reg.is_free("annplays")
    assert reg.sweep() == 1


def test_unknown_accounts_get_no_handle():
    reg = HandleRegistry({}, {}, account_exists=lambda a: a == "real@example.com")
    assert reg.ensure("ghost@example.com", missing_ok=True) is None
    with pytest.raises(HandleError):
        reg.claim("ghost@example.com", "ghost")
    assert reg.ensure("real@example.com")["handle"] == "real"
    assert list(reg.owners) == ["real@example.com"]


def test_an_unconfirmed_default_is_private_and_gives_way():
    reg = _registry()
    reg.ensure("ann@example.com")
    assert reg.handle_of("ann@example.com") is None
    assert reg.account_of("ann") is None and reg.resolve("ann") is None
    assert reg.check("ann")["available"]  # the check does not reveal it either
    assert reg.claim("bob@example.com", "ann")["handle"] == "ann"
    assert reg.record_of("ann@example.com") == {"handle": "ann1", "chosen": False}
    assert reg.account_of("ann") == "bob@example.com"


# ------------------------------------------------------------------- races


def test_concurrent_defaults_never_share_a_name(tmp_path):
    factory = make_file_store_factory(str(tmp_path))
    lock = file_lock(tmp_path / "handles.lock")

    def registry():  # one per thread, like one per worker process
        return HandleRegistry(
            factory("handles"),
            factory("handle_owners"),
            lock=lock,
            account_exists=lambda a: True,
        )

    accounts = [f"kim@example{i}.com" for i in range(16)]
    got = {}
    barrier = threading.Barrier(len(accounts))

    def assign(account):
        reg = registry()
        barrier.wait()
        got[account] = reg.ensure(account)["handle"]

    threads = [threading.Thread(target=assign, args=(a,)) for a in accounts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(got.values())) == len(accounts)
    reg = registry()
    assert {a: reg.record_of(a)["handle"] for a in accounts} == got


def test_an_interrupted_rename_leaves_a_stale_entry_that_reads_as_free():
    reg = _registry()
    reg.claim("ann@example.com", "annplays")
    # a write of handles[] that never reached owners[] (a crash in between)
    reg.handles["ghost"] = {"handle": "ghost", "account": "ann@example.com"}
    assert reg.account_of("ghost") is None
    assert reg.claim("bob@example.com", "ghost")["handle"] == "ghost"


# ------------------------------------------------------- the platform surface

KEY = "handles-test-key-32bytes-minimum!!"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI, Request
    app = FastAPI()
    @app.get("/by")
    def by(owner: str, request: Request):
        return {"handle": request.state.handles.handle_of(owner)}
    @app.get("/mine")
    def mine(request: Request):
        return {"handle": request.state.handles.handle_of(request.state.user_id)}
    """
).strip()


@pytest.fixture
def platform(tmp_path, monkeypatch):
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    apps = tmp_path / "apps"
    (apps / "market").mkdir(parents=True)
    (apps / "market" / "server.py").write_text(_SERVER)
    (apps / "market" / "app.toml").write_text('access = "protected:user"\n')
    root = tmp_path / "platform"
    for email in ("ann@example.com", "ann@example.org", "bob@example.com"):
        _seed_account(root, email, "a-long-enough-password")

    def make(**handles) -> TestClient:
        config = PlatformConfig(
            apps_dir=apps,
            auth={
                "enabled": True,
                "secure_cookies": False,
                "stores": {"backend": "file", "path": str(root)},
                "groups": {"family": ["bob@example.com"]},
                "handles": handles,
            },
            stores={"user_data": {"backend": "file", "path": str(tmp_path / "ud")}},
        )
        return TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))

    return make


def _sign_in(client, email):
    csrf = {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf"]}
    r = client.post(
        "/auth/login",
        json={"email": email, "password": "a-long-enough-password"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf"]}


def _no_email(response):
    assert "@example." not in response.text, response.text


def test_routes_need_a_signed_in_account(platform):
    client = platform()
    for path in (
        "/auth/handles/me",
        "/auth/handles/check?handle=x",
        "/auth/handles/ann",
    ):
        assert client.get(path).status_code == 401


def test_first_run_flow_over_http(platform):
    client = platform()
    csrf = _sign_in(client, "ann@example.com")
    me = client.get("/auth/handles/me")
    assert me.json() == {"handle": "ann", "chosen": False}
    _no_email(me)

    check = client.get("/auth/handles/check", params={"handle": "Family"})
    assert check.json()["code"] == "reserved"  # an [auth.groups] name
    check = client.get("/auth/handles/check", params={"handle": "Ann.Plays"})
    assert check.json()["available"] and check.json()["handle"] == "ann.plays"

    assert (
        client.post("/auth/handles/me", json={"handle": "annplays"}).status_code == 403
    )
    r = client.post("/auth/handles/me", json={"handle": "annplays"}, headers=csrf)
    assert r.json() == {"handle": "annplays", "chosen": True}
    _no_email(r)

    other = platform()
    csrf2 = _sign_in(other, "ann@example.org")
    r = other.post("/auth/handles/me", json={"handle": "ann_plays"}, headers=csrf2)
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "taken" and r.json()["detail"]["suggestions"]
    _no_email(r)
    found = other.get("/auth/handles/AnnPlays")
    assert found.json() == {"handle": "annplays"}
    _no_email(found)
    assert other.get("/auth/handles/nobody-here").status_code == 404


def test_apps_read_handles_from_request_state(platform):
    client = platform()
    csrf = _sign_in(client, "bob@example.com")
    assert client.get("/api/market/mine").json() == {"handle": None}  # not chosen yet
    client.post("/auth/handles/me", json={"handle": "bob"}, headers=csrf)
    assert client.get("/api/market/mine").json() == {"handle": "bob"}
    by = client.get("/api/market/by", params={"owner": "ann@example.com"})
    assert by.json() == {"handle": None}
    ghost = client.get("/api/market/by", params={"owner": "ghost@example.com"})
    assert ghost.json() == {"handle": None}


def test_the_check_is_rate_limited(platform):
    client = platform(check_per_minute=3)
    _sign_in(client, "bob@example.com")
    codes = [
        client.get("/auth/handles/check", params={"handle": f"bob{i}"}).status_code
        for i in range(4)
    ]
    assert codes == [200, 200, 200, 429]


def test_disabled_handles_mount_nothing(platform):
    client = platform(enabled=False)
    _sign_in(client, "bob@example.com")
    assert client.get("/auth/handles/me").status_code == 404
