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
    got = []
    for i in range(12):  # each one published before the next account arrives
        account = f"sam@example{i}.com"
        assert reg.record_of(account) is None
        default = reg.ensure(account)
        assert default["chosen"] is False
        got.append(reg.claim(account, default["handle"])["handle"])
    assert got == ["sam"] + [f"sam{i}" for i in range(1, 12)]


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
    # ann's default moves on when next read, and confirming the old one is refused
    with pytest.raises(HandleError) as e:
        reg.claim("ann@example.com", "ann")
    assert e.value.code == "taken" and e.value.suggestions
    assert reg.ensure("ann@example.com") == {"handle": "ann1", "chosen": False}
    assert reg.account_of("ann") == "bob@example.com"


def test_another_accounts_private_default_tells_nothing():
    # Review finding: avoiding others' private defaults leaked their local parts.
    reg = _registry()
    reg.ensure("jsmith@example.com")  # the victim, never confirmed
    assert reg.ensure("jsm1th@example.org")["handle"] == "jsm1th"  # same key, no hint
    reg2 = _registry()
    assert reg2.ensure("jsm1th@example.org")["handle"] == "jsm1th"


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

    def claim(account):
        reg = registry()
        barrier.wait()
        try:
            got[account] = reg.claim(account, "kim")["handle"]
        except HandleError as e:
            got[account] = e.code

    threads = [threading.Thread(target=claim, args=(a,)) for a in accounts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(got.values()) == ["kim"] + ["taken"] * 15
    reg = registry()
    winner = reg.account_of("kim")
    assert got[winner] == "kim"
    assert [a for a in accounts if reg.handle_of(a)] == [winner]


def test_an_interrupted_rename_leaves_a_stale_entry_that_reads_as_free():
    reg = _registry()
    reg.claim("ann@example.com", "annplays")
    # a write of handles[] that never reached owners[] (a crash in between)
    reg.handles["ghost"] = {"handle": "ghost", "account": "ann@example.com"}
    assert reg.account_of("ghost") is None
    assert reg.claim("bob@example.com", "ghost")["handle"] == "ghost"


class _Crash(Exception):
    pass


class _CrashOn(dict):
    """A mapping that dies on the n-th write: a worker killed mid-claim."""

    def __init__(self, at: int):
        super().__init__()
        self.writes, self.at = 0, at

    def __setitem__(self, key, value):
        self.writes += 1
        if self.writes == self.at:
            raise _Crash(key)
        super().__setitem__(key, value)

    def __delitem__(self, key):
        self.writes += 1
        if self.writes == self.at:
            raise _Crash(key)
        super().__delitem__(key)


@pytest.mark.parametrize("where, at", [("handles", 1), ("handles", 2), ("owners", 1)])
def test_no_crash_point_in_a_rename_makes_two_owners_or_frees_a_name(where, at):
    clock = Clock()
    reg = _registry(clock)
    reg.claim("ann@example.com", "first")
    clock.t += 31 * DAY
    crashing = _CrashOn(at)
    crashing.update(getattr(reg, where))
    crashing.writes = 0
    setattr(reg, where, crashing)
    with pytest.raises(_Crash):
        reg.claim("ann@example.com", "second")
    after = HandleRegistry(
        dict(reg.handles), dict(reg.owners), account_exists=lambda a: True, clock=clock
    )
    with pytest.raises(HandleError):  # "first" is never free for someone else
        after.claim("bob@example.com", "first")
    published = [h for h in ("first", "second") if after.account_of(h)]
    assert len(published) <= 1
    # and the account recovers by confirming again
    after.claim("ann@example.com", after.ensure("ann@example.com")["handle"])
    assert after.handle_of("ann@example.com") in ("first", "second")


def test_an_interrupted_deletion_publishes_nothing_twice():
    clock = Clock()
    reg = _registry(clock)
    reg.claim("carol@example.com", "carol")
    crashing = _CrashOn(1)  # dies deleting the record, after the entry was released
    crashing.update(reg.owners)
    crashing.writes = 0
    reg.owners = crashing
    with pytest.raises(_Crash):
        reg.release_account("carol@example.com")
    assert reg.handle_of("carol@example.com") is None
    clock.t += 91 * DAY
    assert reg.claim("dave@example.com", "carol")["handle"] == "carol"
    assert reg.handle_of("carol@example.com") is None


def test_an_account_deleted_before_the_claim_gets_the_lock_keeps_nothing():
    alive = {"erin@example.com"}
    reg = HandleRegistry({}, {}, account_exists=alive.__contains__)

    class Interleave:
        def __enter__(self):
            alive.discard("erin@example.com")  # the deleter ran first

        def __exit__(self, *exc):
            return False

    reg._lock = Interleave
    with pytest.raises(HandleError) as e:
        reg.claim("erin@example.com", "erin")
    assert e.value.code == "no-account"
    assert reg.owners == {} and reg.handles == {}


def test_lookups_of_malformed_input_never_reach_the_store():
    reg = _registry()
    for bad in ("victim/x", "../etc", "a" * 500, ""):
        assert reg.account_of(bad) is None and reg.resolve(bad) is None


@pytest.mark.parametrize(
    "lengths",
    [{"min_length": 20, "max_length": 12}, {"max_length": 5}, {"min_length": 9}],
)
def test_lengths_the_search_could_not_satisfy_are_refused(lengths):
    from enlace_auth.config import coerce_auth_config

    with pytest.raises(Exception):
        coerce_auth_config({"handles": lengths})


def test_a_crowded_base_ends_the_search():
    from enlace_auth.handles import HandlePolicy

    policy = HandlePolicy(max_sequential=2, random_tries=3)
    reg = HandleRegistry({}, {}, policy=policy, account_exists=lambda a: True)
    for name in ("zed", "zed1", "zed2"):
        reg.claim(f"{name}@example.org", name)
    import enlace_auth.handles.core as core

    real = core.random.randint
    core.random.randint = lambda a, b: 111111
    try:
        reg.claim("other@example.org", "zed111111")
        with pytest.raises(HandleError) as e:
            reg.ensure("zed@example.com")
        assert e.value.code == "exhausted"
    finally:
        core.random.randint = real


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


def test_the_check_and_the_lookup_are_rate_limited(platform):
    client = platform(check_per_minute=3)
    _sign_in(client, "bob@example.com")
    codes = [
        client.get("/auth/handles/check", params={"handle": f"bob{i}"}).status_code
        for i in range(3)
    ] + [client.get("/auth/handles/someone").status_code]
    assert codes == [200, 200, 200, 429]


def test_disabled_handles_mount_nothing(platform):
    client = platform(enabled=False)
    _sign_in(client, "bob@example.com")
    assert client.get("/auth/handles/me").status_code == 404


def test_deleting_an_account_erases_its_handle_even_with_handles_off(
    platform, monkeypatch
):
    import enlace_auth.auth.accounts as accounts

    seen = {}
    real = accounts.make_account_deleter

    def spy(**kw):
        seen.update(kw)
        return real(**kw)

    monkeypatch.setattr(accounts, "make_account_deleter", spy)
    platform(enabled=False)
    assert seen["handles"] is not None  # turned off, it still erases what it kept


def test_a_long_minimum_with_a_short_local_part_ends_the_search():
    from enlace_auth.handles import HandlePolicy

    policy = HandlePolicy(min_length=7, max_sequential=3, random_tries=5)
    reg = HandleRegistry({}, {}, policy=policy, account_exists=lambda a: True)
    record = reg.ensure("bo@example.com")  # bo1..bo3 too short: the random tail fits
    assert len(record["handle"]) >= 7


def test_names_forgotten_after_many_renames_lose_their_account():
    clock = Clock()
    reg = _registry(clock, rename_cooldown_seconds=0)
    for i in range(25):
        reg.claim("ann@example.com", f"name{chr(97 + i)}x")
    reg.release_account("ann@example.com")
    assert all(e.get("account") is None for e in reg.handles.values())
