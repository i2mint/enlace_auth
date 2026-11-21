"""One sign-in for apps on sibling subdomains: ``[auth] cookie_domain`` (#94).

Apps served on ``a.apps.example.com`` and ``b.apps.example.com`` (each its own
browser origin) share the sign-in made on ``apps.example.com``: the session cookie
carries ``Domain=apps.example.com``, an app host sends its visitors to sign in on
the parent, and the parent may return them to an ``https://`` URL under it. Unset,
nothing changes; those tests are here too, with the denials that must hold either way.
"""

from __future__ import annotations

import textwrap
from urllib.parse import parse_qs, urlsplit

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth import hash_password
from enlace_auth.auth.cookie_policy import CookiePolicy, absolute_next_problem
from enlace_auth.auth.cookies import verify_cookie
from enlace_auth.auth.pages import safe_next
from enlace_auth.config import AuthConfig
from enlace_auth.stores import make_file_store_factory

KEY = "cookie-domain-key-32bytes-minimum!"
DOMAIN = "apps.example.com"
PARENT = f"https://{DOMAIN}"
APP_HOST = f"https://a.{DOMAIN}"
USER, PW = "ann@example.com", "ann-password-long-enough"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI
    app = FastAPI()
    @app.get("/page")
    def page():
        return {"ok": True}
    """
).strip()


@pytest.fixture
def platform(tmp_path, monkeypatch):
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    monkeypatch.setenv("SHARED_PW", hash_password("open-sesame"))
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    for name, toml in {
        "priv": 'access = "protected:user"\n',
        "shr": 'access = "protected:shared"\nshared_password_env = "SHARED_PW"\n',
    }.items():
        d = apps_dir / name
        d.mkdir()
        (d / "server.py").write_text(_SERVER)
        (d / "app.toml").write_text(toml)
    users = make_file_store_factory(str(tmp_path / "platform"))("users")
    users[USER] = {"password_hash": hash_password(PW)}

    def make(*, cookie_domain=DOMAIN, base_url=PARENT, **extra) -> TestClient:
        auth = {
            "enabled": True,
            "secure_cookies": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            **extra,
        }
        if cookie_domain:
            auth["cookie_domain"] = cookie_domain
        config = PlatformConfig(apps_dir=apps_dir, auth=auth)
        app = build_backend(discover_apps(config), plugins=[auth_plugin])
        return TestClient(app, base_url=base_url, follow_redirects=False)

    return make


def _csrf(client: TestClient) -> dict:
    assert client.get("/auth/csrf").status_code == 200
    raw = verify_cookie(client.cookies.get("enlace_csrf"), KEY, salt="csrf")
    return {"X-CSRF-Token": raw}


def _session_cookies(response, name="enlace_session") -> list[str]:
    return [v for v in response.headers.get_list("set-cookie") if v.startswith(name)]


def _set_cookie(response, name="enlace_session") -> str:
    """The one cookie a response SETS (not the clears that go with it)."""
    (cookie,) = [c for c in _session_cookies(response, name) if "Max-Age=0" not in c]
    return cookie


def _login(client):
    return client.post(
        "/auth/login", json={"email": USER, "password": PW}, headers=_csrf(client)
    )


# -- the session cookie --------------------------------------------------------


def test_signing_in_on_the_parent_sets_a_domain_cookie(platform):
    r = _login(platform())
    assert r.status_code == 200, r.text
    cookie = _set_cookie(r)
    assert f"Domain={DOMAIN}" in cookie and "Secure" in cookie and "HttpOnly" in cookie


def test_signing_in_on_an_app_host_sets_the_domain_cookie_too(platform):
    cookie = _set_cookie(_login(platform(base_url=APP_HOST)))
    assert f"Domain={DOMAIN}" in cookie


def test_a_host_outside_the_domain_gets_a_host_only_cookie(platform):
    """A browser would refuse Domain=apps.example.com there, and sign-in would fail."""
    cookie = _set_cookie(_login(platform(base_url="https://10.0.0.5")))
    assert "Domain=" not in cookie


def test_unset_the_cookie_is_host_only_as_before(platform):
    r = _login(platform(cookie_domain=None))
    assert len(_session_cookies(r)) == 1  # no clearing either: unchanged
    cookie = _set_cookie(r)
    assert "Domain=" not in cookie


def test_the_shared_password_cookie_carries_the_domain(platform):
    client = platform()
    r = client.post(
        "/auth/shared-login",
        json={"app": "shr", "password": "open-sesame"},
        headers=_csrf(client),
    )
    assert r.status_code == 200, r.text
    cookie = _set_cookie(r, "shared_auth_shr")
    assert f"Domain={DOMAIN}" in cookie


def test_logout_clears_the_domain_and_the_host_only_cookie(platform):
    client = platform()
    _login(client)
    r = client.post("/auth/logout", headers=_csrf(client))
    cleared = _session_cookies(r)
    assert len(cleared) == 2
    assert all("Max-Age=0" in c for c in cleared)
    assert sum(f"Domain={DOMAIN}" in c for c in cleared) == 1


def test_the_session_reaches_the_app_host(platform):
    """The point of it all: a sign-in on the parent opens an app on a subdomain."""
    parent = platform()
    _login(parent)
    app_client = platform(base_url=APP_HOST)
    app_client.cookies.set(
        "enlace_session", parent.cookies.get("enlace_session"), domain=DOMAIN
    )
    assert app_client.get("/api/priv/page").status_code == 200


def test_a_signed_in_visit_to_the_sign_in_page_moves_a_host_only_session(platform):
    """A session made before cookie_domain was set needs no new sign-in."""
    old = platform(cookie_domain=None)
    _login(old)
    client = platform()
    client.cookies.set("enlace_session", old.cookies.get("enlace_session"))
    r = client.get("/auth/login?next=/priv/")
    assert r.status_code == 303
    cookies = _session_cookies(r)
    assert any("Max-Age=0" in c and "Domain=" not in c for c in cookies)
    (moved,) = [c for c in cookies if f"Domain={DOMAIN}" in c]
    assert moved.startswith(f"enlace_session={old.cookies.get('enlace_session')};")


def test_a_signed_out_visit_to_the_sign_in_page_sets_nothing(platform):
    r = platform().get("/auth/login?next=/priv/")
    assert r.status_code == 200
    assert not _session_cookies(r)


# -- where an app host sends its visitors ------------------------------------------


def _browser_get(client, path):
    return client.get(path, headers={"accept": "text/html"})


def test_an_app_host_sends_its_visitor_to_sign_in_on_the_parent(platform):
    r = _browser_get(platform(base_url=APP_HOST), "/priv/page?x=1")
    assert r.status_code in (302, 303, 307)
    target = urlsplit(r.headers["location"])
    assert (target.scheme, target.netloc, target.path) == (
        "https",
        DOMAIN,
        "/auth/login",
    )
    assert parse_qs(target.query)["next"] == [f"{APP_HOST}/priv/page?x=1"]


def test_an_app_host_sends_a_shared_app_visitor_to_the_parents_form(platform):
    r = _browser_get(platform(base_url=APP_HOST), "/shr/page")
    target = urlsplit(r.headers["location"])
    assert (target.netloc, target.path) == (DOMAIN, "/auth/shared-login")
    assert parse_qs(target.query)["next"] == [f"{APP_HOST}/shr/page"]


def test_the_parent_and_outside_hosts_redirect_relatively_as_before(platform):
    for client in (platform(), platform(base_url="https://10.0.0.5")):
        location = _browser_get(client, "/priv/page").headers["location"]
        assert location.startswith("/auth/login?")


def test_the_sign_in_page_returns_to_an_app_host(platform):
    client = platform()
    _login(client)
    r = client.get("/auth/login", params={"next": f"{APP_HOST}/priv/page"})
    assert r.status_code == 303
    assert r.headers["location"] == f"{APP_HOST}/priv/page"


@pytest.mark.parametrize(
    "bad",
    [
        "https://evil.example.com/",
        f"https://evil{DOMAIN}/",  # a suffix, not a subdomain
        f"http://a.{DOMAIN}/",  # not https
        f"https://evil.com\\.{DOMAIN}/",  # a browser reads \\ as /
        f"https://evil.com@a.{DOMAIN}/",
        f"https://a.{DOMAIN}%2F@evil.com/",
        f"https://a.{DOMAIN}:x/",
        f"https://a.{DOMAIN}/\n",
        f"//a.{DOMAIN}/",
        f"javascript://a.{DOMAIN}/",
    ],
)
def test_the_sign_in_page_never_returns_outside_the_domain(platform, bad):
    client = platform()
    _login(client)
    r = client.get("/auth/login", params={"next": bad})
    assert r.headers["location"] == "/"
    assert safe_next(bad, cookie_domain=DOMAIN) == "/"
    assert absolute_next_problem(bad, DOMAIN) or not bad.startswith("https://")


def test_without_cookie_domain_no_absolute_next_is_accepted(platform):
    client = platform(cookie_domain=None)
    _login(client)
    r = client.get("/auth/login", params={"next": f"{APP_HOST}/priv/page"})
    assert r.headers["location"] == "/"


# -- the CSRF cookie (#78) --------------------------------------------------------


def test_the_csrf_cookie_is_secure_and_host_only(platform):
    r = platform().get("/auth/csrf")
    (cookie,) = [
        v for v in r.headers.get_list("set-cookie") if v.startswith("enlace_csrf")
    ]
    assert "Secure" in cookie and "Domain=" not in cookie


def test_the_csrf_cookie_is_secure_on_https_even_with_secure_cookies_off(tmp_path):
    from enlace_auth.auth.middleware import CSRFMiddleware

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    for base, want in (
        ("https://x.example.com", True),
        ("http://x.example.com", False),
    ):
        client = TestClient(CSRFMiddleware(app, signing_key=KEY), base_url=base)
        cookie = client.get("/").headers["set-cookie"]
        assert ("Secure" in cookie) is want, base
    forwarded = TestClient(CSRFMiddleware(app, signing_key=KEY)).get(
        "/", headers={"x-forwarded-proto": "https"}
    )
    assert "Secure" in forwarded.headers["set-cookie"]


# -- the configuration ------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "https://apps.example.com",
        ".apps.example.com",
        "Apps.Example.com",
        "apps.example.com:443",
        "localhost",
        "apps example.com",
        "",
    ],
)
def test_a_malformed_cookie_domain_is_refused_at_load(bad):
    with pytest.raises(ValueError, match="cookie_domain"):
        AuthConfig(cookie_domain=bad)


def test_the_policy_clears_only_the_host_only_form_when_unset():
    assert len(CookiePolicy(secure=False).clear_headers("s")) == 1


# -- review of #102: stale and duplicate cookies, every sign-in path -----------


def test_a_domain_sign_in_clears_an_older_host_only_cookie(platform):
    """Else the browser keeps sending the dead host-only one first, and the parent
    host never sees the new session (a reset revokes the old one: a lock-out)."""
    r = _login(platform())
    cookies = _session_cookies(r)
    assert len(cookies) == 2
    clear, new = cookies
    assert "Max-Age=0" in clear and "Domain=" not in clear
    assert f"Domain={DOMAIN}" in new


def test_the_parent_sees_the_new_session_past_a_dead_host_only_cookie(platform):
    old = platform(cookie_domain=None)
    _login(old)
    dead = old.cookies.get("enlace_session")
    old.post("/auth/logout", headers=_csrf(old))  # the session behind it ends
    client = platform()
    r = _login(client)
    fresh = _set_cookie(r).split(";", 1)[0].split("=", 1)[1]
    # What the browser holds after that response: only the Domain cookie.
    assert any("Max-Age=0" in c and "Domain=" not in c for c in _session_cookies(r))
    me = platform().get("/auth/whoami", headers={"cookie": f"enlace_session={fresh}"})
    assert me.json()["email"] == USER
    stale = platform().get("/auth/whoami", headers={"cookie": f"enlace_session={dead}"})
    assert stale.json()["email"] is None


def test_the_move_reissues_the_authenticated_cookie_not_a_planted_one(platform):
    client = platform()
    _login(client)
    good = client.cookies.get("enlace_session")
    r = platform().get(
        "/auth/login?next=/priv/",
        headers={"cookie": f"enlace_session={good}; enlace_session=planted"},
    )
    assert r.status_code == 303
    moved = _set_cookie(r)
    assert moved.startswith(f"enlace_session={good};")
    assert "planted" not in " ".join(r.headers.get_list("set-cookie"))


def test_an_email_code_sign_in_sets_the_domain_cookie(platform):
    from tests.signup_helpers import challenge, mailed_code

    client = platform(signup={"default": "open"})
    body = {"email": USER, "challenge": challenge(KEY)}
    r, code = mailed_code(client, "/auth/email/start", body, csrf=_csrf(client))
    assert r.status_code == 202 and code, r.text
    v = client.post(
        "/auth/email/verify", json={"email": USER, "code": code}, headers=_csrf(client)
    )
    assert v.status_code == 200, v.text
    assert f"Domain={DOMAIN}" in _set_cookie(v)


def test_a_passkey_sign_in_sets_the_domain_cookie(platform):
    from tests.passkey_helpers import SoftAuthenticator

    client = platform(passkeys={"enabled": True, "origins": [PARENT]})
    _login(client)
    device = SoftAuthenticator(PARENT)
    csrf = _csrf(client)
    options = client.post("/auth/passkeys/register/options", json={}, headers=csrf)
    assert options.status_code == 200, options.text
    added = client.post(
        "/auth/passkeys/register/verify",
        json={"credential": device.create(options.json()), "name": "Mac"},
        headers=csrf,
    )
    assert added.status_code == 200, added.text
    login = client.post("/auth/passkeys/login/options", json={}, headers=csrf).json()
    r = client.post(
        "/auth/passkeys/login/verify",
        json={"credential": device.get(login), "next": f"{APP_HOST}/priv/page"},
        headers=csrf,
    )
    assert r.status_code == 200, r.text
    assert f"Domain={DOMAIN}" in _set_cookie(r)
    assert r.json()["next"] == f"{APP_HOST}/priv/page"


def test_an_app_host_on_a_port_keeps_it_both_ways(platform):
    r = _browser_get(platform(base_url=f"{APP_HOST}:8443"), "/priv/page")
    target = urlsplit(r.headers["location"])
    assert target.netloc == f"{DOMAIN}:8443"
    assert parse_qs(target.query)["next"] == [f"{APP_HOST}:8443/priv/page"]


def test_no_sign_in_cookie_is_written_around_the_policy():
    """Every session or shared-password Set-Cookie goes through CookiePolicy."""
    from pathlib import Path

    import enlace_auth

    root = Path(enlace_auth.__file__).parent
    allowed = {
        "auth/cookie_policy.py",  # the policy itself
        "auth/middleware.py",  # the CSRF cookie, host-only by design
        "auth/oauth.py",  # the OAuth state cookie, Path=/auth
        "signup/routes.py",  # the sign-up nonce cookie, Path=/auth
    }
    writers = {
        str(p.relative_to(root))
        for p in root.rglob("*.py")
        if "set-cookie" in p.read_text("utf-8").lower()
    }
    assert writers <= allowed, writers - allowed
