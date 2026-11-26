"""An app opts its own write paths into the CSRF check with app.toml ``csrf``.

i2mint/enlace_auth#110: a ``public`` app that lets a few signed-in people write
(``request.state.user_groups``) has its endpoints under ``/api/<app>/``, which
the double-submit check exempts. ``SameSite=Lax`` alone does not stop a
same-site page (a sibling host under ``cookie_domain``) from posting there with
the victim's session. ``csrf = true`` (or a list of sub-paths) puts those paths
under the same check as ``/api/<app>/store``. Without the key nothing changes.
"""

from __future__ import annotations

import textwrap

import pytest
from enlace.base import PlatformConfig
from enlace.compose import build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin
from enlace_auth.auth.cookies import sign_cookie
from enlace_auth.auth.middleware import _under_any
from tests.signup_helpers import sign_up

KEY = "app-csrf-key-32bytes-minimum-len!!"
_SERVER = textwrap.dedent(
    """
    from fastapi import FastAPI, Request
    app = FastAPI()
    @app.api_route("/edit", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    def edit(request: Request):
        return {"wrote": request.method}
    @app.post("/edit/{item}")
    def edit_item(item: str):
        return {"wrote": item}
    @app.post("/editor")
    def editor():
        return {"wrote": "editor"}
    @app.post("/open")
    def open_write():
        return {"wrote": "open"}
    """
).strip()

APPS = {
    "ed": 'access = "public"\ncsrf = ["edit"]\n',
    "whole": 'access = "public"\ncsrf = true\n',
    "plain": 'access = "public"\n',
    "off": 'access = "public"\ncsrf = false\n',
}


def _platform(tmp_path, monkeypatch, apps: dict, *, external: dict = ()):
    monkeypatch.setenv("ENLACE_SIGNING_KEY", KEY)
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    for name, toml in apps.items():
        d = apps_dir / name
        d.mkdir()
        (d / "server.py").write_text(_SERVER)
        (d / "app.toml").write_text(toml)
    for name, toml in dict(external).items():
        d = apps_dir / name
        d.mkdir()
        (d / "app.toml").write_text(toml)
    config = PlatformConfig(
        apps_dir=apps_dir,
        auth={
            "enabled": True,
            "secure_cookies": False,
            "registration_open": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
        },
        stores={"user_data": {"backend": "file", "path": str(tmp_path / "ud")}},
    )
    return build_backend(discover_apps(config), plugins=[auth_plugin])


@pytest.fixture
def client(tmp_path, monkeypatch):
    return TestClient(_platform(tmp_path, monkeypatch, APPS))


def _token(client) -> str:
    return client.get("/auth/csrf").json()["csrf"]


def _sign_in(client, email: str = "writer@example.com") -> None:
    csrf = {"X-CSRF-Token": _token(client)}
    r = sign_up(client, email, "a-long-enough-passphrase", csrf=csrf)
    assert r.status_code == 200, r.text


# --- The default is unchanged -------------------------------------------------


@pytest.mark.parametrize(
    "path", ["/api/plain/edit", "/api/off/edit", "/api/plain/open"]
)
def test_apps_without_the_key_stay_exempt(client, path):
    r = client.post(path)
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("path", ["/api/ed/open", "/api/ed/editor"])
def test_unlisted_sub_paths_stay_exempt(client, path):
    """A list covers its sub-paths by whole segments, nothing else."""
    assert client.post(path).status_code == 200


def test_safe_methods_need_no_token(client):
    """GET is never checked: a write must not be reachable by GET (documented)."""
    r = client.get("/api/ed/edit")
    assert r.status_code == 200 and r.json() == {"wrote": "GET"}


def test_opting_in_sets_no_cookie_on_public_pages(client):
    """#31 still holds: only /auth/csrf (and protected apps) mint the cookie."""
    for path in ("/api/ed/edit", "/api/whole/open", "/ed/"):
        assert client.get(path).headers.get_list("set-cookie") == [], path


# --- Forgery is refused ---------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize(
    "path", ["/api/ed/edit", "/api/ed/edit/42", "/api/whole/open", "/api/whole/edit"]
)
def test_opted_in_writes_without_a_token_are_refused(client, method, path):
    r = client.request(method, path)
    assert r.status_code == 403, (method, path, r.text)
    assert r.json() == {"detail": "CSRF check failed"}


def test_a_signed_in_form_post_is_refused(client):
    """The attack: the victim's session (and even its CSRF cookie) ride along on
    a same-site form post, which cannot set the header."""
    _sign_in(client)  # the victim's browser now holds a valid CSRF cookie too
    assert "enlace_session" in client.cookies and "enlace_csrf" in client.cookies
    r = client.post("/api/ed/edit", data={"x": "1"})
    assert r.status_code == 403


def test_a_wrong_header_is_refused(client):
    _token(client)
    r = client.post("/api/ed/edit", headers={"X-CSRF-Token": "guessed"})
    assert r.status_code == 403


def test_a_header_without_its_cookie_is_refused(client):
    token = _token(client)
    other = TestClient(client.app)  # a browser that never fetched a token
    r = other.post("/api/ed/edit", headers={"X-CSRF-Token": token})
    assert r.status_code == 403


def test_an_unsigned_or_foreign_cookie_is_refused(client):
    """Cookie tossing: an attacker who can set a cookie still cannot sign one."""
    for cookie in (
        "chosen",
        sign_cookie("chosen", "another-key-32bytes-minimum-len!!!", salt="csrf"),
    ):
        c = TestClient(client.app)
        c.cookies.set("enlace_csrf", cookie)
        r = c.post("/api/ed/edit", headers={"X-CSRF-Token": "chosen"})
        assert r.status_code == 403, cookie


@pytest.mark.parametrize(
    "path",
    [
        "/api/ed//edit",
        "/api/ED/edit",
        "/api/ed/EDIT",
        "/api/ed/edit;v=1",
        "/api/ed/edit/",
    ],
)
def test_other_spellings_of_an_opted_in_path_are_refused(client, path):
    """A spelling a lenient upstream router may resolve to /edit is checked too."""
    assert client.post(path).status_code == 403, path


def test_the_spelling_match_only_adds_enforcement():
    edit = ("/api/ed/edit",)
    assert _under_any("/api/ed/./edit", edit)
    assert _under_any("/api/ed/x/../edit", edit)
    assert _under_any("/api//ed///edit/1", edit)
    assert not _under_any("/api/ed/editor", edit)
    assert not _under_any("/api/ed/open", edit)


# --- The legitimate client ------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_the_token_from_auth_csrf_lets_the_app_write(client, method):
    token = _token(client)
    r = client.request(method, "/api/ed/edit", headers={"X-CSRF-Token": token})
    assert r.status_code == 200 and r.json() == {"wrote": method}
    r = client.post("/api/whole/open", headers={"X-CSRF-Token": token})
    assert r.status_code == 200


def test_a_signed_in_writer_with_the_token_writes(client):
    _sign_in(client)
    r = client.post("/api/ed/edit/7", headers={"X-CSRF-Token": _token(client)})
    assert r.status_code == 200 and r.json() == {"wrote": "7"}


# --- Proxied apps and refusals ------------------------------------------------------


def test_a_proxied_app_can_opt_in(tmp_path, monkeypatch):
    """External/process apps are exempt by default; csrf = true checks them first."""
    upstream = (
        'mode = "external"\nupstream_url = "http://127.0.0.1:9"\naccess = "public"\n'
    )
    app = _platform(
        tmp_path,
        monkeypatch,
        {},
        external={"ext": upstream + "csrf = true\n", "raw": upstream},
    )
    client = TestClient(app, raise_server_exceptions=False)
    assert client.post("/api/ext/write").status_code == 403
    # Without the key the request goes through to the (unreachable) upstream.
    assert client.post("/api/raw/write").status_code != 403


def test_a_root_route_app_cannot_opt_in(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="site root"):
        _platform(tmp_path, monkeypatch, {"rooty": 'route = "/"\ncsrf = true\n'})
