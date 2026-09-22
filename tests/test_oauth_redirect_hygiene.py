"""Dynamic client registration only accepts redirect URIs a code may go to.

Registration is anonymous, so the registered redirect URI is the only thing
deciding where an authorization code is delivered. The consent screen also
names that destination, so a person approving can tell whose app gets in.
"""

from __future__ import annotations

import pytest

from enlace_auth.auth.oauth_server import _redirect_uri_problem
from tests.test_oauth_server import EMAIL, SIGNING_KEY, _build  # noqa: F401


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "http://localhost:6274/oauth/callback",
        "http://127.0.0.1:33418/callback",
        "http://[::1]:8080/cb",
        "cursor://anysphere.cursor-retrieval/oauth/callback",
        "com.example.app:/oauth2redirect",
    ],
)
def test_legitimate_redirect_uris_register(tmp_path, uri):
    client, _ = _build(tmp_path)
    r = client.post("/auth/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 201, r.text
    assert _redirect_uri_problem(uri) is None


@pytest.mark.parametrize(
    "uri",
    [
        "javascript:alert(document.cookie)",
        "JavaScript://x/%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "http://evil.example/callback",
        "https:///no-host",
        "https://ok.example/cb#frag",
        "https://claude.ai@evil.example/cb",
        "https://claude.ai:443@evil.example/cb",
        "http://evil.example\\@127.0.0.1/cb",
        "https://ok.example/cb\n",
        "/relative/path",
        "",
        "https://ok.example/" + "a" * 3000,
        42,
        None,
    ],
)
def test_dangerous_redirect_uris_are_refused(tmp_path, uri):
    client, _ = _build(tmp_path)
    r = client.post("/auth/oauth/register", json={"redirect_uris": [uri]})
    assert r.status_code == 400, r.text
    assert r.json()["error"] == "invalid_redirect_uri"


def test_one_bad_uri_refuses_the_whole_registration(tmp_path):
    client, _ = _build(tmp_path)
    r = client.post(
        "/auth/oauth/register",
        json={"redirect_uris": ["https://claude.ai/cb", "javascript:alert(1)"]},
    )
    assert r.status_code == 400


@pytest.mark.parametrize("body", [[], "x", 3, None])
def test_non_object_body_is_a_clean_400(tmp_path, body):
    client, _ = _build(tmp_path)
    r = client.post("/auth/oauth/register", json=body)
    assert r.status_code == 400


def test_consent_page_names_the_destination(tmp_path):
    client, cookie = _build(tmp_path)
    r = client.post(
        "/auth/oauth/register",
        json={"redirect_uris": ["https://app.example.org/oauth/cb?x=1"]},
    )
    cid = r.json()["client_id"]
    client.cookies.set("enlace_session", cookie)
    r = client.get(
        "/auth/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": "https://app.example.org/oauth/cb?x=1",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "s",
        },
    )
    assert r.status_code == 200, r.text
    assert "<strong>https://app.example.org</strong>" in r.text


def _authorize(client, cid, redirect):
    return client.get(
        "/auth/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": cid,
            "redirect_uri": redirect,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "state": "s",
        },
        follow_redirects=False,
    )


def test_legacy_client_with_unsafe_uri_is_refused_at_authorize(tmp_path):
    """Clients stored before registration validation existed are re-checked."""
    import enlace_auth.auth.oauth_server as osrv

    client, cookie = _build(tmp_path)
    real = osrv._redirect_uri_problem
    osrv._redirect_uri_problem = lambda uri: None  # simulate pre-check registration
    try:
        r = client.post(
            "/auth/oauth/register", json={"redirect_uris": ["http://evil.example/cb"]}
        )
    finally:
        osrv._redirect_uri_problem = real
    cid = r.json()["client_id"]
    client.cookies.set("enlace_session", cookie)
    r = _authorize(client, cid, "http://evil.example/cb")
    assert r.status_code == 400
    assert "evil.example" not in r.headers.get("location", "")


def test_redirect_uri_query_is_preserved(tmp_path):
    client, cookie = _build(tmp_path, require_consent=False)
    uri = "https://app.example.org/cb?tenant=7"
    cid = client.post("/auth/oauth/register", json={"redirect_uris": [uri]}).json()[
        "client_id"
    ]
    client.cookies.set("enlace_session", cookie)
    loc = _authorize(client, cid, uri).headers["location"]
    assert loc.startswith("https://app.example.org/cb?tenant=7&code=")
    assert loc.count("?") == 1


def test_destination_display_uses_punycode():
    from enlace_auth.auth.oauth_server import _redirect_destination

    assert (
        _redirect_destination("https://\u0430pple.com/cb") == "https://xn--pple-43d.com"
    )
    assert _redirect_destination("http://[::1]:8080/cb") == "http://[::1]:8080"
    assert _redirect_destination("cursor://x/y") == "cursor:"
    assert _redirect_destination("http://[::1") == "an unrecognised address"
