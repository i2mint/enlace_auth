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
