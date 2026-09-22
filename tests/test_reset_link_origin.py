"""A password-reset email links to the platform's configured origin.

Built from the request instead, the link would follow a forged ``Host`` header
and deliver the victim's reset token to whatever site the requester named.
"""

from __future__ import annotations

import re

from fastapi import FastAPI
from starlette.testclient import TestClient

from enlace_auth.auth import SessionStore, hash_password
from enlace_auth.auth.routes import make_auth_router
from enlace_auth.plugin import _public_base_url


def _client(**kw):
    sent = []
    router = make_auth_router(
        session_store=SessionStore({}),
        user_store={"a@example.com": {"password_hash": hash_password("pw-12345678")}},
        signing_key="k" * 40,
        secure_cookies=False,
        send_email=lambda **m: sent.append(m),
        **kw,
    )
    app = FastAPI()
    app.include_router(router)
    return TestClient(app), sent


def _link(sent):
    return re.search(r"(\S+/auth/reset-password\?token=\S+)", sent[-1]["body"]).group(1)


def test_forged_host_does_not_reach_the_link():
    client, sent = _client(public_base_url="https://platform.example")
    r = client.post(
        "/auth/password-reset/request",
        json={"email": "a@example.com"},
        headers={"Host": "attacker.example"},
    )
    assert r.status_code == 200
    assert _link(sent).startswith("https://platform.example/auth/reset-password?")
    assert "attacker.example" not in sent[-1]["body"]


def test_without_a_configured_origin_the_request_origin_is_used():
    client, sent = _client()
    client.post("/auth/password-reset/request", json={"email": "a@example.com"})
    assert _link(sent).startswith("http://testserver/auth/reset-password?")


class _Cfg:
    def __init__(self, domain="localhost", issuer=None):
        self.domain = domain

        class _OS:
            pass

        self.oauth_server = _OS()
        self.oauth_server.issuer = issuer


def test_public_base_url_precedence():
    assert _public_base_url(_Cfg(), _Cfg()) is None
    assert _public_base_url(_Cfg("example.com"), _Cfg()) == "https://example.com"
    auth = _Cfg(issuer="https://id.example.com")
    assert _public_base_url(_Cfg("example.com"), auth) == "https://id.example.com"
