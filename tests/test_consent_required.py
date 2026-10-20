"""The consent screen cannot be turned off (i2mint/enlace_auth#46).

Client registration is open to anyone, so a site can register a client whose
redirect URI it owns. If ``GET /auth/oauth/authorize`` issued a code without a
consent click, that site could navigate a signed-in visitor there (a top-level GET
carries the ``SameSite=Lax`` session cookie) and receive a code for the visitor's
account. So ``require_consent = false`` is refused wherever it is set, and the GET
only ever renders the consent page.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("authlib")

from enlace.base import PlatformConfig  # noqa: E402

from enlace_auth.auth.oauth_server import make_oauth_server_router  # noqa: E402
from enlace_auth.config import OAuthServerConfig, coerce_auth_config  # noqa: E402
from tests.test_oauth_server import (  # noqa: E402
    REDIRECT,
    RESOURCE,
    _authorize_params,
    _build,
    _pkce,
    _register,
)

ATTACKER_REDIRECT = "https://attacker.example/cb"


@pytest.mark.parametrize("enabled", [True, False])
def test_config_refuses_require_consent_false(enabled):
    with pytest.raises(ValueError, match="require_consent = false is refused"):
        OAuthServerConfig(
            enabled=enabled, allow_unlisted_resources=True, require_consent=False
        )


@pytest.mark.parametrize("value", ["false", 0, "no"])
def test_config_refuses_a_non_boolean_require_consent(value):
    """A string or int is a typo, never a silent bypass (nor a silent True)."""
    with pytest.raises(ValueError):
        OAuthServerConfig(
            enabled=True, allow_unlisted_resources=True, require_consent=value
        )


def test_config_accepts_require_consent_true_and_the_default():
    assert OAuthServerConfig(require_consent=True).require_consent is True
    assert OAuthServerConfig().require_consent is True


def test_platform_toml_with_require_consent_false_fails_at_load(tmp_path):
    path = tmp_path / "platform.toml"
    path.write_text(
        textwrap.dedent(
            """
            [auth]
            enabled = true
            [auth.oauth_server]
            enabled = true
            allow_unlisted_resources = true
            require_consent = false
            """
        )
    )
    with pytest.raises(ValueError, match="require_consent"):
        coerce_auth_config(PlatformConfig.from_toml(path).auth)


@pytest.mark.parametrize("value", [False, 0, None, "false"])
def test_router_refuses_anything_but_true(tmp_path, value):
    """Direct callers skip pydantic, so the router checks too."""
    with pytest.raises(ValueError, match="require_consent"):
        _build(tmp_path, require_consent=value)


def test_router_signature_still_defaults_to_consent():
    import inspect

    sig = inspect.signature(make_oauth_server_router)
    assert sig.parameters["require_consent"].default is True


def test_cross_site_get_from_a_fresh_client_gets_a_page_not_a_code(tmp_path):
    """The attack in #46: register, then navigate the signed-in visitor."""
    client, cookie = _build(tmp_path)
    cid = _register(client, redirect=ATTACKER_REDIRECT)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params={
            **_authorize_params(cid, challenge, redirect=ATTACKER_REDIRECT),
            "state": "s",
        },
        headers={"Sec-Fetch-Site": "cross-site", "Referer": ATTACKER_REDIRECT},
        follow_redirects=False,
    )
    assert r.status_code == 200
    assert "location" not in r.headers
    assert "code=" not in r.text
    assert "Approve" in r.text


def test_the_consent_post_still_needs_its_csrf_token(tmp_path):
    """The only remaining door to a code needs the signed consent token."""
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    r = client.post(
        "/auth/oauth/authorize",
        data={
            "client_id": cid,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "state": "s",
            "scope": "mcp:read",
            "resource": RESOURCE,
            "csrf": "forged",
            "decision": "approve",
        },
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert "code=" not in r.headers.get("location", "")


def test_the_consent_page_refuses_to_be_framed(tmp_path):
    """A framed consent page would turn "no click" into "one tricked click"."""
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    r = client.get(
        "/auth/oauth/authorize",
        params=_authorize_params(cid, challenge),
    )
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
