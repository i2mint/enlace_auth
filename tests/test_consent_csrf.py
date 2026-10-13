"""The consent CSRF token approves one request, in one session, for a while (#49).

It used to be ``sign_cookie(email)``: one value per account that never expired and
named no client. A script that read one consent page once (an XSS anywhere on the
shared origin) could then approve any client's request, in any later session,
without a click. The token is now bound to the session, to every field of the
request its page showed, and to ``consent_ttl``.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("authlib")
pytest.importorskip("multipart")

from enlace_auth.auth.cookies import sign_cookie, verify_cookie  # noqa: E402
from enlace_auth.auth.sessions import SessionStore  # noqa: E402
from enlace_auth.config import OAuthServerConfig  # noqa: E402
from tests.test_oauth_server import (  # noqa: E402
    COOKIE,
    EMAIL,
    OTHER_RESOURCE,
    REDIRECT,
    RESOURCE,
    SIGNING_KEY,
    _build,
    _consent_csrf,
    _pkce,
    _register,
)

ATTACKER_REDIRECT = "https://attacker.example/cb"
SECOND_REDIRECT = "https://claude.ai/api/mcp/callback2"


def _post(client, cookie, csrf, **overrides):
    form = {
        "redirect_uri": REDIRECT,
        "state": "s",
        "scope": "mcp:read",
        "resource": RESOURCE,
        "decision": "approve",
        "csrf": csrf,
        **overrides,
    }
    return client.post(
        "/auth/oauth/authorize",
        data=form,
        cookies={COOKIE: cookie},
        follow_redirects=False,
    )


def _no_code(r):
    assert r.status_code == 403, r.text
    assert "code=" not in r.headers.get("location", "")
    assert "Nothing was approved" in r.text


def test_the_page_token_approves_its_own_request(tmp_path):
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    r = _post(client, cookie, csrf, client_id=cid, code_challenge=challenge)
    assert r.status_code == 302 and "code=" in r.headers["location"]


def test_a_token_from_one_clients_page_does_not_approve_another(tmp_path):
    """The review's reproduction: a victim-client token approving an attacker client."""
    client, cookie = _build(tmp_path)
    victim = _register(client)
    attacker = _register(client, redirect=ATTACKER_REDIRECT)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=victim, challenge=challenge)
    r = _post(
        client,
        cookie,
        csrf,
        client_id=attacker,
        redirect_uri=ATTACKER_REDIRECT,
        code_challenge=challenge,
    )
    _no_code(r)


@pytest.mark.parametrize(
    "field, value",
    [
        ("redirect_uri", SECOND_REDIRECT),
        ("code_challenge", "a-different-challenge"),
        ("state", "another-state"),
        ("resource", OTHER_RESOURCE),
    ],
)
def test_changing_any_request_field_voids_the_token(tmp_path, field, value):
    client, cookie = _build(tmp_path)
    r = client.post(
        "/auth/oauth/register", json={"redirect_uris": [REDIRECT, SECOND_REDIRECT]}
    )
    cid = r.json()["client_id"]
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    form = {"client_id": cid, "code_challenge": challenge, field: value}
    _no_code(_post(client, cookie, csrf, **form))


def test_a_token_does_not_outlive_its_session(tmp_path):
    """A new sign-in (after logout, a password change...) gets new tokens."""
    store = SessionStore({})
    client, cookie = _build(tmp_path, session_store=store)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    new_sid = store.create(user_id=EMAIL, email=EMAIL)
    new_cookie = sign_cookie(new_sid, SIGNING_KEY, salt="session")
    _no_code(_post(client, new_cookie, csrf, client_id=cid, code_challenge=challenge))


def test_a_token_expires_after_consent_ttl(tmp_path, monkeypatch):
    client, cookie = _build(tmp_path, consent_ttl=60)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    later = time.time() + 61
    monkeypatch.setattr(time, "time", lambda: later)
    _no_code(_post(client, cookie, csrf, client_id=cid, code_challenge=challenge))


@pytest.mark.parametrize("email", [EMAIL, "j\u00f6rg@example.com"])
def test_the_old_email_token_is_refused(tmp_path, email):
    """A page rendered before #49 carries the bare email, non-ASCII ones too."""
    client, cookie = _build(tmp_path, email=email)
    cid = _register(client)
    _, challenge = _pkce()
    legacy = sign_cookie(email, SIGNING_KEY, salt="oauth-consent")
    _no_code(_post(client, cookie, legacy, client_id=cid, code_challenge=challenge))


def test_the_stale_form_page_cannot_be_framed(tmp_path):
    client, cookie = _build(tmp_path)
    cid = _register(client)
    r = _post(client, cookie, "garbage", client_id=cid, code_challenge="x")
    _no_code(r)
    assert r.headers["x-frame-options"] == "DENY"


def test_the_token_does_not_carry_the_session_id(tmp_path):
    """The token sits in the page; a raw session id there would leak the session."""
    store = SessionStore({})
    client, cookie = _build(tmp_path, session_store=store)
    sid = verify_cookie(cookie, SIGNING_KEY, salt="session")
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    payload = verify_cookie(csrf, SIGNING_KEY, salt="oauth-consent")
    assert sid not in csrf and sid not in payload
    assert EMAIL not in payload


@pytest.mark.parametrize("ttl", [0, -1])
def test_a_non_positive_consent_ttl_is_refused(tmp_path, ttl):
    with pytest.raises(ValueError, match="consent_ttl"):
        _build(tmp_path, consent_ttl=ttl)
    with pytest.raises(ValueError):
        OAuthServerConfig(consent_ttl_seconds=ttl)


# --- One click, one code (#55) ---------------------------------------------


def test_a_token_is_spent_by_its_first_submit(tmp_path):
    """A double-click (or a replayed POST) gets the stale page, not a second code."""
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    first = _post(client, cookie, csrf, client_id=cid, code_challenge=challenge)
    assert first.status_code == 302 and "code=" in first.headers["location"]
    _no_code(_post(client, cookie, csrf, client_id=cid, code_challenge=challenge))


def test_a_deny_spends_the_token_too(tmp_path):
    client, cookie = _build(tmp_path)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    denied = _post(
        client, cookie, csrf, client_id=cid, code_challenge=challenge, decision="deny"
    )
    assert denied.status_code == 302 and "access_denied" in denied.headers["location"]
    _no_code(_post(client, cookie, csrf, client_id=cid, code_challenge=challenge))


def test_a_new_request_gets_its_own_approval(tmp_path):
    """Spending one request's approval leaves the next authorization untouched."""
    client, cookie = _build(tmp_path)
    cid = _register(client)
    for _ in range(2):
        _, challenge = _pkce()
        csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
        r = _post(client, cookie, csrf, client_id=cid, code_challenge=challenge)
        assert r.status_code == 302 and "code=" in r.headers["location"]


def test_a_forged_token_never_reaches_the_claim(tmp_path):
    """Only a verified token spends anything: junk must not burn a real approval."""
    claimed = []
    client, cookie = _build(
        tmp_path, consent_claim_once=lambda k: claimed.append(k) or True
    )
    cid = _register(client)
    _, challenge = _pkce()
    _no_code(_post(client, cookie, "junk", client_id=cid, code_challenge=challenge))
    assert claimed == []
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    _post(client, cookie, csrf, client_id=cid, code_challenge=challenge)
    assert len(claimed) == 1 and len(claimed[0]) == 64  # a sha256 hex filename


def test_the_injected_consent_claim_decides(tmp_path):
    """The platform injects a cross-process claim; a False from it is stale."""
    client, cookie = _build(tmp_path, consent_claim_once=lambda k: False)
    cid = _register(client)
    _, challenge = _pkce()
    csrf = _consent_csrf(client, cookie, cid=cid, challenge=challenge)
    _no_code(_post(client, cookie, csrf, client_id=cid, code_challenge=challenge))
