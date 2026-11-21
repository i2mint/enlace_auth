"""Signing in keeps the fragment of the page that asked for it (#91).

The server never sees a URL fragment, so the gate's redirect cannot put it in ``next``;
the browser carries it onto the sign-in page, and the page's script re-attaches it when
it sends the visitor on. These tests check every sign-in script that leaves for
``next`` uses the shared helper, and run the helper itself in Node when Node is there.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from enlace_auth.auth.pages import (
    _NEXT_JS,
    render_login_page,
    render_shared_login_page,
)
from enlace_auth.passkeys.pages import render_signin_section
from enlace_auth.signup.pages import render_email_section, render_link_page


def _email_step() -> str:
    section = render_email_section(
        lang="en",
        next_url="/app/page/",
        app="app",
        challenge="c",
        min_seconds=0,
        mode="invite",
        code_minutes=10,
    )
    return render_login_page(next_url="/app/page/", email_section=section)


PAGES = {
    "password": lambda: render_login_page(next_url="/app/page/"),
    "shared password": lambda: render_shared_login_page(
        app="app", next_url="/app/page/"
    ),
    "email code": _email_step,
}


def test_the_passkey_button_leaves_through_the_helper():
    """Its own IIFE and copy of the helper, for the server's ``next`` or the page's."""
    html = render_signin_section(lang="en", next_url="/app/page/")
    assert "function nextUrl(next)" in html
    assert "location.assign(nextUrl(next || NEXT))" in html
    assert "location.hash" not in html.replace(_NEXT_JS, "")


@pytest.mark.parametrize("name", PAGES)
def test_every_sign_in_script_leaves_through_the_helper(name):
    html = PAGES[name]()
    assert "function nextUrl(next)" in html, name
    assert "location.assign(nextUrl(NEXT))" in html, name
    assert not re.search(r"location\.assign\(NEXT\b", html), name


def test_the_email_step_has_its_own_copy_of_the_helper():
    """Its script runs in an IIFE beside the password form's, so it needs its own."""
    html = _email_step()
    assert html.count("location.assign(nextUrl(NEXT))") == 2
    assert html.count("function nextUrl(next)") == 2


def test_the_emailed_link_page_does_not_append_its_own_fragment():
    """Its fragment is the one-time token: it must never travel on to the app."""
    html = render_link_page(lang="en")
    assert "nextUrl(" not in html
    assert "history.replaceState(null, '', location.pathname)" in html


def _run(next_value, hash_value: str) -> str:
    script = (
        f"const location = {{hash: {json.dumps(hash_value)}}};\n"
        f"{_NEXT_JS}\n"
        f"process.stdout.write(nextUrl({json.dumps(next_value)}));\n"
    )
    out = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=30, check=True
    )
    return out.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize(
    "next_value, hash_value, want",
    [
        ("/app/page/", "#state=abc", "/app/page/#state=abc"),  # the fix
        ("/app/page/?q=1", "#t=x", "/app/page/?q=1#t=x"),
        ("/app/page/", "", "/app/page/"),  # no fragment: unchanged
        ("/app/page/#own", "#state=abc", "/app/page/#own"),  # next's own fragment wins
        ("", "#state=abc", "/"),  # no next: the root, not someone else's fragment
        (None, "#state=abc", "/"),
    ],
)
def test_next_url_keeps_the_fragment(next_value, hash_value, want):
    assert _run(next_value, hash_value) == want
