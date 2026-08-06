"""Regression tests for the browser-facing auth pages (:mod:`enlace_auth.auth.pages`).

Focus: the ``next`` URL is threaded back through the sign-in page as an inline-JS
constant. It must be embedded as a **JS string literal** (JSON-encoded), never
HTML-escaped — inside a ``<script>`` element the browser does not decode HTML
entities, so escaping ``&`` to ``&amp;`` corrupts a multi-parameter ``next`` URL
(dropping every query parameter after the first). That corruption broke the OAuth
authorization-code flow, whose ``next`` is the multi-param ``/authorize`` URL.
"""

import doctest
from urllib.parse import parse_qs

import pytest

from enlace_auth.auth import pages
from enlace_auth.auth.pages import (
    _js_string,
    fill_template,
    render_login_page,
    render_shared_login_page,
)

# A representative OAuth authorize URL: several params, an embedded https redirect.
AUTHZ = (
    "/auth/oauth/authorize?response_type=code&client_id=QsnRJ56Z"
    "&redirect_uri=https://claude.ai/api/mcp/auth_callback"
    "&code_challenge=abc&code_challenge_method=S256&state=xyz"
)


def _js_runtime_value(literal: str) -> str:
    """Decode a JS string literal (with ``\\uXXXX`` escapes) to its runtime value."""
    assert literal[0] == '"' and literal[-1] == '"'
    return literal[1:-1].encode("utf-8").decode("unicode_escape")


def test_js_string_preserves_query_params():
    runtime = _js_runtime_value(_js_string(AUTHZ))
    assert runtime == AUTHZ
    assert parse_qs(runtime.split("?", 1)[1])["client_id"] == ["QsnRJ56Z"]


def test_js_string_has_no_script_breakout():
    lit = _js_string("/x?a=</script><b>&c=1")
    assert (
        "</script>" not in lit and "<" not in lit and ">" not in lit and "&" not in lit
    )
    # ...but the runtime value is exactly the original, untouched.
    assert _js_runtime_value(lit) == "/x?a=</script><b>&c=1"


def test_login_page_does_not_html_escape_next_into_js():
    page = render_login_page(next_url=AUTHZ)
    # The bug's fingerprint: an HTML entity where a raw ampersand must be.
    assert "&amp;client_id" not in page
    # The fix's fingerprint: query separators carried as JS unicode escapes.
    assert "\\u0026client_id" in page


def test_shared_login_page_does_not_html_escape_next_into_js():
    page = render_shared_login_page(app="demo", next_url=AUTHZ)
    assert "&amp;client_id" not in page
    assert "\\u0026client_id" in page


# --------------------------------------------------------------------------
# fill_template — the HTML-escaping boundary for server-rendered bodies
# --------------------------------------------------------------------------


def test_fill_template_escapes_every_value():
    # _page escapes the page *title* only, so anything interpolated into a body
    # has to be escaped here. Both attribute- and text-context characters.
    out = fill_template('<a href="{href}">{label}</a>', href='" x', label="<b>&</b>")
    assert '"' not in out.replace('href="', "").replace('">', "")
    assert "&quot; x" in out
    assert "&lt;b&gt;&amp;&lt;/b&gt;" in out
    assert "<b>" not in out


def test_fill_template_leaves_template_markup_alone():
    # The template is trusted static markup; only values are escaped.
    assert fill_template("<p>{v}</p>", v="x") == "<p>x</p>"


def test_fill_template_stringifies_non_str_values():
    assert fill_template("<p>{v}</p>", v=7) == "<p>7</p>"
    assert fill_template("<p>{v}</p>", v=None) == "<p>None</p>"


def test_fill_template_fails_loudly_on_a_missing_value():
    # A placeholder with no matching kwarg must raise, not render "{v}" or an
    # empty string — a silently-blank consent field would be a broken form.
    with pytest.raises(KeyError):
        fill_template("<p>{v}</p>")


def test_pages_doctests_pass():
    # The escaping contract is documented in fill_template's docstring; keep it
    # executable so the documented behaviour cannot drift from the code.
    results = doctest.testmod(pages, verbose=False)
    assert results.failed == 0, f"{results.failed} doctest failure(s)"
