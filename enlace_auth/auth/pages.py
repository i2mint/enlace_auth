"""HTML pages for the enlace_auth browser-facing flows.

Single source of truth for the auth UI: the sign-in page, the password-recovery
pages, and a generic notice page. Pages are returned as plain HTML strings — the
same inline-HTML, no-build-step pattern used elsewhere in enlace
(``enlace.frontend._NOT_FOUND_PAGE``). All pages share one dark, minimal
stylesheet so the platform feels consistent from the very first unauthenticated
screen.

``PlatformAuthMiddleware`` 303-redirects a blocked browser navigation to
``/auth/login?login_required=1&next=<path>``; :func:`render_login_page` is the
page that redirect lands on, and it threads ``next`` back through after sign-in.
"""

from __future__ import annotations

from html import escape
from typing import Optional

# --------------------------------------------------------------------------
# Shared chrome
# --------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box}
body{font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
     background:#0f1115;color:#e6e8eb;margin:0;min-height:100vh;
     display:grid;place-items:center;padding:20px}
.card{width:100%;max-width:400px;background:#171a21;border:1px solid #2a2e38;
      border-radius:12px;padding:28px 32px}
.card.wide{max-width:560px}
h1{margin:0 0 6px;font-size:21px;font-weight:600;text-align:center}
.sub{margin:0 0 20px;color:#8a90a0;font-size:14px;text-align:center}
p{color:#c4c8d0;margin:0 0 16px}
label{display:block;font-size:13px;color:#8a90a0;margin:14px 0 4px}
input{width:100%;background:#0f1115;border:1px solid #2a2e38;border-radius:8px;
      color:#e6e8eb;font-size:15px;padding:10px 12px}
input:focus{outline:none;border-color:#7cc4ff}
button{width:100%;margin-top:20px;background:#7cc4ff;color:#0a1420;border:0;
       border-radius:8px;font-size:15px;font-weight:600;padding:11px;
       cursor:pointer}
button:hover{background:#9aa6ff}
button:disabled{opacity:.6;cursor:default}
a{color:#7cc4ff;text-decoration:none}
a:hover{text-decoration:underline}
a.btn{display:inline-block;width:auto;background:#7cc4ff;color:#0a1420;
      font-weight:600;padding:9px 18px;border-radius:8px;margin-top:4px}
a.btn:hover{background:#9aa6ff;text-decoration:none}
.nav{margin-top:18px;text-align:center;font-size:13px}
.nav a{margin:0 8px}
.msg{margin-top:14px;padding:9px 12px;border-radius:8px;font-size:14px;
     display:none}
.msg.err{display:block;background:#2a1416;border:1px solid #5a2a2e;
         color:#ffb4b4}
.msg.ok{display:block;background:#13241a;border:1px solid #2a5a3a;
        color:#a4e8c0}
.muted{color:#8a90a0;font-size:13px;text-align:center;margin-top:14px}
code{background:#0f1115;padding:1px 6px;border-radius:4px;
     border:1px solid #2a2e38;color:#e6e8eb;word-break:break-all}
.actions{text-align:center}
""".strip()

_SHELL = (
    "<!doctype html>\n"
    '<html lang="en"><head><meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
    "<title>__TITLE__</title>\n"
    "<style>__CSS__</style></head><body>\n"
    "__BODY__\n"
    "</body></html>"
)

# Shared client helper: the CSRF double-submit dance. enlace's CSRFMiddleware
# requires GET /auth/csrf first, then the unsigned token echoed in a header on
# every mutating request.
_CSRF_JS = """
async function csrfToken(){
  const r = await fetch('/auth/csrf', {credentials:'include'});
  if(!r.ok) throw new Error('Could not get a security token. Reload and retry.');
  return (await r.json()).csrf;
}
async function postJSON(url, data){
  const token = await csrfToken();
  const r = await fetch(url, {
    method:'POST', credentials:'include',
    headers:{'Content-Type':'application/json','X-CSRF-Token':token},
    body: JSON.stringify(data),
  });
  let body = {};
  try { body = await r.json(); } catch(e) {}
  return {ok:r.ok, status:r.status, detail:(body && body.detail) || ''};
}
"""


def _page(title: str, body: str) -> str:
    """Wrap ``body`` HTML in the shared shell with ``title``."""
    return (
        _SHELL.replace("__TITLE__", escape(title))
        .replace("__CSS__", _CSS)
        .replace("__BODY__", body)
    )


def _msg_div(error: Optional[str]) -> str:
    """Return the ``#msg`` status element, pre-populated when ``error`` is set.

    Forms reuse a single status line: server-rendered errors land here on first
    paint, and the client script rewrites the same element after a submit.
    """
    if error:
        return f'<div id="msg" class="msg err">{escape(error)}</div>'
    return '<div id="msg" class="msg"></div>'


def safe_next(raw: Optional[str], *, default: str = "/") -> str:
    """Return a same-origin path safe to redirect to, or ``default``.

    Guards against open-redirect: only local absolute paths are accepted —
    no scheme, no ``//host`` form, no control characters. This is applied to
    every ``?next=`` value before it reaches a page or a redirect.
    """
    if not raw or not isinstance(raw, str):
        return default
    if not raw.startswith("/") or raw.startswith("//") or raw.startswith("/\\"):
        return default
    if any(c in raw for c in ("\n", "\r", "\t", "\\")) or ":" in raw.split("?", 1)[0]:
        return default
    return raw


# --------------------------------------------------------------------------
# Sign-in
# --------------------------------------------------------------------------


def render_login_page(
    *,
    next_url: str = "/",
    error: Optional[str] = None,
    show_register_hint: bool = True,
) -> str:
    """Render the sign-in form.

    Args:
        next_url: where to send the browser after a successful login. Already
            sanitized by the caller via :func:`safe_next`.
        error: optional error banner (e.g. a stale-session note).
        show_register_hint: whether to show the "ask an admin" footnote.
    """
    next_js = escape(next_url, quote=True)
    hint = (
        '<p class="muted">No account? Accounts are created by the platform '
        "admin.</p>"
        if show_register_hint
        else ""
    )
    body = f"""<div class="card">
<h1>Sign in</h1>
<p class="sub">Access your apps on this platform.</p>
<form id="f" autocomplete="on">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autocomplete="username"
         autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" required
         autocomplete="current-password">
  <button id="submit" type="submit">Sign in</button>
</form>
{_msg_div(error)}
<div class="nav">
  <a href="/auth/forgot-password">Forgot password?</a>
  <a href="/">Back to apps</a>
</div>
{hint}
</div>
<script>
{_CSRF_JS}
const NEXT = "{next_js}";
const f = document.getElementById('f');
const msg = document.getElementById('msg');
const submit = document.getElementById('submit');
f.addEventListener('submit', async (e) => {{
  e.preventDefault();
  msg.className = 'msg'; submit.disabled = true; submit.textContent = 'Signing in…';
  try {{
    const res = await postJSON('/auth/login', {{
      email: document.getElementById('email').value.trim(),
      password: document.getElementById('password').value,
    }});
    if (res.ok) {{ window.location.assign(NEXT || '/'); return; }}
    msg.textContent = res.detail || ('Sign in failed (' + res.status + ').');
    msg.className = 'msg err';
  }} catch (err) {{
    msg.textContent = err.message || 'Something went wrong.';
    msg.className = 'msg err';
  }}
  submit.disabled = false; submit.textContent = 'Sign in';
}});
</script>"""
    return _page("Sign in", body)


# --------------------------------------------------------------------------
# Forgot password — request a reset link
# --------------------------------------------------------------------------


def render_forgot_page(*, error: Optional[str] = None) -> str:
    """Render the "request a password-reset link" form."""
    body = f"""<div class="card">
<h1>Reset your password</h1>
<p class="sub">We'll email you a link to set a new password.</p>
<form id="f">
  <label for="email">Email</label>
  <input id="email" name="email" type="email" required autocomplete="username"
         autofocus>
  <button id="submit" type="submit">Email me a reset link</button>
</form>
{_msg_div(error)}
<div class="nav">
  <a href="/auth/login">Back to sign in</a>
</div>
</div>
<script>
{_CSRF_JS}
const f = document.getElementById('f');
const msg = document.getElementById('msg');
const submit = document.getElementById('submit');
f.addEventListener('submit', async (e) => {{
  e.preventDefault();
  msg.className = 'msg'; submit.disabled = true; submit.textContent = 'Sending…';
  try {{
    const res = await postJSON('/auth/password-reset/request', {{
      email: document.getElementById('email').value.trim(),
    }});
    if (res.ok) {{
      msg.textContent = "If that email has an account, a reset link is on its "
        + "way. Check your inbox (and spam).";
      msg.className = 'msg ok';
      f.style.display = 'none';
    }} else {{
      msg.textContent = res.detail || ('Request failed (' + res.status + ').');
      msg.className = 'msg err';
      submit.disabled = false; submit.textContent = 'Email me a reset link';
    }}
  }} catch (err) {{
    msg.textContent = err.message || 'Something went wrong.';
    msg.className = 'msg err';
    submit.disabled = false; submit.textContent = 'Email me a reset link';
  }}
}});
</script>"""
    return _page("Reset your password", body)


# --------------------------------------------------------------------------
# Reset password — set a new one from a token
# --------------------------------------------------------------------------


def render_reset_page(*, token: str, error: Optional[str] = None) -> str:
    """Render the "set a new password" form for a reset ``token``."""
    token_js = escape(token, quote=True)
    body = f"""<div class="card">
<h1>Choose a new password</h1>
<p class="sub">Enter a new password for your account.</p>
<form id="f">
  <label for="pw">New password</label>
  <input id="pw" name="pw" type="password" required minlength="8"
         autocomplete="new-password" autofocus>
  <label for="pw2">Confirm new password</label>
  <input id="pw2" name="pw2" type="password" required minlength="8"
         autocomplete="new-password">
  <button id="submit" type="submit">Set new password</button>
</form>
{_msg_div(error)}
<div class="nav">
  <a href="/auth/login">Back to sign in</a>
</div>
</div>
<script>
{_CSRF_JS}
const TOKEN = "{token_js}";
const f = document.getElementById('f');
const msg = document.getElementById('msg');
const submit = document.getElementById('submit');
f.addEventListener('submit', async (e) => {{
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  const pw2 = document.getElementById('pw2').value;
  msg.className = 'msg';
  if (pw !== pw2) {{
    msg.textContent = "The two passwords don't match.";
    msg.className = 'msg err'; return;
  }}
  if (pw.length < 8) {{
    msg.textContent = 'Use at least 8 characters.';
    msg.className = 'msg err'; return;
  }}
  submit.disabled = true; submit.textContent = 'Saving…';
  try {{
    const res = await postJSON('/auth/password-reset/confirm', {{
      token: TOKEN, new_password: pw,
    }});
    if (res.ok) {{
      msg.textContent = "Password updated — you're now signed in.";
      msg.className = 'msg ok';
      f.style.display = 'none';
      setTimeout(() => window.location.assign('/'), 1200);
    }} else {{
      msg.textContent = res.detail || ('Reset failed (' + res.status + ').');
      msg.className = 'msg err';
      submit.disabled = false; submit.textContent = 'Set new password';
    }}
  }} catch (err) {{
    msg.textContent = err.message || 'Something went wrong.';
    msg.className = 'msg err';
    submit.disabled = false; submit.textContent = 'Set new password';
  }}
}});
</script>"""
    return _page("Choose a new password", body)


# --------------------------------------------------------------------------
# Generic notice page (errors, confirmations)
# --------------------------------------------------------------------------


def render_notice_page(
    *,
    title: str,
    heading: str,
    message: str,
    links: list[tuple[str, str, bool]],
    wide: bool = False,
) -> str:
    """Render a centered notice card.

    Args:
        title: ``<title>`` text.
        heading: the card's ``<h1>``.
        message: a sentence or two of explanation (HTML-escaped here).
        links: ``(label, href, is_primary)`` tuples rendered as a row of
            actions; primary links get the filled-button style.
        wide: use the wider card (for longer content).
    """
    link_html = " ".join(
        f'<a class="btn" href="{escape(href, quote=True)}">{escape(label)}</a>'
        if primary
        else f'<a href="{escape(href, quote=True)}">{escape(label)}</a>'
        for label, href, primary in links
    )
    cls = "card wide" if wide else "card"
    body = f"""<div class="{cls}">
<h1>{escape(heading)}</h1>
<p style="text-align:center">{escape(message)}</p>
<div class="actions">{link_html}</div>
</div>"""
    return _page(title, body)

