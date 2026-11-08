"""Markup for the sign-up flow: the "continue with email" step, the link page,
and the account-deletion card.

Every dynamic value reaches the markup through
:func:`enlace_auth.auth.pages.fill_template` (HTML) or ``_js_string`` (inline
script), the same escaping boundary as the rest of the auth pages. The step is
handed to :func:`~enlace_auth.auth.pages.render_login_page` as its
``email_section``; it carries its own script, which reuses the page's
``postJSON`` CSRF helper.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape
from typing import Optional

from enlace_auth.auth.pages import (
    _CSRF_JS,
    _js_string,
    _page,
    fill_template,
)
from enlace_auth.signup.botcheck import HONEYPOT_FIELD
from enlace_auth.signup.texts import t


def _link(href: str, label: str) -> str:
    return fill_template(
        '<a href="{href}" target="_blank" rel="noopener">{label}</a>',
        href=href,
        label=label,
    )


def _legal_line(lang: str, *, terms_url: Optional[str], privacy_url: Optional[str]):
    """'By continuing you accept the terms and the privacy notice', as available."""
    terms = _link(terms_url, t(lang, "terms")) if terms_url else ""
    privacy = _link(privacy_url, t(lang, "privacy")) if privacy_url else ""
    # The translated sentence is trusted; only the escaped links are inserted.
    if terms and privacy:
        text = t(lang, "accept", terms="{terms}", privacy="{privacy}")
    elif terms:
        text = t(lang, "accept_terms", terms="{terms}")
    elif privacy:
        text = t(lang, "accept_privacy", privacy="{privacy}")
    else:
        return ""
    html = escape(text).replace("{terms}", terms).replace("{privacy}", privacy)
    return f'<p class="muted">{html}</p>'


def render_email_section(
    *,
    lang: str,
    next_url: str,
    app: Optional[str],
    challenge: str,
    min_seconds: float,
    mode: str,
    code_minutes: int,
    terms_url: Optional[str] = None,
    privacy_url: Optional[str] = None,
    providers: Sequence[tuple[str, str]] = (),
) -> str:
    """The "continue with email" step: address, then the 6-digit code.

    *mode* (the sign-up policy of *app*) picks the note under the form: an open
    policy says who may sign up (15 and over), an invite or allowlist policy
    says sign-up is by invitation, a closed one says accounts come from the
    admin. *providers* are ``(label, href)`` pairs for external sign-in.
    """
    note_key = {"open": "note_open", "closed": "note_closed"}.get(mode, "note_invite")
    legal = (
        _legal_line(lang, terms_url=terms_url, privacy_url=privacy_url)
        if mode != "closed"
        else ""
    )
    provider_links = "".join(
        fill_template(
            '<a class="alt" href="{href}">{label}</a>',
            href=href,
            label=t(lang, "provider", name=label),
        )
        for label, href in providers
    )
    form = fill_template(
        """<form id="ef" autocomplete="on">
  <label for="e-email">{email_label}</label>
  <input id="e-email" name="email" type="email" required
         autocomplete="username email" autofocus>
  <div class="hp" aria-hidden="true"><label>Website
    <input id="e-hp" name="{hp}" tabindex="-1" autocomplete="off"></label></div>
  <button id="e-submit" type="submit">{continue_label}</button>
</form>
<form id="cf" hidden>
  <p id="e-sent"></p>
  <label for="e-code">{code_label}</label>
  <input id="e-code" name="code" inputmode="numeric" pattern="[0-9 -]*"
         autocomplete="one-time-code" maxlength="9" required>
  <button id="c-submit" type="submit">{verify_label}</button>
  <p class="muted"><a href="#" id="e-restart">{other_label}</a></p>
</form>
<div id="emsg" class="msg"></div>
<p class="muted">{note}</p>""",
        email_label=t(lang, "email"),
        hp=HONEYPOT_FIELD,
        continue_label=t(lang, "continue"),
        code_label=t(lang, "code"),
        verify_label=t(lang, "verify"),
        other_label=t(lang, "other_address"),
        note=t(lang, note_key),
    )
    strings = {
        k: t(lang, k, minutes=code_minutes)
        for k in ("code_sent", "sending", "checking", "continue", "verify")
    }
    strings.update({k: t(lang, k) for k in ("wrong_code", "too_many", "signup_closed")})
    script = f"""<script>
(function(){{
{_CSRF_JS}
const S = {_js_string(_json(strings))};
const T = JSON.parse(S);
const NEXT = {_js_string(next_url)};
const APP = {_js_string(app or "")};
const LANG = {_js_string(lang)};
let CH = {_js_string(challenge)};
let ISSUED = Date.now();
const MIN_MS = {int(min_seconds * 1000)};
const ef = document.getElementById('ef'), cf = document.getElementById('cf');
const emsg = document.getElementById('emsg');
const es = document.getElementById('e-submit'), cs = document.getElementById('c-submit');
let EMAIL = '';
function say(text, cls){{ emsg.textContent = text; emsg.className = 'msg ' + (cls || ''); }}
async function freshChallenge(){{
  if (Date.now() - ISSUED < 30 * 60 * 1000) return;
  const r = await fetch('/auth/email/challenge', {{credentials:'include'}});
  if (r.ok) {{ CH = (await r.json()).challenge; ISSUED = Date.now(); }}
}}
ef.addEventListener('submit', async (e) => {{
  e.preventDefault();
  say(''); es.disabled = true; es.textContent = T.sending;
  try {{
    await freshChallenge();
    const wait = MIN_MS - (Date.now() - ISSUED);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    EMAIL = document.getElementById('e-email').value.trim();
    const res = await postJSON('/auth/email/start', {{
      email: EMAIL, app: APP || null, next: NEXT, lang: LANG, challenge: CH,
      {HONEYPOT_FIELD}: document.getElementById('e-hp').value,
    }});
    if (res.ok) {{
      document.getElementById('e-sent').textContent = T.code_sent;
      ef.hidden = true; cf.hidden = false; document.getElementById('e-code').focus();
    }} else {{
      say(res.status === 429 ? T.too_many : (res.detail || ('Error ' + res.status)), 'err');
    }}
  }} catch (err) {{ say(err.message || 'Error', 'err'); }}
  es.disabled = false; es.textContent = T.continue;
}});
cf.addEventListener('submit', async (e) => {{
  e.preventDefault();
  say(''); cs.disabled = true; cs.textContent = T.checking;
  try {{
    const res = await postJSON('/auth/email/verify', {{
      email: EMAIL, code: document.getElementById('e-code').value,
    }});
    if (res.ok) {{ window.location.assign(NEXT || '/'); return; }}
    say(res.status === 429 ? T.too_many : res.status === 403 ? (res.detail || T.signup_closed) : T.wrong_code, 'err');
  }} catch (err) {{ say(err.message || 'Error', 'err'); }}
  cs.disabled = false; cs.textContent = T.verify;
}});
document.getElementById('e-restart').addEventListener('click', (e) => {{
  e.preventDefault(); cf.hidden = true; ef.hidden = false; say('');
  document.getElementById('e-email').focus();
}});
}})();
</script>"""
    return form + legal + provider_links + script


def _json(value) -> str:
    import json

    return json.dumps(value, ensure_ascii=False)


def render_link_page(*, lang: str) -> str:
    """The page an emailed link opens: one button that spends the token by POST.

    The token is in the URL fragment, which the browser never sends, so a GET of
    this page (a mail scanner's preview) spends nothing.
    """
    body = fill_template(
        """<div class="card">
<h1>{title}</h1>
<p style="text-align:center">{text}</p>
<button id="go" type="button">{verify}</button>
<div id="msg" class="msg"></div>
<div class="nav"><a href="/auth/login">{back}</a></div>
</div>""",
        title=t(lang, "link_title"),
        text=t(lang, "link_body"),
        verify=t(lang, "verify"),
        back=t(lang, "back"),
    )
    bad = _js_string(t(lang, "link_bad"))
    script = f"""<script>
{_CSRF_JS}
const token = new URLSearchParams(location.hash.slice(1)).get('t') || '';
history.replaceState(null, '', location.pathname);
const go = document.getElementById('go'), msg = document.getElementById('msg');
if (!token) {{ go.disabled = true; msg.textContent = {bad}; msg.className = 'msg err'; }}
go.addEventListener('click', async () => {{
  go.disabled = true;
  try {{
    const t = await csrfToken();
    const r = await fetch('/auth/email/verify', {{
      method:'POST', credentials:'include',
      headers:{{'Content-Type':'application/json','X-CSRF-Token':t}},
      body: JSON.stringify({{token}}),
    }});
    const b = await r.json().catch(() => ({{}}));
    if (r.ok) {{ window.location.assign(b.next || '/'); return; }}
    msg.textContent = r.status === 403 && b.detail ? b.detail : {bad};
    msg.className = 'msg err';
  }} catch (err) {{ msg.textContent = err.message || 'Error'; msg.className = 'msg err'; }}
}});
</script>"""
    return _page(t(lang, "link_title"), body + script, lang=lang)


def render_delete_section(*, lang: str, email: str) -> str:
    """The account page's "delete my account" card: send a code, then confirm."""
    card = fill_template(
        """<div class="card">
<h1>{title}</h1>
<p>{text}</p>
<button id="d-send" class="danger" type="button">{send}</button>
<form id="df" hidden>
  <p>{sent}</p>
  <label for="d-code">{code_label}</label>
  <input id="d-code" inputmode="numeric" autocomplete="one-time-code" maxlength="9" required>
  <button id="d-confirm" class="danger" type="submit">{confirm}</button>
</form>
<div id="dmsg" class="msg"></div>
</div>""",
        title=t(lang, "delete_title"),
        text=t(lang, "delete_body"),
        send=t(lang, "delete_send"),
        sent=t(lang, "delete_sent", email=email),
        code_label=t(lang, "code"),
        confirm=t(lang, "delete_confirm"),
    )
    texts = _js_string(
        _json({k: t(lang, k) for k in ("wrong_code", "too_many", "deleted")})
    )
    script = f"""<script>
(function(){{
const T = JSON.parse({texts});
const send = document.getElementById('d-send'), df = document.getElementById('df');
const dmsg = document.getElementById('dmsg');
function say(text, cls){{ dmsg.textContent = text; dmsg.className = 'msg ' + (cls || ''); }}
send.addEventListener('click', async () => {{
  send.disabled = true; say('');
  const res = await postJSON('/auth/account/delete/start', {{}});
  if (res.ok) {{ send.hidden = true; df.hidden = false; document.getElementById('d-code').focus(); }}
  else {{ say(res.status === 429 ? T.too_many : (res.detail || ('Error ' + res.status)), 'err'); send.disabled = false; }}
}});
df.addEventListener('submit', async (e) => {{
  e.preventDefault(); say('');
  const res = await postJSON('/auth/account/delete', {{code: document.getElementById('d-code').value}});
  if (res.ok) {{ df.hidden = true; say(T.deleted, 'ok'); setTimeout(() => window.location.assign('/'), 1500); return; }}
  say(res.status === 429 ? T.too_many : res.status === 400 ? T.wrong_code : (res.detail || ('Error ' + res.status)), 'err');
}});
}})();
</script>"""
    return card + script
