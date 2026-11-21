"""The passkey markup on the sign-in and account pages.

Both are trusted fragments the auth pages embed (``passkey_section`` on the
sign-in page, a card in ``extra_section`` on the account page). The ceremonies
run in ``/auth/passkeys/passkeys.js``; these fragments only wire buttons to it.
"""

from __future__ import annotations

import json
from html import escape

from enlace_auth.auth.pages import _NEXT_JS, _js_string
from enlace_auth.passkeys.texts import t, texts_for

_SCRIPT = '<script src="/auth/passkeys/passkeys.js"></script>'

_CSS = """<style>
.pk-list{list-style:none;padding:0;margin:0 0 16px}
.pk-list li{display:flex;justify-content:space-between;align-items:center;gap:12px;
  padding:8px 0;border-bottom:1px solid #2a2e38}
.pk-list .meta{color:#8a90a0;font-size:13px;display:block}
.pk-list button{width:auto;padding:6px 12px;margin:0}
.pk-signin{margin:0 0 16px}
</style>"""


def render_signin_section(*, lang: str, next_url: str) -> str:
    """The sign-in page's passkey button, plus passkey autofill on its email fields.

    Hidden until the script finds a browser that can use passkeys. Autofill
    (conditional mediation) is armed on load; the button aborts it and opens
    the system prompt instead. The button's request is prepared on load, so the
    prompt opens straight from the tap (Safari refuses it after a round trip).
    """
    texts = _js_string(json.dumps(texts_for(lang, ("cancelled",))))
    return f"""{_CSS}<div class="pk-signin">
<button id="pk-signin" type="button" hidden>{t(lang, "signin")}</button>
<div id="pk-msg" class="msg"></div>
</div>
{_SCRIPT}
<script>
(function(){{
{_NEXT_JS}
const P = window.enlacePasskeys, T = JSON.parse({texts});
const NEXT = {_js_string(next_url)};
if (!P || !P.supported()) return;
const btn = document.getElementById('pk-signin'), msg = document.getElementById('pk-msg');
btn.hidden = false;
let ctrl = null, prepared = null;
function arm() {{ P.prepareSignIn().then((p) => {{ prepared = p; }}, () => {{ prepared = null; }}); }}
function go(next) {{ window.location.assign(nextUrl(next || NEXT)); }}
function say(text) {{ msg.textContent = text || ''; msg.className = 'msg' + (text ? ' err' : ''); }}
async function autofill() {{
  if (!(await P.conditionalAvailable())) return;
  document.querySelectorAll('input[type=email]').forEach((i) => {{
    const ac = i.getAttribute('autocomplete') || 'username';
    if (!/webauthn/.test(ac)) i.setAttribute('autocomplete', ac + ' webauthn');
  }});
  ctrl = new AbortController();
  try {{ const r = await P.signIn({{conditional: true, signal: ctrl.signal, next: NEXT}}); go(r.next); }}
  catch (e) {{ if (e.name !== 'AbortError' && e.name !== 'NotAllowedError') say(e.message); }}
}}
btn.addEventListener('click', async () => {{
  if (ctrl) ctrl.abort();
  say('');
  const p = prepared; prepared = null;
  try {{ const r = await P.signIn({{next: NEXT, prepared: p}}); go(r.next); }}
  catch (e) {{ say(e.name === 'NotAllowedError' ? T.cancelled : e.message); arm(); autofill(); }}
}});
arm();
autofill();
}})();
</script>"""


def render_account_section(*, lang: str) -> str:
    """The account page's passkey card: the list, add, remove, sign in again.

    The add request is prepared when the page loads (and again after each use),
    so the system prompt opens straight from the tap, as Safari requires; a
    refusal there (an old or password sign-in) shows "sign in again" at once.
    """
    keys = (
        "none_yet",
        "added",
        "adding",
        "add",
        "remove",
        "removed",
        "confirm_remove",
        "cancelled",
        "unsupported",
        "required_note",
        "enforced_note",
        "created",
        "last_used",
        "never_used",
        "synced",
        "for_purpose",
    )
    texts = _js_string(json.dumps(texts_for(lang, keys)))
    return f"""{_CSS}<div class="card" id="pk-card">
<h1>{t(lang, "card_title")}</h1>
<p>{t(lang, "card_body")}</p>
<p id="pk-policy" class="muted" hidden></p>
<ul id="pk-list" class="pk-list"></ul>
<label for="pk-name">{t(lang, "name_label")}</label>
<input id="pk-name" maxlength="60" autocomplete="off">
<button id="pk-add" type="button">{t(lang, "add")}</button>
<button id="pk-reauth" type="button" hidden>{t(lang, "reauth")}</button>
<div id="pk-msg" class="msg"></div>
</div>
{_SCRIPT}
<script>
(function(){{
const P = window.enlacePasskeys, T = JSON.parse({texts});
const list = document.getElementById('pk-list'), msg = document.getElementById('pk-msg');
const add = document.getElementById('pk-add'), reauth = document.getElementById('pk-reauth');
const nameInput = document.getElementById('pk-name'), policy = document.getElementById('pk-policy');
function say(text, cls) {{ msg.textContent = text || ''; msg.className = 'msg ' + (cls || ''); }}
function when(ts) {{ return ts ? new Date(ts * 1000).toLocaleDateString() : ''; }}
function guessName() {{
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  if (/Macintosh/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  return '';
}}
function failed(e) {{
  if (e.name === 'NotAllowedError') return say(T.cancelled, 'err');
  if (e.name === 'InvalidStateError') return say(e.message, 'err');
  say(e.message, 'err');
  reauth.hidden = !e.reauth;
}}
async function refresh() {{
  const data = await P.list();
  list.textContent = '';
  if (!data.passkeys.length) {{
    const li = document.createElement('li'); li.textContent = T.none_yet; list.appendChild(li);
  }}
  data.passkeys.forEach((pk) => {{
    const li = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = pk.name;
    const meta = document.createElement('span'); meta.className = 'meta';
    meta.textContent = T.created + ' ' + when(pk.created_at) + ' · ' +
      (pk.last_used_at ? T.last_used + ' ' + when(pk.last_used_at) : T.never_used) +
      (pk.synced ? ' · ' + T.synced : '') +
      (pk.purpose ? ' · ' + T.for_purpose.replace('{{purpose}}', pk.purpose) : '');
    label.appendChild(meta);
    const rm = document.createElement('button'); rm.type = 'button'; rm.className = 'danger';
    rm.textContent = T.remove;
    rm.addEventListener('click', async () => {{
      if (!window.confirm(T.confirm_remove.replace('{{name}}', pk.name))) return;
      try {{ await P.remove(pk.id); say(T.removed, 'ok'); refresh(); }} catch (e) {{ failed(e); }}
    }});
    li.appendChild(label); li.appendChild(rm); list.appendChild(li);
  }});
  if (data.enforced) {{ policy.textContent = T.enforced_note; policy.hidden = false; }}
  else if (data.required) {{
    policy.textContent = T.required_note.replace('{{n}}', data.enforce_from); policy.hidden = false;
  }}
}}
let prepared = null;
async function arm() {{
  try {{ prepared = await P.prepareRegister(); reauth.hidden = true; }}
  catch (e) {{ prepared = null; if (e.reauth) {{ say(e.message, 'err'); reauth.hidden = false; }} }}
}}
nameInput.value = guessName();
add.addEventListener('click', async () => {{
  add.disabled = true; say(T.adding);
  const p = prepared; prepared = null;
  try {{ await P.register(nameInput.value, p); say(T.added, 'ok'); refresh(); }}
  catch (e) {{ failed(e); }}
  add.disabled = false;
  arm();
}});
if (!P || !P.supported()) {{ add.disabled = true; say(T.unsupported, 'err'); }}
else arm();
reauth.addEventListener('click', async () => {{
  try {{ await P.signOut(); }} catch (e) {{ /* signed out already */ }}
  window.location.assign('/auth/login?next=%2Fauth%2Faccount');
}});
refresh().catch((e) => say(e.message, 'err'));
}})();
</script>"""


#: The fragment key the confirmation page hands a proof back under.
PROOF_FRAGMENT = "enlace_step_up"


def render_confirm_section(
    *, lang: str, request_id: str, action: str, audience: str, return_url: str
) -> str:
    """The platform's confirmation page body: the action, as the backend wrote it.

    The text comes from the signed request, never from a page, and the proof is
    minted for that request only. On success the browser goes to *return_url*
    (already checked with ``safe_next``) with the proof in its fragment, which
    never reaches a server log; with no *return_url* the page says it is done.
    """
    texts = _js_string(
        json.dumps(texts_for(lang, ("confirm_waiting", "confirm_done", "cancelled")))
    )
    return f"""{_CSS}<div class="card" id="pk-confirm">
<h1>{escape(t(lang, "confirm_title"))}</h1>
<p>{escape(t(lang, "confirm_asks", audience=audience))}</p>
<p class="pk-action"><strong>{escape(action)}</strong></p>
<button id="pk-go" type="button" hidden>{escape(t(lang, "confirm_button"))}</button>
<div id="pk-msg" class="msg"></div>
</div>
{_SCRIPT}
<script>
(function(){{
const P = window.enlacePasskeys, T = JSON.parse({texts});
const REQ = {_js_string(request_id)}, BACK = {_js_string(return_url)};
const btn = document.getElementById('pk-go'), msg = document.getElementById('pk-msg');
function say(text, cls) {{ msg.textContent = text || ''; msg.className = 'msg ' + (cls || ''); }}
if (!P || !P.supported()) return;
let prepared = null;
function arm() {{
  P.prepareStepUp({{request: REQ}}).then(
    (p) => {{ prepared = p; btn.hidden = false; }},
    (e) => say(e.message, 'err'));
}}
btn.addEventListener('click', async () => {{
  btn.disabled = true; say(T.confirm_waiting);
  try {{
    const r = await P.stepUp(prepared);
    btn.hidden = true;
    if (BACK) {{
      window.location.assign(BACK.split('#')[0] + '#{PROOF_FRAGMENT}=' + encodeURIComponent(r.proof));
      return;
    }}
    say(T.confirm_done, 'ok');
  }} catch (e) {{
    say(e.name === 'NotAllowedError' ? T.cancelled : e.message, 'err');
    prepared = null; btn.disabled = false; arm();
  }}
}});
arm();
}})();
</script>"""
