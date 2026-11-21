# enlace_auth.passkeys.pages

The passkey markup on the sign-in and account pages.

Both are trusted fragments the auth pages embed (`passkey_section` on the
sign-in page, a card in `extra_section` on the account page). The ceremonies
run in `/auth/passkeys/passkeys.js`; these fragments only wire buttons to it.

### Module Attributes

| [`PROOF_FRAGMENT`](#enlace_auth.passkeys.pages.PROOF_FRAGMENT)   | The fragment key the confirmation page hands a proof back under.   |
|-------------------------------------------------------------------|--------------------------------------------------------------------|

### Functions

| [`render_account_section`](#enlace_auth.passkeys.pages.render_account_section)(\*, lang)                  | The account page's passkey card: the list, add, remove, sign in again.        |
|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`render_confirm_section`](#enlace_auth.passkeys.pages.render_confirm_section)(\*, lang, request_id, ...) | The platform's confirmation page body: the action, as the backend wrote it.   |
| [`render_signin_section`](#enlace_auth.passkeys.pages.render_signin_section)(\*, lang, next_url)         | The sign-in page's passkey button, plus passkey autofill on its email fields. |

### enlace_auth.passkeys.pages.PROOF_FRAGMENT *= 'enlace_step_up'*

The fragment key the confirmation page hands a proof back under.

### enlace_auth.passkeys.pages.render_account_section(, lang)

The account page’s passkey card: the list, add, remove, sign in again.

The add request is prepared when the page loads (and again after each use),
so the system prompt opens straight from the tap, as Safari requires; a
refusal there (an old or password sign-in) shows “sign in again” at once.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.pages.render_confirm_section(, lang, request_id, action, audience, return_url)

The platform’s confirmation page body: the action, as the backend wrote it.

The text comes from the signed request, never from a page, and the proof is
minted for that request only. On success the browser goes to *return_url*
(already checked with `safe_next`) with the proof in its fragment, which
never reaches a server log; with no *return_url* the page says it is done.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.pages.render_signin_section(, lang, next_url)

The sign-in page’s passkey button, plus passkey autofill on its email fields.

Hidden until the script finds a browser that can use passkeys. Autofill
(conditional mediation) is armed on load; the button aborts it and opens
the system prompt instead. The button’s request is prepared on load, so the
prompt opens straight from the tap (Safari refuses it after a round trip).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
