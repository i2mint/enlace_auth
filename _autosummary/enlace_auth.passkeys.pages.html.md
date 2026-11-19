# enlace_auth.passkeys.pages

The passkey markup on the sign-in and account pages.

Both are trusted fragments the auth pages embed (`passkey_section` on the
sign-in page, a card in `extra_section` on the account page). The ceremonies
run in `/auth/passkeys/passkeys.js`; these fragments only wire buttons to it.

### Functions

| [`render_account_section`](#enlace_auth.passkeys.pages.render_account_section)(\*, lang)          | The account page's passkey card: the list, add, remove, sign in again.        |
|--------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`render_signin_section`](#enlace_auth.passkeys.pages.render_signin_section)(\*, lang, next_url) | The sign-in page's passkey button, plus passkey autofill on its email fields. |

### enlace_auth.passkeys.pages.render_account_section(, lang)

The account page’s passkey card: the list, add, remove, sign in again.

The add request is prepared when the page loads (and again after each use),
so the system prompt opens straight from the tap, as Safari requires; a
refusal there (an old or password sign-in) shows “sign in again” at once.

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
