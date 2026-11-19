# enlace_auth.passkeys.routes

`/auth/passkeys/*`: add, list and remove passkeys; sign in; step up; redeem.

Endpoints (every POST and DELETE is CSRF-checked like the rest of `/auth`,
except `step-up/redeem`, see below):

- `GET    /auth/passkeys`                   the account’s passkeys and policy
- `POST   /auth/passkeys/register/options`  creation options (fresh sign-in needed)
- `POST   /auth/passkeys/register/verify`   `{credential, name}`: stores the passkey
- `DELETE /auth/passkeys/{id}`              removes one (fresh sign-in needed)
- `POST   /auth/passkeys/login/options`     request options for a sign-in by passkey
- `POST   /auth/passkeys/login/verify`      `{credential, next?}`: opens a session
- `POST   /auth/passkeys/step-up/options`   `{action}`: options bound to the action
- `POST   /auth/passkeys/step-up/verify`    `{action, credential}`: `{proof, ...}`
- `POST   /auth/passkeys/step-up/redeem`    `{proof, action, email}`: spends it
- `GET    /auth/passkeys/passkeys.js`       the browser helper, `enlacePasskeys`

Adding or removing a passkey needs a session opened within `fresh_seconds`:
a stolen session cookie should not be enough to plant a passkey or delete the
owner’s. The refusal then carries an `X-Enlace-Reauth: 1` header so a page
can offer to sign in again. Both mail the account a notice; a removal also ends
the account’s other sessions and connector refresh families
(`on_credentials_changed`).

`step-up/redeem` is called by a backend, not a browser: no cookie
authenticates it, the proof in the body is the credential, so it is exempt from
the CSRF double-submit (the plugin lists it). The caller names the action AND the
account it expects; the answer (`{email, action, verified_at, method,
passkey}`) comes once.

### Module Attributes

| [`REDEEM_PATH`](#enlace_auth.passkeys.routes.REDEEM_PATH)   | The redeem endpoint, which the plugin exempts from the CSRF check.   |
|----------------------------------------------------------------|----------------------------------------------------------------------|
| [`REAUTH_HEADER`](#enlace_auth.passkeys.routes.REAUTH_HEADER) | Set on a 403 that a fresh sign-in would turn into a success.         |

### Functions

| [`make_passkey_router`](#enlace_auth.passkeys.routes.make_passkey_router)(\*, service, ...[, ...])   | Build the passkey router.   |
|-------------------------------------------------------------------------------------------------|-----------------------------|

### enlace_auth.passkeys.routes.REAUTH_HEADER *= 'X-Enlace-Reauth'*

Set on a 403 that a fresh sign-in would turn into a success.

### enlace_auth.passkeys.routes.REDEEM_PATH *= '/auth/passkeys/step-up/redeem'*

The redeem endpoint, which the plugin exempts from the CSRF check.

### enlace_auth.passkeys.routes.make_passkey_router(\*, service, session_store, user_store, signing_key, relying_party, policy=None, send_email=None, on_credentials_changed=None, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, fresh_seconds=900, public_base_url=None, pick_lang=<function <lambda>>)

Build the passkey router. See the module docstring for the endpoints.

* **Parameters:**
  * **service** ([`PasskeyService`](enlace_auth.passkeys.core.html.md#enlace_auth.passkeys.core.PasskeyService)) – the ceremonies and records (`PasskeyService`).
  * **user_store** (*session_store /*) – the platform’s sessions and accounts.
  * **relying_party** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[`Request`], [`RelyingParty`](enlace_auth.passkeys.core.html.md#enlace_auth.passkeys.core.RelyingParty)]) – `(request) -> RelyingParty`; the plugin pins it to the
    platform’s public origin, a test may derive it from the request.
  * **policy** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`PasskeyPolicy`](enlace_auth.passkeys.core.html.md#enlace_auth.passkeys.core.PasskeyPolicy)]) – who must sign in by passkey (default: nobody).
  * **send_email** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[`...`](https://docs.python.org/3/builtins/constants.html#Ellipsis), [`Any`](https://docs.python.org/3/library/typing.html#typing.Any)]]) – `send(to=, subject=, body=)` for add/remove notices
    (`None`: no notice).
  * **on_credentials_changed** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[`...`](https://docs.python.org/3/builtins/constants.html#Ellipsis), [`Any`](https://docs.python.org/3/library/typing.html#typing.Any)]]) – `hook(email, *, keep=None)` run after a
    removal (default: none; the plugin passes the platform’s).
  * **fresh_seconds** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – how recent a sign-in must be to add or remove a passkey.
  * **public_base_url** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – the site named in notices (else the request’s base URL).
  * **pick_lang** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]], [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – `(accept-language header) -> lang` for the notices.
* **Return type:**
  `APIRouter`
