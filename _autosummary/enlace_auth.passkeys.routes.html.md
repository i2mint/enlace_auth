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
- `POST   /auth/passkeys/step-up/request`   a backend’s `{email, action, audience,
  return_url?}` with `Authorization: Bearer <audience key>`: `{request,
  confirm_url, expires_in}`
- `GET    /auth/passkeys/confirm?r=<request>` the platform’s confirmation page
- `POST   /auth/passkeys/step-up/options`   `{action}` or `{request}`: options
  bound to the action (and the request’s audience)
- `POST   /auth/passkeys/step-up/verify`    `{action | request, credential}`:
  `{proof, ...}`
- `POST   /auth/passkeys/step-up/redeem`    `{proof, action, email, audience?,
  methods?}`: spends it
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
account it expects; the answer (`{email, action, audience, verified_at, method,
passkey}`) comes once.

Two ways to ask for a step-up (i2mint/enlace_auth#95). A page may still call
`step-up/options {action}` itself; such a proof carries no audience, so a
backend that names its audience refuses it. The strong way: the backend creates
the request (`step-up/request`, CSRF-exempt, authenticated by the audience key
`enlace-auth step-up-key AUDIENCE` prints), and the browser opens the
platform’s `/auth/passkeys/confirm` page, which shows the backend’s action and
audience and mints one proof that only that audience redeems. No page chooses
the action a proof is for, and the page refuses to be framed. What the person
sees is guaranteed only when `/auth` is on an origin no app shares (see
[`enlace_auth.auth.step_up`](enlace_auth.auth.step_up.html.md#module-enlace_auth.auth.step_up)).

### Module Attributes

| [`REDEEM_PATH`](#enlace_auth.passkeys.routes.REDEEM_PATH)   | The redeem endpoint, which the plugin exempts from the CSRF check.         |
|----------------------------------------------------------------|----------------------------------------------------------------------------|
| [`REQUEST_PATH`](#enlace_auth.passkeys.routes.REQUEST_PATH)  | The backend's request endpoint, exempt likewise (a bearer key, no cookie). |
| [`REAUTH_HEADER`](#enlace_auth.passkeys.routes.REAUTH_HEADER) | Set on a 403 that a fresh sign-in would turn into a success.               |

### Functions

| [`make_passkey_router`](#enlace_auth.passkeys.routes.make_passkey_router)(\*, service, ...[, ...])   | Build the passkey router.   |
|-------------------------------------------------------------------------------------------------|-----------------------------|

### enlace_auth.passkeys.routes.REAUTH_HEADER *= 'X-Enlace-Reauth'*

Set on a 403 that a fresh sign-in would turn into a success.

### enlace_auth.passkeys.routes.REDEEM_PATH *= '/auth/passkeys/step-up/redeem'*

The redeem endpoint, which the plugin exempts from the CSRF check.

### enlace_auth.passkeys.routes.REQUEST_PATH *= '/auth/passkeys/step-up/request'*

The backend’s request endpoint, exempt likewise (a bearer key, no cookie).

### enlace_auth.passkeys.routes.make_passkey_router(\*, service, session_store, user_store, signing_key, relying_party, policy=None, send_email=None, on_credentials_changed=None, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, cookie_domain=None, fresh_seconds=900, public_base_url=None, pick_lang=<function <lambda>>)

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
  * **cookie_domain** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – `[auth] cookie_domain` (#94), for the session cookie a
    passkey sign-in sets and the `next` it may return to.
  * **fresh_seconds** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – how recent a sign-in must be to add or remove a passkey.
  * **public_base_url** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – the site named in notices (else the request’s base URL).
  * **pick_lang** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]], [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – `(accept-language header) -> lang` for the notices.
* **Return type:**
  `APIRouter`
