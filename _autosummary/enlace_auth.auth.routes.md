# enlace_auth.auth.routes

Auth HTTP routes: register, login, logout, shared-login, csrf, recovery.

This router serves both the JSON API (`POST /auth/login` etc., consumed by
app frontends) and the browser-facing HTML pages (`GET /auth/login`,
`GET /auth/account`, the password-recovery screens) so the platform is usable
from a bare URL with no app frontend in the way.

The three ways a password can be set, and who can use each:

- `GET /auth/account` — a signed-in user changing their own.
- `GET /auth/forgot-password` — a locked-out user, *if* SMTP is configured.
- `enlace-auth reset-link` — an admin, handing a link over out-of-band.

The last exists because the middle one needs a mail server. Without one the
forgot-password page says so plainly instead of promising an email that is only
written to the log.

OAuth routes live in `enlace.auth.oauth` and are attached separately so the
Authlib dependency stays lazy.

### Functions

| [`make_auth_router`](#enlace_auth.auth.routes.make_auth_router)(\*, session_store, ...[, ...])   | Build a FastAPI router exposing `/auth/*` endpoints.   |
|----------------------------------------------------------------------------------------------------|--------------------------------------------------------|

### enlace_auth.auth.routes.make_auth_router(\*, session_store, user_store, signing_key, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, shared_password_for=<function <lambda>>, can_register=<function <lambda>>, send_email=None, reset_token_max_age=1800, public_base_url=None, on_credentials_changed=None)

Build a FastAPI router exposing `/auth/*` endpoints.

* **Parameters:**
  * **user_store** (*session_store /*) – backing stores.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – HMAC key for session, CSRF, shared, and reset tokens.
  * **secure_cookies** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – session-cookie policy.
  * **shared_password_for** ([`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]]) – maps an app id to its shared-password hash.
  * **can_register** ([`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]) – predicate gating self-registration by email.
  * **send_email** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`EmailSender`](enlace_auth.auth.email.md#enlace_auth.auth.email.EmailSender)]) – delivers password-reset emails. `None` means no delivery
    channel is configured: the flow falls back to the console sender
    (which logs the link) *and* the forgot-password page says so, rather
    than telling the user to check an inbox nothing was sent to.
  * **reset_token_max_age** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – lifetime of an emailed password-reset link, in
    seconds (default 30 minutes). Links an admin mints by hand carry
    their own, longer lifetime — see `enlace_auth.auth.reset_tokens`.
  * **public_base_url** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – the platform’s public origin (`https://example.com`),
    used to build the link in a password-reset email. Set it in any
    deployment: without it the link is built from the request’s
    `Host` header, which the requester controls – a forged `Host`
    would mail the victim a link that hands their reset token to
    another site, unless a proxy in front only forwards known hosts.
  * **on_credentials_changed** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`CredentialsChanged`](enlace_auth.auth.revocation.md#enlace_auth.auth.revocation.CredentialsChanged)]) – `hook(email, *, keep=None)` called after a
    password change or reset. Defaults to revoking the account’s
    browser sessions only; the plugin injects one that also revokes the
    account’s OAuth connector refresh families (see
    `enlace_auth.auth.revocation`).
* **Return type:**
  `APIRouter`
