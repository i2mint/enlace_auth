# enlace_auth.auth

Authentication subsystem for enlace.

Apps never import from here. The contract exposed to mounted apps is just
`request.state.user_id` and (optionally) `request.state.user_email`.

Public helpers:

- `PlatformAuthMiddleware` — pure-ASGI auth middleware.
- `CSRFMiddleware` — signed double-submit CSRF.
- `SessionStore` — MutableMapping-backed session storage.
- `GrantStore` — MutableMapping-backed runtime per-app access grants.
- `hash_password` / `verify_password` — argon2id helpers.
- `make_auth_router` — FastAPI router for `/auth/*` endpoints.

### Functions

| [`hash_password`](#enlace_auth.auth.hash_password)(password)                         | Return an argon2id hash string for `password`.                     |
|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| [`make_auth_router`](#enlace_auth.auth.make_auth_router)(\*, session_store, ...[, ...]) | Build a FastAPI router exposing `/auth/*` endpoints.               |
| [`parse_expires_at`](#enlace_auth.auth.parse_expires_at)(value, \*[, now])              | Coerce a user-supplied expiry into epoch seconds (UTC), or `None`. |
| [`sign_cookie`](#enlace_auth.auth.sign_cookie)(value, signing_key, \*[, salt])     | Return a signed, URL-safe token carrying `value`.                  |
| [`verify_cookie`](#enlace_auth.auth.verify_cookie)(token, signing_key, \*[, ...])    | Return the original value iff the token is valid and unexpired.    |
| [`verify_password`](#enlace_auth.auth.verify_password)(hashed, password)               | Return True iff `password` matches the stored `hashed` value.      |

### Classes

| [`AccessRule`](#enlace_auth.auth.AccessRule)(prefix, level, app_id[, ...])           | Auth policy for a single mount prefix.                              |
|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| [`CSRFMiddleware`](#enlace_auth.auth.CSRFMiddleware)(app, \*, signing_key[, ...])        | Signed double-submit CSRF for state-changing requests.              |
| [`GrantStore`](#enlace_auth.auth.GrantStore)(backend, \*[, root])                    | Thin adapter over a `MutableMapping` that speaks grant semantics.   |
| [`PlatformAuthMiddleware`](#enlace_auth.auth.PlatformAuthMiddleware)(app, \*, access_rules, ...) | Pure-ASGI auth middleware.                                          |
| [`SessionStore`](#enlace_auth.auth.SessionStore)(store, \*[, max_age, ...])            | Thin adapter around a MutableMapping that speaks session semantics. |

### *class* enlace_auth.auth.AccessRule(prefix, level, app_id, shared_password_hash=None, allowed_users=())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Auth policy for a single mount prefix.

### *class* enlace_auth.auth.CSRFMiddleware(app, , signing_key, cookie_name='enlace_csrf', header_name='X-CSRF-Token', exempt_prefixes=('/auth/callback', '/auth/login/', '/api/'))

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Signed double-submit CSRF for state-changing requests.

On safe-method requests, sets an `enlace_csrf` cookie if one isn’t
present. On state-changing requests, requires the cookie and an
`X-CSRF-Token` header to match after signature verification.

Exempt paths skip the check entirely. Defaults exempt sub-app APIs
under `/api/` because the `enlace_session` cookie is `SameSite=Lax`:
a cross-site POST from an attacker site arrives without credentials and
is rejected by PlatformAuthMiddleware regardless of CSRF. This keeps
pre-enlace apps working out of the box without each having to implement
the `/auth/csrf` double-submit flow. The auth endpoints themselves
(`/auth/login`, `/auth/register`, `/auth/logout`) stay protected.

### *class* enlace_auth.auth.GrantStore(backend, , root=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Thin adapter over a `MutableMapping` that speaks grant semantics.

* **Parameters:**
  * **backend** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – the per-name store (e.g. `factory("grants")`).
  * **root** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path)]) – the resolved filesystem directory backing `backend`
    (`.../grants`). Used ONLY for efficient per-app listing
    (`root/{app_id}/*`). All reads/writes go through `backend` so the
    storage codec stays in one place. When `None` (e.g. a dict backend
    in tests), listing falls back to filtering the backend’s keys.

#### active_emails_for_app(app_id, , now=None)

The set of currently-active granted emails for `app_id` (hot path).

* **Return type:**
  [`set`](https://docs.python.org/3/builtins/stdtypes.html#set)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### grant(app_id, email, , expires_at=None, granted_by=None, note=None, now=None)

Create or replace a grant. `expires_at` is epoch seconds UTC or None.

Use [`parse_expires_at()`](#enlace_auth.auth.parse_expires_at) to turn a date/ISO string into `expires_at`
before calling this.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list_all()

All grant records across all apps. Admin-only / infrequent.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

### *class* enlace_auth.auth.PlatformAuthMiddleware(app, , access_rules, session_store, signing_key, cookie_name='enlace_session', max_age=86400, auth_path_prefix='/auth', login_redirect_path='/', dynamic_allowed_users=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI auth middleware. See module docstring for behavior.

### *class* enlace_auth.auth.SessionStore(store, , max_age=None, sweep_batch=100, sweep_interval=3600.0)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Thin adapter around a MutableMapping that speaks session semantics.

#### revoke_user(user, , keep=None)

Delete every session belonging to *user*; return how many went.

A session is matched on its `user_id` or its `email`,
case-insensitively (emails are the platform’s user ids, and a record
written before lower-casing was consistent must still be caught).
*keep* names one session id to spare – the browser that just changed
its own password stays signed in while every other copy of the
account is logged out.

Call this whenever an account’s credentials change hands: deletion,
an admin password reset, a self-service change, a reset-link redemption.
Without it a session outlives the change for the full cookie lifetime.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### sweep_expired(, now=None)

Delete up to *sweep_batch* records older than *max_age*; return count.

No-op without a *max_age*. A cursor carries the position across calls
(wrapping at the end) so successive sweeps walk the whole store. A
record without a numeric `created_at` is left alone.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### enlace_auth.auth.hash_password(password)

Return an argon2id hash string for `password`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.make_auth_router(\*, session_store, user_store, signing_key, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, shared_password_for=<function <lambda>>, can_register=<function <lambda>>, send_email=None, reset_token_max_age=1800, public_base_url=None, on_credentials_changed=None)

Build a FastAPI router exposing `/auth/*` endpoints.

* **Parameters:**
  * **user_store** (*session_store /*) – backing stores.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – HMAC key for session, CSRF, shared, and reset tokens.
  * **secure_cookies** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – session-cookie policy.
  * **shared_password_for** ([`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]]) – maps an app id to its shared-password hash.
  * **can_register** ([`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]) – predicate gating self-registration by email.
  * **send_email** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`EmailSender`](enlace_auth.auth.email.html.md#enlace_auth.auth.email.EmailSender)]) – delivers password-reset emails. `None` means no delivery
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
  * **on_credentials_changed** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`CredentialsChanged`](enlace_auth.auth.revocation.html.md#enlace_auth.auth.revocation.CredentialsChanged)]) – `hook(email, *, keep=None)` called after a
    password change or reset. Defaults to revoking the account’s
    browser sessions only; the plugin injects one that also revokes the
    account’s OAuth connector refresh families (see
    `enlace_auth.auth.revocation`).
* **Return type:**
  `APIRouter`

### enlace_auth.auth.parse_expires_at(value, , now=None)

Coerce a user-supplied expiry into epoch seconds (UTC), or `None`.

Accepts:

- `None` / empty string → `None` (never expires).
- a number → treated as epoch seconds, returned as a float.
- `"YYYY-MM-DD"` → **end of that day UTC** (`23:59:59`), so the grant is
  valid through the whole named day (least-surprising “expires on this date”).
- a full ISO-8601 timestamp (`...THH:MM[:SS][±TZ|Z]`) → that instant. A
  trailing `Z` is honored (Python 3.10’s `fromisoformat` can’t) and a
  naive timestamp is assumed to be UTC.

Raises `GrantError` for unparseable input or an already-past expiry.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`float`](https://docs.python.org/3/builtins/functions.html#float)]

### enlace_auth.auth.sign_cookie(value, signing_key, , salt='enlace-cookie')

Return a signed, URL-safe token carrying `value`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.verify_cookie(token, signing_key, , max_age=None, salt='enlace-cookie')

Return the original value iff the token is valid and unexpired.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.verify_password(hashed, password)

Return True iff `password` matches the stored `hashed` value.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### Modules

| [`cookies`](enlace_auth.auth.cookies.html.md#module-enlace_auth.auth.cookies)           | Signed cookie helpers built on itsdangerous.                                        |
|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| [`email`](enlace_auth.auth.email.html.md#module-enlace_auth.auth.email)               | Outbound email for enlace_auth — used by the password-recovery flow.                |
| [`grants`](enlace_auth.auth.grants.html.md#module-enlace_auth.auth.grants)             | Runtime per-app access grants, with optional UTC expiry.                            |
| [`middleware`](enlace_auth.auth.middleware.html.md#module-enlace_auth.auth.middleware)     | Platform auth middleware (pure ASGI).                                               |
| [`oauth`](enlace_auth.auth.oauth.html.md#module-enlace_auth.auth.oauth)               | OAuth2/OIDC login via Authlib.                                                      |
| [`oauth_server`](enlace_auth.auth.oauth_server.html.md#module-enlace_auth.auth.oauth_server) | OAuth 2.1 authorization server — issue tokens for MCP custom connectors.            |
| [`pages`](enlace_auth.auth.pages.html.md#module-enlace_auth.auth.pages)               | HTML pages for the enlace_auth browser-facing flows.                                |
| [`passwords`](enlace_auth.auth.passwords.html.md#module-enlace_auth.auth.passwords)       | Password hashing via argon2id.                                                      |
| [`reset_tokens`](enlace_auth.auth.reset_tokens.html.md#module-enlace_auth.auth.reset_tokens) | Password-reset tokens — minting, verification, and the link they live in.           |
| [`revocation`](enlace_auth.auth.revocation.html.md#module-enlace_auth.auth.revocation)     | Credential revocation: end everything an account holds when its credentials change. |
| [`routes`](enlace_auth.auth.routes.html.md#module-enlace_auth.auth.routes)             | Auth HTTP routes: register, login, logout, shared-login, csrf, recovery.            |
| [`sessions`](enlace_auth.auth.sessions.html.md#module-enlace_auth.auth.sessions)         | Session storage backed by a MutableMapping.                                         |
