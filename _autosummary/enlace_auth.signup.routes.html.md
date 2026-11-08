# enlace_auth.signup.routes

`/auth/email/*`, the verify-first `/auth/register`, and self-service deletion.

Verify before create. No user record is written until the address has proved
it receives mail: `start` mails a one-time code, `verify` spends it and then
signs in an existing account or creates the new one. That closes the two gaps
of a register-then-verify flow: answering whether an address has an account
(enumeration), and an attacker creating an account for a victim’s address
before the victim does (pre-hijacking).

The code is bound to the browser that asked for it. `start` sets an HttpOnly
cookie holding a fresh random nonce, the pending code is stored under it, and
`verify` finds the code only through that cookie (refused when the request
carries it twice). Only the newest code of a browser works. So a sign-up is finished by
the browser that began it: nobody can register a victim’s address with their
own password and wait for the victim to verify it, and nobody can sign a
victim’s browser into an account of theirs by sending a link. A stranger asking
for codes for an address replaces only their own pending code, never the
owner’s.

`start` answers every address the same way, byte for byte, and does the same
work for each: it always stores a pending code (a decoy that can never verify
for an address the policy refuses, or for an admin account) and always mails in
the background. Only the mail differs: a code, or a short “sign-up here is by
invitation” notice. A submission failing the bot check gets the same answer and
no mail. Rate limits answer 429; they count hits, not accounts.

Endpoints, all CSRF-checked like every other `/auth` POST:

- `GET  /auth/email/challenge`     a bot-check token for an API client’s form
- `POST /auth/email/start`         `{email, app?, next?, lang?, challenge, website}`
- `POST /auth/email/verify`        `{email, code}` or `{token}` (the emailed link)
- `GET  /auth/email/link`          the link’s landing page (token in the fragment)
- `POST /auth/register`            `{email, password, ...}`: `start` that also
  sets a password on the account it creates
- `POST /auth/account/delete/start`  mails the signed-in account a confirmation code
- `POST /auth/account/delete`      `{code}`: deletes it

### Module Attributes

| [`SIGNUP_MIN_PASSWORD_LEN`](#enlace_auth.signup.routes.SIGNUP_MIN_PASSWORD_LEN)   | a password that is the only factor needs at least 15.                         |
|----------------------------------------------------------------------------|-------------------------------------------------------------------------------|
| [`SIGNUP_MAX_PASSWORD_LEN`](#enlace_auth.signup.routes.SIGNUP_MAX_PASSWORD_LEN)   | Longer than any passphrase, short enough that hashing it costs nothing extra. |
| [`NONCE_COOKIE`](#enlace_auth.signup.routes.NONCE_COOKIE)              | The cookie naming the browser a pending code belongs to.                      |
| [`ACCEPTED`](#enlace_auth.signup.routes.ACCEPTED)                  | The one answer `start` and `register` give to every address.                  |

### Functions

| [`make_limit_gates`](#enlace_auth.signup.routes.make_limit_gates)(rate_limiter[, limits])       | `(mail_allowed, verify_allowed)`, each `(email, client_ip) -> bool`.   |
|-------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| [`make_signup_router`](#enlace_auth.signup.routes.make_signup_router)(\*, user_store, ...[, ...]) | Build the sign-up router.                                              |

### enlace_auth.signup.routes.ACCEPTED *= {'detail': 'If this address can sign in here, a code is on its way.', 'ok': True}*

The one answer `start` and `register` give to every address.

### enlace_auth.signup.routes.NONCE_COOKIE *= 'enlace_signup'*

The cookie naming the browser a pending code belongs to.

### enlace_auth.signup.routes.SIGNUP_MAX_PASSWORD_LEN *= 1024*

Longer than any passphrase, short enough that hashing it costs nothing extra.

### enlace_auth.signup.routes.SIGNUP_MIN_PASSWORD_LEN *= 15*

a password that is the only factor needs at least 15.

* **Type:**
  NIST SP 800-63B-4

### enlace_auth.signup.routes.make_limit_gates(rate_limiter, limits=None)

`(mail_allowed, verify_allowed)`, each `(email, client_ip) -> bool`.

*mail_allowed* (`kind=` `signin`, `reset` or `delete`) charges the
address, the IP and the overall budget of that kind of mail, so flooding one
kind cannot stop the others. *verify_allowed* charges the address-and-IP pair,
the IP, and the overall budget of code checks: keyed on the pair, so a
stranger’s wrong guesses do not lock the owner out, and the overall budget
bounds how many guesses all clients together get. Every key is charged even
after one is over, or a client at one cap would stop counting against the
others.

```pycon
>>> mail, _ = make_limit_gates(SlidingWindowLimiter({}), {"mail_per_address": 1})
>>> mail("a@x.io", "1.2.3.4"), mail("a@x.io", "5.6.7.8"), mail("b@x.io", "5.6.7.8")
(True, False, True)
>>> mail("a@x.io", "1.2.3.4", kind="reset")
True
```

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[`...`](https://docs.python.org/3/builtins/constants.html#Ellipsis), [`bool`](https://docs.python.org/3/builtins/functions.html#bool)], [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]

### enlace_auth.signup.routes.make_signup_router(\*, user_store, session_store, signing_key, send_email, policy=None, codes=None, rate_limiter=None, bot_check=None, limits=None, client_ip=<function \_peer_host>, known_apps=(), delete_account=None, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, public_base_url=None, terms_version=None)

Build the sign-up router. See the module docstring for the endpoints.

* **Parameters:**
  * **session_store** (*user_store /*) – the platform’s account records and sessions.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – HMAC key for codes, link tokens, challenges and cookies.
  * **send_email** ([`EmailSender`](enlace_auth.auth.email.html.md#enlace_auth.auth.email.EmailSender)) – delivers the mails (`to=, subject=, body=`; never raises).
  * **policy** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`SignupPolicy`](enlace_auth.signup.policy.html.md#enlace_auth.signup.policy.SignupPolicy)]) – who may create an account from which app (default: nobody); its
    admin addresses are never created and get no sign-in codes.
  * **codes** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`PendingCodes`](enlace_auth.signup.codes.html.md#enlace_auth.signup.codes.PendingCodes)]) – the pending-code store (default: in memory, 10 minutes, 5 tries).
  * **rate_limiter** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`RateLimiter`](enlace_auth.ratelimit.html.md#enlace_auth.ratelimit.RateLimiter)]) – `allow(key, *, limit, window)` (default: in memory).
  * **bot_check** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`BotCheck`](enlace_auth.signup.botcheck.html.md#enlace_auth.signup.botcheck.BotCheck)]) – `challenge()` / `verify(fields)` (default: honeypot plus
    a 2-second time-to-submit).
  * **limits** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]) – the counts of `SignupLimitsConfig` as a dict.
  * **client_ip** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[`Request`], [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – `(request) -> str`, the client a rate limit counts (the
    plugin reads `X-Forwarded-For` only from a trusted proxy).
  * **known_apps** ([`Iterable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Iterable)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – app names a sign-up may name, directly or through `next`.
  * **delete_account** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`None`](https://docs.python.org/3/builtins/constants.html#None)]]) – `delete(email)`, removing an account and its data;
    `None` leaves the deletion endpoints unmounted.
  * **public_base_url** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – the origin put in mailed links. Without it the link is
    built from the request’s `Host`, which the requester controls.
  * **terms_version** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]) – stored on each account created, as the terms accepted.
* **Return type:**
  `APIRouter`
