# enlace_auth.signup

Self-service sign-up and email-code sign-in.

`make_signup_router` mounts `/auth/email/*` (a one-time code mailed to the
address, verify-before-create), the verify-first `/auth/register`, and
self-service deletion (`/auth/account/delete`). The pieces are seams the
plugin wires from `[auth.signup]`: [`SignupPolicy`](enlace_auth.signup.policy.html.md#enlace_auth.signup.policy.SignupPolicy)
(who may create an account from which app), a rate limiter
([`enlace_auth.ratelimit`](enlace_auth.ratelimit.html.md#module-enlace_auth.ratelimit)), and a bot check
([`TimedHoneypot`](enlace_auth.signup.botcheck.html.md#enlace_auth.signup.botcheck.TimedHoneypot)). The design and its
research: `misc/docs/research/self-signup-synthesis.md`.

### Functions

| [`consume_invite`](#enlace_auth.signup.consume_invite)(invites, email)          | Drop *email*'s invitation once its account exists (a missing one is fine).   |
|------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| [`invite`](#enlace_auth.signup.invite)(invites, email, \*[, apps, ...]) | Invite *email* to sign up from *apps* (merged with any earlier invitation).  |

### Classes

| [`PendingCodes`](#enlace_auth.signup.PendingCodes)(store, \*, signing_key[, ttl, ...])   | Issue and check one-time codes.                    |
|-----------------------------------------------------------------------------------------------------|----------------------------------------------------|
| [`SignupPolicy`](#enlace_auth.signup.SignupPolicy)(\*[, default, apps, allowlist, ...])  | The per-app sign-up policy of `[auth.signup]`.     |
| [`TimedHoneypot`](#enlace_auth.signup.TimedHoneypot)(signing_key, \*[, min_seconds, ...]) | Honeypot field plus a signed time-to-submit token. |

### *class* enlace_auth.signup.PendingCodes(store, \*, signing_key, ttl=600, max_attempts=3, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Issue and check one-time codes. See the module docstring.

#### check(email, code, , purpose='signin', nonce='')

Spend *code* for *email* and *nonce*; return its data, else `None`.

`None` covers every failure alike (no pending code, another browser’s,
expired, wrong, too many attempts, already spent).

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### discard(email, , purpose='signin', nonce='')

Forget any pending code for *email* and *nonce*.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### issue(email, , purpose='signin', nonce='', data=None)

Store a fresh code for *email* and *nonce* (replacing theirs); return it.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### link_token(email, code, , purpose='signin')

A signed token carrying *email* and *code*, for the emailed link.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### open_link_token(token)

`(email, code, purpose)` from a valid, unexpired token, else `None`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]]

### *class* enlace_auth.signup.SignupPolicy(, default='closed', apps=None, allowlist=(), invites=None, admin_emails=())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The per-app sign-up policy of `[auth.signup]`. See the module docstring.

#### allows(email, app)

May *email* create an account by signing up from *app*?

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### is_admin(email)

True for an admin address, in either spelling.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### is_invited(email, app)

True when *email* holds an invitation for *app*, or is allowlisted.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### mode(app)

The mode that applies to a sign-up from *app* (`None`: the default).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### on_created(email)

Called once an account for *email* exists: its invitation is used up.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### *class* enlace_auth.signup.TimedHoneypot(signing_key, \*, min_seconds=2.0, max_seconds=3600, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Honeypot field plus a signed time-to-submit token. See the module docstring.

#### challenge(, issued_at=None)

A token recording when the form was rendered (*issued_at*: now).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### verify(fields)

True when the honeypot is empty and the token is old enough, not stale.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### enlace_auth.signup.consume_invite(invites, email)

Drop *email*’s invitation once its account exists (a missing one is fine).

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### enlace_auth.signup.invite(invites, email, , apps=('\*',), invited_by=None, now=None)

Invite *email* to sign up from *apps* (merged with any earlier invitation).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

### Modules

| [`botcheck`](enlace_auth.signup.botcheck.html.md#module-enlace_auth.signup.botcheck)   | A cheap check that a sign-up form was sent by a person.                                                    |
|------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| [`codes`](enlace_auth.signup.codes.html.md#module-enlace_auth.signup.codes)         | One-time codes mailed for sign-in, sign-up and account deletion.                                           |
| [`pages`](enlace_auth.signup.pages.html.md#module-enlace_auth.signup.pages)         | Markup for the sign-up flow: the "continue with email" step, the link page, and the account-deletion card. |
| [`policy`](enlace_auth.signup.policy.html.md#module-enlace_auth.signup.policy)       | Who may create an account, from which app.                                                                 |
| [`routes`](enlace_auth.signup.routes.html.md#module-enlace_auth.signup.routes)       | `/auth/email/*`, the verify-first `/auth/register`, and self-service deletion.                             |
| [`texts`](enlace_auth.signup.texts.html.md#module-enlace_auth.signup.texts)         | What the sign-up flow says, in English and French: page text and emails.                                   |
