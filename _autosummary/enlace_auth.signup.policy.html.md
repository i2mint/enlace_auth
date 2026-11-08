# enlace_auth.signup.policy

Who may create an account, from which app.

A [`SignupPolicy`](#enlace_auth.signup.policy.SignupPolicy) answers two questions: `allows(email, app)` (may this
address create an account when it signs up from *app*) and `mode(app)` (which
of `closed`, `allowlist`, `invite` or `open` applies, for the page copy).
It decides account *creation* only. Whether an account may open an app stays
with `enlace.access.is_user_allowed`.

An admin address is refused under every mode: a self-service sign-up must never
be the way an admin account comes into being (i2mint/enlace_auth#35, #38).

Invitations are a `MutableMapping` keyed by the normalized address, whose
value is `{"apps": [...], "invited_by": ..., "created_at": ...}`; `"*"` in
`apps` invites to every app. An allowlisted address counts as invited.

```pycon
>>> p = SignupPolicy(
...     default="closed",
...     apps={"game": "open", "beta": "invite"},
...     invites={"a@x.io": {"apps": ["beta"]}},
...     admin_emails=("boss@x.io",),
... )
>>> p.allows("anyone@x.io", "game"), p.allows("anyone@x.io", None)
(True, False)
>>> p.allows("a@x.io", "beta"), p.allows("b@x.io", "beta")
(True, False)
>>> p.allows("boss@x.io", "game")
False
```

### Functions

| [`app_from_next`](#enlace_auth.signup.policy.app_from_next)(next_url, known_apps)     | The app a `next` path belongs to (`/<app>/...` or `/api/<app>/...`).        |
|------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| [`consume_invite`](#enlace_auth.signup.policy.consume_invite)(invites, email)          | Drop *email*'s invitation once its account exists (a missing one is fine).  |
| [`invite`](#enlace_auth.signup.policy.invite)(invites, email, \*[, apps, ...]) | Invite *email* to sign up from *apps* (merged with any earlier invitation). |

### Classes

| [`SignupPolicy`](#enlace_auth.signup.policy.SignupPolicy)(\*[, default, apps, allowlist, ...])   | The per-app sign-up policy of `[auth.signup]`.   |
|------------------------------------------------------------------------------------------------------|--------------------------------------------------|

### *class* enlace_auth.signup.policy.SignupPolicy(, default='closed', apps=None, allowlist=(), invites=None, admin_emails=())

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

### enlace_auth.signup.policy.app_from_next(next_url, known_apps)

The app a `next` path belongs to (`/<app>/...` or `/api/<app>/...`).

```pycon
>>> app_from_next("/api/game/state?x=1", {"game"})
'game'
>>> app_from_next("/nope/", {"game"}) is None
True
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.signup.policy.consume_invite(invites, email)

Drop *email*’s invitation once its account exists (a missing one is fine).

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### enlace_auth.signup.policy.invite(invites, email, , apps=('\*',), invited_by=None, now=None)

Invite *email* to sign up from *apps* (merged with any earlier invitation).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)
