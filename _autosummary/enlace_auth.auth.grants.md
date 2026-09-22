# enlace_auth.auth.grants

Runtime per-app access grants, with optional UTC expiry.

A *grant* gives a specific user (by email) access to a specific `protected:user`
app at runtime, **without a redeploy**. Grants are ADDITIVE on top of the static
`allowed_users` declared in an app’s `app.toml`: the effective allow-set for
an app is `config allowed_users ∪ {active grants}`. A grant is *active* when its
`expires_at` is `None` (never expires) or lies in the future (UTC).

Storage mirrors [`enlace_auth.auth.sessions.SessionStore`](enlace_auth.auth.sessions.md#enlace_auth.auth.sessions.SessionStore): a thin adapter
over a `MutableMapping` whose keys are `"{app_id}/{email}"` and whose values
are JSON grant records:

```default
{
    "app_id": str,
    "email": str,              # normalized to lowercase
    "expires_at": float | None,  # epoch seconds, UTC; None = never
    "granted_at": float,       # epoch seconds, UTC
    "granted_by": str | None,  # admin email who created it
    "note": str | None,
}
```

The composite key groups grants per app on disk (`grants/{app_id}/{email}`), so
the hot path — [`GrantStore.active_emails_for_app()`](#enlace_auth.auth.grants.GrantStore.active_emails_for_app), consulted by the auth
middleware on every `protected:user` request — lists a single app’s
subdirectory rather than scanning every grant for every app.

### Functions

| [`parse_expires_at`](#enlace_auth.auth.grants.parse_expires_at)(value, \*[, now])   | Coerce a user-supplied expiry into epoch seconds (UTC), or `None`.   |
|---------------------------------------------------------------------------------------|----------------------------------------------------------------------|

### Classes

| [`GrantStore`](#enlace_auth.auth.grants.GrantStore)(backend, \*[, root])   | Thin adapter over a `MutableMapping` that speaks grant semantics.   |
|------------------------------------------------------------------------------------|---------------------------------------------------------------------|

### Exceptions

| [`GrantError`](#enlace_auth.auth.grants.GrantError)   | Raised when a grant argument is invalid (bad email/app_id, past expiry).   |
|---------------------------------------------------------------|----------------------------------------------------------------------------|

### *exception* enlace_auth.auth.grants.GrantError

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

Raised when a grant argument is invalid (bad email/app_id, past expiry).

### *class* enlace_auth.auth.grants.GrantStore(backend, , root=None)

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

Use [`parse_expires_at()`](#enlace_auth.auth.grants.parse_expires_at) to turn a date/ISO string into `expires_at`
before calling this.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list_all()

All grant records across all apps. Admin-only / infrequent.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

### enlace_auth.auth.grants.parse_expires_at(value, , now=None)

Coerce a user-supplied expiry into epoch seconds (UTC), or `None`.

Accepts:

- `None` / empty string → `None` (never expires).
- a number → treated as epoch seconds, returned as a float.
- `"YYYY-MM-DD"` → **end of that day UTC** (`23:59:59`), so the grant is
  valid through the whole named day (least-surprising “expires on this date”).
- a full ISO-8601 timestamp (`...THH:MM[:SS][±TZ|Z]`) → that instant. A
  trailing `Z` is honored (Python 3.10’s `fromisoformat` can’t) and a
  naive timestamp is assumed to be UTC.

Raises [`GrantError`](#enlace_auth.auth.grants.GrantError) for unparseable input or an already-past expiry.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`float`](https://docs.python.org/3/builtins/functions.html#float)]
