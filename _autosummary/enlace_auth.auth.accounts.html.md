# enlace_auth.auth.accounts

Disabled accounts, and the one way a sign-in opens a session.

A user record is a plain dict in the user store. `disabled_at` (epoch
seconds) marks an account that exists, keeps its grants, shares and history,
but cannot sign in by any path; its connector grants are refused too (see
`enlace_auth.plugin._make_is_active`). Disabling also ends its sessions;
re-enabling only removes the key.

Every sign-in path opens its session through [`open_session()`](#enlace_auth.auth.accounts.open_session), which
re-checks the record after creating the session, so a sign-in racing an admin’s
disable cannot keep a session the revocation already missed.

The last sign-in time is NOT kept on the user record (a read-modify-write there
at every login could overwrite a concurrent disable); `SessionStore` records
it in its own mapping (`sign_ins`).

### Module Attributes

| [`DISABLED_DETAIL`](#enlace_auth.auth.accounts.DISABLED_DETAIL)   | What a disabled account is told when it tries to sign in.   |
|--------------------------------------------------------------------|-------------------------------------------------------------|

### Functions

| [`is_disabled`](#enlace_auth.auth.accounts.is_disabled)(record)                            | True when *record* is a user record marked disabled.                   |
|-------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| [`open_session`](#enlace_auth.auth.accounts.open_session)(session_store, user_store, email) | Create a session for *email* and return its id, unless it is disabled. |
| [`set_disabled`](#enlace_auth.auth.accounts.set_disabled)(user_store, email, disabled, \*)  | Mark *email*'s record disabled (or not); return the new record.        |

### enlace_auth.auth.accounts.DISABLED_DETAIL *= 'This account is disabled. Contact the platform admin.'*

What a disabled account is told when it tries to sign in.

### enlace_auth.auth.accounts.is_disabled(record)

True when *record* is a user record marked disabled.

```pycon
>>> is_disabled({"disabled_at": 1.0}), is_disabled({}), is_disabled(None)
(True, False, False)
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### enlace_auth.auth.accounts.open_session(session_store, user_store, email)

Create a session for *email* and return its id, unless it is disabled.

The disabled check runs AFTER the session exists: if an admin disabled the
account (and revoked its sessions) while this sign-in was in flight, the
new session is deleted here and the sign-in refused. Raises
`fastapi.HTTPException(403)` in that case.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.accounts.set_disabled(user_store, email, disabled, , now=None)

Mark *email*’s record disabled (or not); return the new record.

Raises `KeyError` when there is no such account.

```pycon
>>> s = {"a@x.io": {"created_at": 0}}
>>> is_disabled(set_disabled(s, "a@x.io", True, now=5))
True
>>> is_disabled(set_disabled(s, "a@x.io", False))
False
```

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)
