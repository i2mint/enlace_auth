# enlace_auth.auth.accounts

Disabled accounts, and the one way a sign-in opens a session.

A user record is a plain dict in the user store. `disabled_at` (epoch
seconds) marks an account that exists, keeps its grants, shares and history,
but cannot sign in by any path; its connector grants are refused too (see
`enlace_auth.plugin._make_is_active`). Disabling also ends its sessions;
re-enabling only removes the mark.

The platform keeps that mark in its own mapping, not in the stored record
([`AccountRecords`](#enlace_auth.auth.accounts.AccountRecords), #71): several paths rewrite a whole record from a copy
read moments earlier (password change, reset, OAuth subject binding), and the
file store has no compare-and-set, so a mark inside the record could be undone
by any of them. Reads still show `disabled_at` on the record, so every
`is_disabled(record)` check is unchanged; only [`set_disabled()`](#enlace_auth.auth.accounts.set_disabled) writes it.

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

| [`is_disabled`](#enlace_auth.auth.accounts.is_disabled)(record)                            | True when *record* is a user record marked disabled.                     |
|-------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`make_account_records`](#enlace_auth.auth.accounts.make_account_records)(store_factory)            | The platform's user records: `users` plus the `disabled_accounts` marks. |
| [`open_session`](#enlace_auth.auth.accounts.open_session)(session_store, user_store, email) | Create a session for *email* and return its id, unless it is disabled.   |
| [`set_disabled`](#enlace_auth.auth.accounts.set_disabled)(user_store, email, disabled, \*)  | Mark *email*'s record disabled (or not); return the new record.          |

### Classes

| [`AccountRecords`](#enlace_auth.auth.accounts.AccountRecords)(users, disabled)   | User records whose disabled mark lives in its own mapping.   |
|------------------------------------------------------------------------------------|--------------------------------------------------------------|

### *class* enlace_auth.auth.accounts.AccountRecords(users, disabled)

Bases: [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)

User records whose disabled mark lives in its own mapping.

Reading a record adds `disabled_at` from *disabled*; writing one drops
that key, so a path that rewrites a record from a copy read before an
admin’s disable cannot undo it. Only [`set_disabled()`](#enlace_auth.auth.accounts.set_disabled) writes
*disabled*, one key at a time, with no read-modify-write.

```pycon
>>> users = AccountRecords({"a@x.io": {"password_hash": "old"}}, {})
>>> copy = users["a@x.io"]                   # a password change reads...
>>> _ = users.set_disabled("a@x.io", True, now=5)  # ...an admin disables...
>>> users["a@x.io"] = {**copy, "password_hash": "new"}  # ...it writes back
>>> is_disabled(users["a@x.io"]), users["a@x.io"]["password_hash"]
(True, 'new')
```

A mark that exists but cannot be read counts as disabled (fail closed). A
record written before this split (#70) may still carry the key itself:
[`make_account_records()`](#enlace_auth.auth.accounts.make_account_records) moves such marks out at startup, and until then
the record stays disabled (rewrites keep it) until an enable clears it.

#### migrate_legacy_marks()

Move marks written into records (before #71) to *disabled*; return how many.

```pycon
>>> records = AccountRecords({"a@x.io": {"disabled_at": 3.0}}, {})
>>> records.migrate_legacy_marks(), records.users, records.disabled
(1, {'a@x.io': {}}, {'a@x.io': 3.0})
```

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### set_disabled(email, disabled, , now=None)

Mark *email* disabled (or not); return its record as now read.

Raises `KeyError` when there is no such account.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

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

### enlace_auth.auth.accounts.make_account_records(store_factory)

The platform’s user records: `users` plus the `disabled_accounts` marks.

Marks still inside records (written before #71) are moved out first.

```pycon
>>> stores = {}
>>> records = make_account_records(lambda name: stores.setdefault(name, {}))
>>> sorted(stores)
['disabled_accounts', 'users']
```

* **Return type:**
  [`AccountRecords`](#enlace_auth.auth.accounts.AccountRecords)

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

Raises `KeyError` when there is no such account. On
[`AccountRecords`](#enlace_auth.auth.accounts.AccountRecords) (the platform’s store) the mark is written apart
from the record; on a plain mapping it is written into the record.

```pycon
>>> s = {"a@x.io": {"created_at": 0}}
>>> is_disabled(set_disabled(s, "a@x.io", True, now=5))
True
>>> is_disabled(set_disabled(s, "a@x.io", False))
False
```

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)
