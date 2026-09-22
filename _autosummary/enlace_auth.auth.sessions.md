# enlace_auth.auth.sessions

Session storage backed by a MutableMapping.

A session is `{"user_id": str, "email": str | None, "created_at": float}`.
Session IDs are 32-byte urlsafe tokens. Revocation is a simple delete.

Records are otherwise only deleted by logout, so given a *max_age* the store
sweeps records older than it, a bounded batch at a time, when a session is
created (at most once per *sweep_interval* per process) – keeping the
store (and [`SessionStore.revoke_user()`](#enlace_auth.auth.sessions.SessionStore.revoke_user)’s scan) from growing without bound.

### Classes

| [`SessionStore`](#enlace_auth.auth.sessions.SessionStore)(store, \*[, max_age, ...])   | Thin adapter around a MutableMapping that speaks session semantics.   |
|--------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|

### *class* enlace_auth.auth.sessions.SessionStore(store, , max_age=None, sweep_batch=100, sweep_interval=3600.0)

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
