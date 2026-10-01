# enlace_auth.auth.shares

Owner-granted data shares: let named users at one user’s per-user data in one app.

Grants ([`enlace_auth.auth.grants`](enlace_auth.auth.grants.md#module-enlace_auth.auth.grants)) answer *may this user open this app?* A
**share** answers a different question: \*may this user act on that user’s data in
this app?\* A share is `(app_id, owner, grantee)` plus an access level, and the
per-user store ([`enlace_auth.stores.middleware`](enlace_auth.stores.middleware.md#module-enlace_auth.stores.middleware)) honours it when a request
names an owner with `?owner=`. The design, and why it is shaped this way, is
`misc/docs/decisions/0001-owner-granted-data-shares.md`.

Storage mirrors [`GrantStore`](enlace_auth.auth.grants.md#enlace_auth.auth.grants.GrantStore): a thin adapter over a
`MutableMapping` whose keys are `"{app_id}/{owner}/{grantee}"` and whose values
are JSON records:

```default
{
    "app_id": str,
    "owner": str,              # normalized email
    "grantee": str,            # normalized email
    "access": "rw" | "ro",     # "ro" = read-only (GET)
    "label": str | None,       # how the grantee sees this space
    "granted_at": float,       # epoch seconds, UTC
    "granted_by": str | None,  # who created it (the owner, or an admin)
    "expires_at": float | None,  # epoch seconds, UTC; None = never
}
```

Two rules the store enforces, so no caller can forget them:

- **A share names existing accounts only** (when `account_exists` is given). A
  share to an address nobody holds would be claimed by whoever registers it next.
- **A share dies with either account**: [`ShareStore.remove_account()`](#enlace_auth.auth.shares.ShareStore.remove_account) deletes
  every share an email is part of, and account deletion calls it.

### Module Attributes

| [`ACCESS_LEVELS`](#enlace_auth.auth.shares.ACCESS_LEVELS)   | read-write, or read-only (GET).                                                  |
|------------------------------------------------------------------|----------------------------------------------------------------------------------|
| [`MAX_LABEL`](#enlace_auth.auth.shares.MAX_LABEL)       | The longest `label` a share may carry (the grantee sees it as the space's name). |

### Classes

| [`ShareStore`](#enlace_auth.auth.shares.ShareStore)(backend, \*[, root, account_exists])   | Share semantics over a `MutableMapping`.   |
|----------------------------------------------------------------------------------------------------|--------------------------------------------|

### Exceptions

| [`ShareError`](#enlace_auth.auth.shares.ShareError)(message, \*[, code])   | An invalid share.   |
|------------------------------------------------------------------------------------|---------------------|

### enlace_auth.auth.shares.ACCESS_LEVELS *= ('rw', 'ro')*

read-write, or read-only (GET).

* **Type:**
  The access levels a share may carry

### enlace_auth.auth.shares.MAX_LABEL *= 80*

The longest `label` a share may carry (the grantee sees it as the space’s name).

### *exception* enlace_auth.auth.shares.ShareError(message, , code='invalid')

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

An invalid share. `code` says which: `"no_account"` or `"invalid"`.

### *class* enlace_auth.auth.shares.ShareStore(backend, , root=None, account_exists=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Share semantics over a `MutableMapping`.

* **Parameters:**
  * **backend** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – the per-name store (e.g. `factory("shares")`).
  * **root** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path)]) – the filesystem directory backing `backend`, used only to list one
    app’s shares without scanning every key (as `GrantStore` does).
    `None` (a dict backend in tests) falls back to filtering all keys.
  * **account_exists** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]) – `email -> bool`. When given, [`share()`](#enlace_auth.auth.shares.ShareStore.share) refuses an
    owner or grantee with no account. `None` skips the check (tests).

#### access(app_id, owner, grantee, , now=None)

`"rw"`, `"ro"` or `None`: what `grantee` may do with the data.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### granted(app_id, owner, , now=None)

Every share `owner` made in `app_id`, each with `"active"`.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### list_all()

Every share in every app. Admin-only, infrequent.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### received(app_id, grantee, , now=None)

The **active** shares made to `grantee` in `app_id`.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### remove_account(email)

Delete every share `email` is part of, either side. Returns how many.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### share(app_id, owner, grantee, , access='rw', label=None, expires_at=None, granted_by=None, now=None)

Create or replace the share `owner` → `grantee` in `app_id`.

`expires_at` is epoch seconds UTC or `None`; turn a date string into it
with [`enlace_auth.auth.grants.parse_expires_at()`](enlace_auth.auth.grants.md#enlace_auth.auth.grants.parse_expires_at) first.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)
