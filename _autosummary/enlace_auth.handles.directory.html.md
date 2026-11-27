# enlace_auth.handles.directory

The read-only view of handles every app gets at `request.state.handles`.

An app’s server stores the account of whoever made something (its
`request.state.user_id`) and shows their handle with
`request.state.handles.handle_of(account)`. Accounts go in; only handles go out
to the browser. Renames need nothing from the app: it looks the handle up when it
shows it, so it never stores a stale one.

```pycon
>>> from enlace_auth.handles.registry import HandleRegistry
>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
>>> _ = reg.claim("thorwhalen@example.com", "thorwhalen")
>>> _ = reg.ensure("ann@example.com")            # a default, not confirmed yet
>>> d = HandleDirectory(reg)
>>> d.handles_of(["thorwhalen@example.com", "ann@example.com"])
{'thorwhalen@example.com': 'thorwhalen'}
>>> d.account_of("@ThorWhalen")
'thorwhalen@example.com'
>>> hasattr(d, "claim")   # read-only: apps cannot rename anyone
False
```

### Classes

| [`HandleDirectory`](#enlace_auth.handles.directory.HandleDirectory)(registry)                     | Look handles up by account and accounts up by handle; nothing else.      |
|------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`HandleDirectoryMiddleware`](#enlace_auth.handles.directory.HandleDirectoryMiddleware)(app, \*, directory) | Pure-ASGI middleware that sets `request.state.handles` on every request. |

### *class* enlace_auth.handles.directory.HandleDirectory(registry)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Look handles up by account and accounts up by handle; nothing else.

Only confirmed handles: an account that has not yet confirmed its default (made
from its email) has none to show, and `handle_of` returns `None`. An app
then shows no name, or sends its user to its “choose your username” step.

This is a convenience for trusted server code, not a boundary between apps:
every app server on the platform runs in the platform’s process and already
sees its own users’ emails. What must never happen is an email reaching a
browser; that is the app’s duty, and this view makes it easy by dealing in
handles.

#### account_of(handle)

The account holding *handle* (any spelling, `@` or not), or `None`.

For server code only (filtering “everything by @x”); never send it on.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### handle_of(account)

The public handle of *account* (a `request.state.user_id`), or `None`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### handles_of(accounts)

`{account: handle}` for many accounts at once (a list page).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### resolve(handle)

`{"handle"}`, or `{"handle", "renamed_from"}` after a recent rename.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

### *class* enlace_auth.handles.directory.HandleDirectoryMiddleware(app, , directory)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI middleware that sets `request.state.handles` on every request.
