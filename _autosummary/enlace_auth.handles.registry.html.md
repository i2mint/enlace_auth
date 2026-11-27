# enlace_auth.handles.registry

The handle registry: which account holds which handle, kept unique under a lock.

Two mappings, each a plain `MutableMapping` (a `dict` in tests, the platform’s
file store in production):

- `handles`: uniqueness key -> `{"handle", "account", "at", "released_at"}`,
  public names only. A live entry has `released_at` `None`. A released one keeps
  the name out of reach for *quarantine_seconds*: after a rename it still names its
  old account (who may take it back, and whose old links resolve to the new name);
  after an account deletion its `account` is `None` (the email is erased).
- `owners`: account -> `{"handle", "chosen", "at", "changed_at", "previous"}`.
  `chosen` is `False` for a private default the account has not confirmed: a
  frontend shows its “choose your username” step, and nobody else can see it.

A name is public only while both halves agree: a live `handles` entry naming the
account, and the account’s chosen record naming that key. Writes are ordered so
that an interrupted one leaves at most one half, which every read ignores: never
two owners, never a name freed before its quarantine.

Uniqueness: every write runs under *lock* (a context manager). The default is a
process-local `threading.Lock`; the platform passes [`file_lock()`](#enlace_auth.handles.registry.file_lock), which holds
across worker processes on one host. A store with a conditional write (S3
`If-None-Match`, a database unique index) is the replacement for a multi-host
deployment.

```pycon
>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True, clock=lambda: 0.0)
>>> reg.ensure("ann.lee@example.com")
{'handle': 'ann.lee', 'chosen': False}
>>> reg.ensure("annlee@example.org")["handle"]   # private defaults do not collide
'annlee'
>>> reg.claim("annlee@example.org", "Ann_Music")
{'handle': 'ann_music', 'chosen': True}
>>> reg.account_of("@annmusic")
'annlee@example.org'
>>> reg.handle_of("ann.lee@example.com") is None   # an unconfirmed default is private
True
```

### Functions

| [`file_lock`](#enlace_auth.handles.registry.file_lock)(path)                                   | A lock factory over `flock` on *path*: exclusive across processes on a host.   |
|----------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [`make_handle_registry`](#enlace_auth.handles.registry.make_handle_registry)(handles_cfg, \*, ...[, ...]) | The platform's registry, from `[auth.handles]` (a `HandlesConfig`).            |

### Classes

| [`HandleRegistry`](#enlace_auth.handles.registry.HandleRegistry)(handles, owners, \*[, policy, ...])   | Handles of accounts: assign defaults, claim, rename, release, look up.   |
|-------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|

### Exceptions

| [`HandleError`](#enlace_auth.handles.registry.HandleError)(code, message, \*[, suggestions])   | A handle could not be set.   |
|--------------------------------------------------------------------------------------------------|------------------------------|

### *exception* enlace_auth.handles.registry.HandleError(code, message, , suggestions=())

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

A handle could not be set. *code* says why, *message* says it to a person.

Codes: `invalid`, `reserved`, `taken`, `cooldown`, `no-account`,
`exhausted`.

### *class* enlace_auth.handles.registry.HandleRegistry(handles, owners, \*, policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), lock=None, account_exists=<function HandleRegistry.<lambda>>, quarantine_seconds=7776000.0, rename_cooldown_seconds=2592000.0, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Handles of accounts: assign defaults, claim, rename, release, look up.

A default handle (made from the email) is *private* until its account confirms
or changes it: it lives only in the account’s own `owners` record, never in
`handles`. So lookups, the availability check, timings and other accounts’
defaults are all unaffected by it, two accounts may hold the same private
default, and confirming one is an ordinary claim that can find the name taken.
A handle made from an email gives part of the address away, so it is published
only by its owner’s own action (GDPR Art. 25(2); see
`misc/docs/research/general/usernames.md`).

* **Parameters:**
  * **handles** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – uniqueness key -> public name entry (see the module docstring)
  * **owners** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – account -> its handle record
  * **policy** ([`HandlePolicy`](enlace_auth.handles.core.html.md#enlace_auth.handles.core.HandlePolicy)) – the rules ([`HandlePolicy`](enlace_auth.handles.core.html.md#enlace_auth.handles.core.HandlePolicy))
  * **lock** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`ContextManager`](https://docs.python.org/3/library/typing.html#typing.ContextManager)]]) – a zero-argument factory of a context manager held around writes
  * **account_exists** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]) – whether an account exists; checked under the lock, so
    nothing is written for an account deleted meanwhile
  * **quarantine_seconds** ([`float`](https://docs.python.org/3/builtins/functions.html#float)) – how long a released public name stays out of others’
    reach (a renamed one redirects meanwhile)
  * **rename_cooldown_seconds** ([`float`](https://docs.python.org/3/builtins/functions.html#float)) – the least time between two public names (the
    first choice is free)
  * **clock** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`float`](https://docs.python.org/3/builtins/functions.html#float)]) – the time, in epoch seconds

#### account_of(handle)

The account holding *handle* publicly (any spelling of it), or `None`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### check(wanted, , account=None)

What a “choose your username” field shows while the person types.

`{"handle", "available", "problem", "code", "suggestions"}`: *handle* is
the normalised form (show it as the preview), *problem* a sentence or
`None`, *code* one of [`HandleError`](#enlace_auth.handles.registry.HandleError)’s codes or `None`.

```pycon
>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
>>> _ = reg.claim("thorwhalen@example.com", "thorwhalen")
>>> reg.check("Thor.Whalen")["suggestions"]
['thor.whalen1', 'thor.whalen2', 'thor.whalen3']
```

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### claim(account, wanted, , force=False)

Publish *wanted* as *account*’s handle (also: confirm its default).

The first public name is free; changing it waits
*rename_cooldown_seconds* after the last change, and the old name stays
with the account for the quarantine (it redirects). *force* (an admin)
skips the reserved list, the cooldown and a quarantine, never a public
owner. Raises [`HandleError`](#enlace_auth.handles.registry.HandleError); a `taken` one carries suggestions.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### ensure(account, , missing_ok=False)

The handle record of *account*, giving it a private default if needed.

The default is the email’s local part, then `1`, `2` … until a name no
one holds publicly ([`candidates()`](enlace_auth.handles.core.html.md#enlace_auth.handles.core.candidates)). A private
default that someone has since published is replaced by the next one. An
account that does not exist gets nothing: `None` with *missing_ok*, else
[`HandleError`](#enlace_auth.handles.registry.HandleError) `no-account`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### handle_of(account)

The public handle of *account*: `None` until it has confirmed one.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### handles_of(accounts)

`{account: handle}` for each of *accounts* with a public handle.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### is_free(handle, , account=None)

Whether *handle* could be claimed by *account* (by anyone, if `None`).

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### record_of(account)

`{"handle", "chosen"}` of *account*, for the account itself.

`chosen` is true only while the name is really published (so a write
interrupted half-way shows as not chosen, and the account confirms again).

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### release_account(account)

Forget *account*’s handles (the account is being deleted); return 1 or 0.

Its public name, and the names it renamed away from, stay out of others’
reach for the quarantine with no account attached (the email is erased);
then they are free. Only entries that name this account are touched, and
the record goes last, so an interrupted release never frees a name early.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### resolve(handle)

`{"handle": current}` for *handle*, following a recent rename.

A name its account renamed away from, still in quarantine, resolves to that
account’s current handle with `"renamed_from"`; a deleted account’s name,
a private default, or an unknown one resolves to `None`.

```pycon
>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
>>> _ = reg.claim("a@example.com", "first")
>>> _ = reg.claim("a@example.com", "second", force=True)
>>> reg.resolve("FIRST")
{'handle': 'second', 'renamed_from': 'first'}
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### sweep()

Remove released entries whose quarantine is over; return how many.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### enlace_auth.handles.registry.file_lock(path)

A lock factory over `flock` on *path*: exclusive across processes on a host.

Each call returns a fresh context manager. Without `fcntl` (Windows) it falls
back to a process-local lock.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`ContextManager`](https://docs.python.org/3/library/typing.html#typing.ContextManager)]

### enlace_auth.handles.registry.make_handle_registry(handles_cfg, , store_factory, store_root, account_exists, groups=(), lock=None)

The platform’s registry, from `[auth.handles]` (a `HandlesConfig`).

The two mappings are the platform store’s `handles` and `handle_owners`, and
the lock is a `flock` on `<store_root>/handles.lock`, so the gunicorn
workers of one host agree (pass *lock* for stores shared across hosts). The
names of *groups* (`[auth.groups]`) are reserved too, so no account can be
called `@family`.

* **Return type:**
  [`HandleRegistry`](#enlace_auth.handles.registry.HandleRegistry)
