# enlace_auth.handles

Handles (usernames): the public, unique, case-insensitive name of an account.

The email stays the account’s private key; the handle is what other people and
apps see (“by @thorwhalen”). Three layers, imported one way:

- [`core`](enlace_auth.handles.core.html.md#module-enlace_auth.handles.core): the rules (normal form, validity, reserved
  names, the default from an email, suggestions). Pure; no web or storage imports.
- [`registry`](enlace_auth.handles.registry.html.md#module-enlace_auth.handles.registry): [`HandleRegistry`](#enlace_auth.handles.HandleRegistry), which account holds
  which handle, over two `MutableMapping` s, unique under a lock.
- [`directory`](enlace_auth.handles.directory.html.md#module-enlace_auth.handles.directory): [`HandleDirectory`](#enlace_auth.handles.HandleDirectory), the read-only
  view every app gets at `request.state.handles` (set by
  [`HandleDirectoryMiddleware`](#enlace_auth.handles.HandleDirectoryMiddleware)).
- [`routes`](enlace_auth.handles.routes.html.md#module-enlace_auth.handles.routes): `/auth/handles/*` for the browser.

An app’s server shows “by <handle>” with `request.state.handles.handle_of(owner)`,
where *owner* is the `request.state.user_id` it stored; it never sends emails to
the browser. See `misc/docs/research/general/usernames.md` for the rules’ sources.

### Functions

| [`base_from_email`](#enlace_auth.handles.base_from_email)(email, \*[, policy])               | The base of a default handle: the email's local part, made into a handle.                                                                 |
|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| [`candidates`](#enlace_auth.handles.candidates)(base, \*[, policy, limit, rng, tries])  | Valid handles to try, in order: *base*, `base1` .                                                                                         |
| [`file_lock`](#enlace_auth.handles.file_lock)(path)                                    | A lock factory over `flock` on *path*: exclusive across processes on a host.                                                              |
| [`handle_problem`](#enlace_auth.handles.handle_problem)(handle, \*[, policy])               | Why *handle* (already normalised) cannot be a handle, or `None` if it can.                                                                |
| [`make_handle_registry`](#enlace_auth.handles.make_handle_registry)(handles_cfg, \*, ...[, ...])  | The platform's registry, from `[auth.handles]` (a `HandlesConfig`).                                                                       |
| [`normalize`](#enlace_auth.handles.normalize)(text)                                    | The stored form of what a person typed: NFKC, case-folded, trimmed, no `@`.                                                               |
| [`suggestions`](#enlace_auth.handles.suggestions)(wanted, is_free, \*[, policy, n, ...]) | Up to *n* free handles close to *wanted*, for a name that is taken or invalid.                                                            |
| [`uniqueness_key`](#enlace_auth.handles.uniqueness_key)(handle)                             | The form two handles are compared by: normalised, without separators, with look-alike characters folded (`0` as `o`; `1` and `i` as `l`). |

### Classes

| [`HandleDirectory`](#enlace_auth.handles.HandleDirectory)(registry)                          | Look handles up by account and accounts up by handle; nothing else.      |
|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`HandleDirectoryMiddleware`](#enlace_auth.handles.HandleDirectoryMiddleware)(app, \*, directory)      | Pure-ASGI middleware that sets `request.state.handles` on every request. |
| [`HandlePolicy`](#enlace_auth.handles.HandlePolicy)([min_length, max_length, ...])        | The knobs of the handle rules.                                           |
| [`HandleRegistry`](#enlace_auth.handles.HandleRegistry)(handles, owners, \*[, policy, ...]) | Handles of accounts: assign defaults, claim, rename, release, look up.   |

### Exceptions

| [`HandleError`](#enlace_auth.handles.HandleError)(code, message, \*[, suggestions])   | A handle could not be set.   |
|--------------------------------------------------------------------------------------------------|------------------------------|

### *class* enlace_auth.handles.HandleDirectory(registry)

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

### *class* enlace_auth.handles.HandleDirectoryMiddleware(app, , directory)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI middleware that sets `request.state.handles` on every request.

### *exception* enlace_auth.handles.HandleError(code, message, , suggestions=())

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

A handle could not be set. *code* says why, *message* says it to a person.

Codes: `invalid`, `reserved`, `taken`, `cooldown`, `no-account`,
`exhausted`.

### *class* enlace_auth.handles.HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'about', 'abuse', 'account', 'accounts', 'admin', 'administrator', 'admins', 'all', 'anonymous', 'api', 'app', 'apps', 'auth', 'autoconfig', 'autodiscover', 'blog', 'callback', 'check', 'contact', 'csrf', 'dashboard', 'deleted', 'docs', 'everyone', 'false', 'favicon', 'guest', 'help', 'here', 'home', 'hostmaster', 'info', 'localhost', 'login', 'logout', 'mail', 'mailer-daemon', 'me', 'mod', 'moderator', 'mods', 'new', 'no-reply', 'nobody', 'noc', 'none', 'noreply', 'null', 'oauth', 'official', 'operator', 'owner', 'postmaster', 'privacy', 'register', 'removed', 'robots', 'root', 'search', 'security', 'settings', 'signin', 'signout', 'signup', 'staff', 'static', 'status', 'store', 'superuser', 'support', 'sysadmin', 'system', 'team', 'terms', 'test', 'true', 'undefined', 'unknown', 'user', 'users', 'webmaster', 'well-known', 'wpad', 'www', 'xrpc', 'you'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The knobs of the handle rules. The defaults are the platform’s.

*reserved* is compared by [`uniqueness_key()`](#enlace_auth.handles.uniqueness_key), so reserving `no-reply` also
reserves `noreply` and `no.reply`.

#### fallback_base *: [str](https://docs.python.org/3/builtins/stdtypes.html#str)* *= 'user'*

the base of a default handle when the email gives nothing usable

#### max_sequential *: [int](https://docs.python.org/3/builtins/functions.html#int)* *= 99*

sequential suffixes tried (`name1` .. `name<N>`) before random ones

#### random_suffix_digits *: [int](https://docs.python.org/3/builtins/functions.html#int)* *= 6*

digits of the random suffix used once the sequential ones are spent

#### random_tries *: [int](https://docs.python.org/3/builtins/functions.html#int)* *= 1000*

random suffixes tried before giving up (a crowded base, a tiny max_length)

#### *property* reserved_keys *: [frozenset](https://docs.python.org/3/builtins/stdtypes.html#frozenset)*

The uniqueness keys of the reserved names.

#### with_reserved(extra)

This policy with *extra* names reserved too (a host’s group names).

```pycon
>>> "acme" in DEFAULT_POLICY.with_reserved(["Acme"]).reserved_keys
True
```

* **Return type:**
  [`HandlePolicy`](enlace_auth.handles.core.html.md#enlace_auth.handles.core.HandlePolicy)

### *class* enlace_auth.handles.HandleRegistry(handles, owners, \*, policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), lock=None, account_exists=<function HandleRegistry.<lambda>>, quarantine_seconds=7776000.0, rename_cooldown_seconds=2592000.0, clock=<built-in function time>)

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
`None`, *code* one of [`HandleError`](#enlace_auth.handles.HandleError)’s codes or `None`.

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
owner. Raises [`HandleError`](#enlace_auth.handles.HandleError); a `taken` one carries suggestions.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### ensure(account, , missing_ok=False)

The handle record of *account*, giving it a private default if needed.

The default is the email’s local part, then `1`, `2` … until a name no
one holds publicly ([`candidates()`](enlace_auth.handles.core.html.md#enlace_auth.handles.core.candidates)). A private
default that someone has since published is replaced by the next one. An
account that does not exist gets nothing: `None` with *missing_ok*, else
[`HandleError`](#enlace_auth.handles.HandleError) `no-account`.

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

### enlace_auth.handles.base_from_email(email, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000))

The base of a default handle: the email’s local part, made into a handle.

The `+tag` of plus-addressing is dropped (it is private routing, and often
names the site), accents are folded, other characters removed, separator runs
collapsed, and the result cut so a suffix still fits. When nothing usable is
left, or the local part is a reserved word (`info@`, `admin@`: role
mailboxes), *policy.fallback_base*. The base may still be too short:
[`candidates()`](#enlace_auth.handles.candidates) then starts at the first suffix.

```pycon
>>> base_from_email("José.Ñúñez@example.com")
'jose.nunez'
>>> base_from_email("o'brien@example.com")
'obrien'
>>> base_from_email("--@example.com"), base_from_email("info@example.com")
('user', 'user')
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.handles.candidates(base, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), limit=None, rng=None, tries=None)

Valid handles to try, in order: *base*, `base1` .. `base<max_sequential>`,
then `base` plus a random number of *policy.random_suffix_digits* digits.
Endless unless *tries* bounds the names generated (valid or not): a caller
that must terminate passes it.

Invalid ones (too short, reserved) are skipped, so `bo` starts at `bo1`. The
base is cut so the suffix fits. Sequential suffixes are what people expect (the
first `john` is `john`, the next `john1`); the random tail keeps a crowded
base from costing a hundred lookups.

```pycon
>>> list(candidates("thorwhalen", limit=3))
['thorwhalen', 'thorwhalen1', 'thorwhalen2']
>>> list(candidates("agent007", limit=2))
['agent007', 'agent007_1']
>>> no_sequence = HandlePolicy(max_sequential=0)
>>> list(candidates("xyz", policy=no_sequence, rng=lambda a, b: 424242, limit=2))
['xyz', 'xyz424242']
```

* **Return type:**
  [`Iterator`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Iterator)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.handles.file_lock(path)

A lock factory over `flock` on *path*: exclusive across processes on a host.

Each call returns a fresh context manager. Without `fcntl` (Windows) it falls
back to a process-local lock.

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`ContextManager`](https://docs.python.org/3/library/typing.html#typing.ContextManager)]

### enlace_auth.handles.handle_problem(handle, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000))

Why *handle* (already normalised) cannot be a handle, or `None` if it can.

The message is written for the person choosing the name.

```pycon
>>> handle_problem("ab")
'Use at least 3 characters.'
>>> handle_problem("josé")
'Use only letters a-z, digits, and . _ -'
>>> handle_problem("12345")
'Use at least one letter.'
>>> handle_problem("admin")
'This name is reserved.'
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.handles.make_handle_registry(handles_cfg, , store_factory, store_root, account_exists, groups=(), lock=None)

The platform’s registry, from `[auth.handles]` (a `HandlesConfig`).

The two mappings are the platform store’s `handles` and `handle_owners`, and
the lock is a `flock` on `<store_root>/handles.lock`, so the gunicorn
workers of one host agree (pass *lock* for stores shared across hosts). The
names of *groups* (`[auth.groups]`) are reserved too, so no account can be
called `@family`.

* **Return type:**
  [`HandleRegistry`](enlace_auth.handles.registry.html.md#enlace_auth.handles.registry.HandleRegistry)

### enlace_auth.handles.normalize(text)

The stored form of what a person typed: NFKC, case-folded, trimmed, no `@`.

It does not validate: [`handle_problem()`](#enlace_auth.handles.handle_problem) does, on this form.

```pycon
>>> normalize("  @Ｔhor_Whalen")
'thor_whalen'
>>> normalize("Straße")
'strasse'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.handles.suggestions(wanted, is_free, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), n=3, max_tries=200)

Up to *n* free handles close to *wanted*, for a name that is taken or invalid.

*wanted* is first made into a base the way an email’s local part is, so
`Thor Whalen!` suggests `thorwhalen1` and so on.

```pycon
>>> taken = {"thorwhalen", "thorwhalen1"}
>>> suggestions("ThorWhalen", lambda h: h not in taken)
['thorwhalen2', 'thorwhalen3', 'thorwhalen4']
```

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.handles.uniqueness_key(handle)

The form two handles are compared by: normalised, without separators, with
look-alike characters folded (`0` as `o`; `1` and `i` as `l`).

So `th0r.whalen` cannot pose as `thorwhalen`. It is a key, never shown.

```pycon
>>> uniqueness_key("@Thor.Whalen") == uniqueness_key("th0r-whalen")
True
>>> uniqueness_key("bill") == uniqueness_key("b1ll")
True
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### Modules

| [`core`](enlace_auth.handles.core.html.md#module-enlace_auth.handles.core)           | What a handle is: its normal form, its rules, and the default made from an email.   |
|-------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| [`directory`](enlace_auth.handles.directory.html.md#module-enlace_auth.handles.directory) | The read-only view of handles every app gets at `request.state.handles`.            |
| [`registry`](enlace_auth.handles.registry.html.md#module-enlace_auth.handles.registry)   | The handle registry: which account holds which handle, kept unique under a lock.    |
| [`routes`](enlace_auth.handles.routes.html.md#module-enlace_auth.handles.routes)       | `/auth/handles/*`: the signed-in user's handle, the availability check, lookups.    |
