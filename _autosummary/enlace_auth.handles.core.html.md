# enlace_auth.handles.core

What a handle is: its normal form, its rules, and the default made from an email.

A *handle* (a username) is the public name of an account: unique, case-insensitive,
shown as `@name`. The account itself stays keyed by its email, which no other user
and no browser of another user ever sees. This module is pure (no web, no storage
imports), so the rules can move unchanged; `registry.py` holds the state.

The rules, and why (the research behind each is in
`misc/docs/research/general/usernames.md`):

- **ASCII only**: lowercase `a-z`, digits, and the separators `.`, `_`, `-`.
  Input is NFKC-normalised and case-folded first, so `ThorWhalen` and fullwidth
  `ｔｈｏｒ` are accepted and stored as `thorwhalen` / `thor`. Restricting the
  stored form to ASCII removes the Unicode confusables problem (UTS #39) instead of
  detecting it.
- **Case-insensitive by construction**: the stored form is lowercase, so the
  display form and the comparison form are the same string.
- **Separators and look-alikes do not distinguish**: `john.smith`, `john_smith`,
  `johnsmith` and `j0hnsmith` have one [`uniqueness_key()`](#enlace_auth.handles.core.uniqueness_key), so a name cannot
  be impersonated by moving a dot or swapping `o` for `0`.
  A separator may not start or end a handle, nor follow another one (so a trailing
  dot is never swallowed as punctuation after `@name.`).
- **Not all digits**: an all-digit handle reads as an id.
- **Reserved words** (`RESERVED`): routes, roles and system words that would
  let an account pass for the platform. A host adds its own (its group names).

```pycon
>>> normalize("@ThorWhalen ")
'thorwhalen'
>>> handle_problem("thorwhalen") is None
True
>>> handle_problem("thor..whalen")
'A dot, dash or underscore cannot follow another one.'
>>> {uniqueness_key(h) for h in ("john.smith", "john_smith", "j0hnsmith")}
{'johnsmlth'}
>>> base_from_email("John.Smith+news@example.com")
'john.smith'
>>> list(candidates("bo", limit=3))
['bo1', 'bo2', 'bo3']
```

### Functions

| [`base_from_email`](#enlace_auth.handles.core.base_from_email)(email, \*[, policy])               | The base of a default handle: the email's local part, made into a handle.                                                                 |
|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| [`candidates`](#enlace_auth.handles.core.candidates)(base, \*[, policy, limit, rng, tries])  | Valid handles to try, in order: *base*, `base1` .                                                                                         |
| [`handle_problem`](#enlace_auth.handles.core.handle_problem)(handle, \*[, policy])               | Why *handle* (already normalised) cannot be a handle, or `None` if it can.                                                                |
| [`normalize`](#enlace_auth.handles.core.normalize)(text)                                    | The stored form of what a person typed: NFKC, case-folded, trimmed, no `@`.                                                               |
| [`suggestions`](#enlace_auth.handles.core.suggestions)(wanted, is_free, \*[, policy, n, ...]) | Up to *n* free handles close to *wanted*, for a name that is taken or invalid.                                                            |
| [`uniqueness_key`](#enlace_auth.handles.core.uniqueness_key)(handle)                             | The form two handles are compared by: normalised, without separators, with look-alike characters folded (`0` as `o`; `1` and `i` as `l`). |

### Classes

| [`HandlePolicy`](#enlace_auth.handles.core.HandlePolicy)([min_length, max_length, ...])   | The knobs of the handle rules.   |
|------------------------------------------------------------------------------------------------|----------------------------------|

### *class* enlace_auth.handles.core.HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'about', 'abuse', 'account', 'accounts', 'admin', 'administrator', 'admins', 'all', 'anonymous', 'api', 'app', 'apps', 'auth', 'autoconfig', 'autodiscover', 'blog', 'callback', 'check', 'contact', 'csrf', 'dashboard', 'deleted', 'docs', 'everyone', 'false', 'favicon', 'guest', 'help', 'here', 'home', 'hostmaster', 'info', 'localhost', 'login', 'logout', 'mail', 'mailer-daemon', 'me', 'mod', 'moderator', 'mods', 'new', 'no-reply', 'nobody', 'noc', 'none', 'noreply', 'null', 'oauth', 'official', 'operator', 'owner', 'postmaster', 'privacy', 'register', 'removed', 'robots', 'root', 'search', 'security', 'settings', 'signin', 'signout', 'signup', 'staff', 'static', 'status', 'store', 'superuser', 'support', 'sysadmin', 'system', 'team', 'terms', 'test', 'true', 'undefined', 'unknown', 'user', 'users', 'webmaster', 'well-known', 'wpad', 'www', 'xrpc', 'you'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The knobs of the handle rules. The defaults are the platform’s.

*reserved* is compared by [`uniqueness_key()`](#enlace_auth.handles.core.uniqueness_key), so reserving `no-reply` also
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
  [`HandlePolicy`](#enlace_auth.handles.core.HandlePolicy)

### enlace_auth.handles.core.base_from_email(email, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000))

The base of a default handle: the email’s local part, made into a handle.

The `+tag` of plus-addressing is dropped (it is private routing, and often
names the site), accents are folded, other characters removed, separator runs
collapsed, and the result cut so a suffix still fits. When nothing usable is
left, or the local part is a reserved word (`info@`, `admin@`: role
mailboxes), *policy.fallback_base*. The base may still be too short:
[`candidates()`](#enlace_auth.handles.core.candidates) then starts at the first suffix.

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

### enlace_auth.handles.core.candidates(base, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), limit=None, rng=None, tries=None)

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

### enlace_auth.handles.core.handle_problem(handle, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000))

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

### enlace_auth.handles.core.normalize(text)

The stored form of what a person typed: NFKC, case-folded, trimmed, no `@`.

It does not validate: [`handle_problem()`](#enlace_auth.handles.core.handle_problem) does, on this form.

```pycon
>>> normalize("  @Ｔhor_Whalen")
'thor_whalen'
>>> normalize("Straße")
'strasse'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.handles.core.suggestions(wanted, is_free, , policy=HandlePolicy(min_length=3, max_length=30, reserved=frozenset({'contact', 'webmaster', 'mail', 'none', 'postmaster', 'about', 'superuser', 'noreply', 'unknown', 'deleted', 'status', 'favicon', 'accounts', 'here', 'search', 'admins', 'autodiscover', 'blog', 'app', 'help', 'info', 'csrf', 'you', 'system', 'official', 'team', 'anonymous', 'root', 'static', 'new', 'logout', 'www', 'null', 'moderator', 'apps', 'signup', 'test', 'robots', 'signin', 'guest', 'abuse', 'api', 'docs', 'check', 'user', 'security', 'sysadmin', 'wpad', 'no-reply', 'signout', 'hostmaster', 'removed', 'privacy', 'callback', 'mods', 'users', 'owner', 'everyone', 'mailer-daemon', 'undefined', 'localhost', 'staff', 'operator', 'support', 'all', 'noc', 'me', 'nobody', 'store', 'mod', 'true', 'xrpc', 'admin', 'administrator', 'dashboard', 'login', 'auth', 'register', 'settings', 'home', 'well-known', 'autoconfig', 'account', 'false', 'terms', 'oauth'}), fallback_base='user', max_sequential=99, random_suffix_digits=6, random_tries=1000), n=3, max_tries=200)

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

### enlace_auth.handles.core.uniqueness_key(handle)

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
