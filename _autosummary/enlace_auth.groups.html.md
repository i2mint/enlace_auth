# enlace_auth.groups

Named groups of accounts: one list of emails, referenced as `@name` wherever an
email list is.

`[auth.groups]` in `platform.toml` names lists of emails:

```default
[auth.groups]
acme = ["ann@acme.com", "bob@acme.com"]
```

and `@acme` then stands for that list in an app’s `allowed_users` and in a
connector’s `[auth.oauth_server.resource_allowlist]` entry. A client team that may
reach two connectors and a document room is listed once; adding or removing a person
is one edit.

`@admins` is the built-in group (the platform admins, see
`enlace_auth.plugin.ADMINS_ALIAS`), so `admins` cannot be declared here.

Unknown references fail closed in both places, differently because the cost differs:
in a connector allowlist (validated when the config loads) an unknown `@name` is an
error, as every malformed allowlist entry is; in an app’s `allowed_users` it is kept
as written, so it matches no account and the app admits nobody, since refusing to
start would take every other app down with it (the same rule as `@admins` with no
admins configured).

Pure functions, no web imports, so the config model can use them.

### Module Attributes

| [`GROUP_PREFIX`](#enlace_auth.groups.GROUP_PREFIX)    | `@name`                                                                        |
|------------------------------------------------------------------|--------------------------------------------------------------------------------|
| [`RESERVED_GROUPS`](#enlace_auth.groups.RESERVED_GROUPS) | names enlace_auth defines itself (`@admins`), not redefinable in [auth.groups] |

### Functions

| [`expand_groups`](#enlace_auth.groups.expand_groups)(entries, groups, \*[, where, ...])   | *entries* with every `@name` of *groups* replaced by its emails, in order, deduplicated.   |
|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| [`is_group_ref`](#enlace_auth.groups.is_group_ref)(entry)                                | Whether *entry* names a group (`@name`) rather than an email.                              |
| [`parse_groups`](#enlace_auth.groups.parse_groups)(raw)                                  | Validate `[auth.groups]`: `{name: (email, ...)}`, or `ValueError` naming the entry.        |

### enlace_auth.groups.GROUP_PREFIX *= '@'*

`@name`

* **Type:**
  how an email list refers to a group

### enlace_auth.groups.RESERVED_GROUPS *= frozenset({'admins'})*

names enlace_auth defines itself (`@admins`), not redefinable in [auth.groups]

### enlace_auth.groups.expand_groups(entries, groups, , where='', unknown='raise')

*entries* with every `@name` of *groups* replaced by its emails, in order,
deduplicated.

Entries that are not group references pass through (emails, `*`, and the built-in
`@admins`, which its own expansion handles). An unknown `@name` raises
`ValueError` (`unknown="raise"`) or is kept as written (`unknown="keep"`),
where it matches no account.

```pycon
>>> acme = {"acme": ["ann@acme.com", "bob@acme.com"]}
>>> expand_groups(["@acme", "cy@x.com", "ann@acme.com"], acme)
['ann@acme.com', 'bob@acme.com', 'cy@x.com']
```

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)

### enlace_auth.groups.is_group_ref(entry)

Whether *entry* names a group (`@name`) rather than an email.

```pycon
>>> is_group_ref("@acme"), is_group_ref("ann@acme.com"), is_group_ref("*")
(True, False, False)
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### enlace_auth.groups.parse_groups(raw)

Validate `[auth.groups]`: `{name: (email, ...)}`, or `ValueError` naming
the entry.

A name is lowercase letters, digits, `-` and `_`; `admins` is reserved; each
member is one bare address (no `@group` inside a group, no `*`); a group is
never empty, since an `allowed_users` that expanded to nothing admits everyone.

```pycon
>>> parse_groups({"acme": ["Ann@acme.com"]})
{'acme': ('Ann@acme.com',)}
```

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`...`](https://docs.python.org/3/builtins/constants.html#Ellipsis)]]
