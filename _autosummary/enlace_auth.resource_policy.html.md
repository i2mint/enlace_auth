# enlace_auth.resource_policy

The OAuth per-connector allowlist: its shape, its parsing and its one rule.

`[auth.oauth_server.resource_allowlist]` maps a connector’s resource URL to the
emails allowed to authorize for it. The authorization server enforces it
([`enlace_auth.auth.oauth_server`](enlace_auth.auth.oauth_server.html.md#module-enlace_auth.auth.oauth_server)), the config model validates it
([`enlace_auth.config`](enlace_auth.config.html.md#module-enlace_auth.config)), and the admin dashboard describes it
([`enlace_auth.admin.routes`](enlace_auth.admin.routes.html.md#module-enlace_auth.admin.routes)). All three go through [`parse_resource_allowlist()`](#enlace_auth.resource_policy.parse_resource_allowlist)
here, so they cannot disagree about what a key means or what a value may hold.

The rule is **fail closed, and fail loudly on anything malformed**:

- A listed resource admits exactly its listed emails; `["*"]`
  ([`ANY_ACCOUNT`](#enlace_auth.resource_policy.ANY_ACCOUNT)), on its own, admits every authenticated account.
- A key must be the resource URL exactly as a connector spells its audience
  (lowercase scheme and host, no default port, no `//`, `.` or `..`), since
  a key in any other spelling can never match one.
- An unlisted resource is refused to everyone.
- A server with no allowlist at all would admit everyone to every resource. That
  is never the result of a typo: it has to be asked for with
  `allow_unlisted_resources = true`, and an allowlist that is present but
  malformed (a key that is not a URL, a value that is not a list of emails, a
  wildcard pattern, two keys that differ only by a trailing slash) is an error,
  not a guess.

The authorization server’s other config-time refusal lives here for the same
reason: `check_require_consent()` refuses to skip the consent screen, because
client registration is open to anyone (i2mint/enlace_auth#46).

Pure functions, no web or crypto imports, so the config model can use them.

### Module Attributes

| [`ANY_ACCOUNT`](#enlace_auth.resource_policy.ANY_ACCOUNT)   | A `resource_allowlist` entry that opens a resource to every authenticated account.   |
|----------------------------------------------------------------|--------------------------------------------------------------------------------------|

### Functions

| [`normalize_resource`](#enlace_auth.resource_policy.normalize_resource)(resource)             | Canonical form of a resource URL: the key both maps use, and the token `aud`.   |
|-------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| [`parse_resource_allowlist`](#enlace_auth.resource_policy.parse_resource_allowlist)(raw, \*[, ...]) | Validate *raw* and return `{normalized resource: lowercased emails}`.           |
| [`parse_resource_display_names`](#enlace_auth.resource_policy.parse_resource_display_names)(raw)        | Validate *raw* and return `{normalized resource: display name}`.                |

### enlace_auth.resource_policy.ANY_ACCOUNT *= '\*'*

A `resource_allowlist` entry that opens a resource to every authenticated
account. Must be written out: an unlisted resource is refused (fail-closed).

### enlace_auth.resource_policy.normalize_resource(resource)

Canonical form of a resource URL: the key both maps use, and the token `aud`.

```pycon
>>> normalize_resource("https://apps.example.com/api/x_mcp/mcp/")
'https://apps.example.com/api/x_mcp/mcp'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.resource_policy.parse_resource_allowlist(raw, , allow_unlisted_resources=False)

Validate *raw* and return `{normalized resource: lowercased emails}`.

Raises `ValueError` naming the offending entry for anything that is not
exactly the documented shape, and for an empty allowlist unless
*allow_unlisted_resources* says an open server is intended. Setting that flag
alongside a non-empty allowlist is also an error: the allowlist always refuses
unlisted resources, so the flag would promise something that does not happen.

```pycon
>>> allowlist = parse_resource_allowlist(
...     {"https://a.example/api/x/mcp/": ["Ann@Example.com", "bob@example.com"]}
... )
>>> {k: sorted(v) for k, v in allowlist.items()}
{'https://a.example/api/x/mcp': ['ann@example.com', 'bob@example.com']}
>>> parse_resource_allowlist({}, allow_unlisted_resources=True)
{}
```

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`frozenset`](https://docs.python.org/3/builtins/stdtypes.html#frozenset)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]]

### enlace_auth.resource_policy.parse_resource_display_names(raw)

Validate *raw* and return `{normalized resource: display name}`.

Keys follow the same rule as the allowlist’s, so a key that would never match
a resource is reported rather than silently showing generic consent copy.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]
