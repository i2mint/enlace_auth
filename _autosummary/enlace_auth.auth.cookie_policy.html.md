# enlace_auth.auth.cookie_policy

Where the platform’s sign-in cookies go, in one place (#94).

Every sign-in path (password, reset, email code, passkey, OAuth, shared password)
sets the same kind of cookie, and every sign-out clears it. They used to build the
`Set-Cookie` line each on its own; [`CookiePolicy`](#enlace_auth.auth.cookie_policy.CookiePolicy) builds it once, so adding
an attribute (`Domain`) cannot miss a path.

`cookie_domain` (`[auth] cookie_domain`) lets one sign-in serve apps on sibling
subdomains of one parent (`a.apps.example.com`, `b.apps.example.com`, sign-in on
`apps.example.com`): sign-in cookies then carry `Domain=apps.example.com` when
the request came to that host or one under it. On any other host (an IP, a second
name) the cookie stays host-only, as a browser would refuse the `Domain` there.
Unset, nothing changes.

Every host under `cookie_domain` receives the session cookie, so it must be one
the platform serves: an outside service on a sibling subdomain would see it.

```pycon
>>> p = CookiePolicy(secure=True, domain="apps.example.com")
>>> p.set_header("s", "v", max_age=60, host="a.apps.example.com")
's=v; Path=/; HttpOnly; Max-Age=60; SameSite=Lax; Secure; Domain=apps.example.com'
>>> p.set_header("s", "v", max_age=60, host="10.0.0.5")
's=v; Path=/; HttpOnly; Max-Age=60; SameSite=Lax; Secure'
>>> len(p.clear_headers("s"))  # the Domain form and the host-only one
2
```

### Functions

| [`absolute_next_problem`](#enlace_auth.auth.cookie_policy.absolute_next_problem)(raw, domain)   | None when *raw* is an `https://` URL on *domain* or a host under it.        |
|---------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| [`cookie_domain_problem`](#enlace_auth.auth.cookie_policy.cookie_domain_problem)(domain)        | Why *domain* cannot be a `cookie_domain`, or None when it can.              |
| [`first_cookie`](#enlace_auth.auth.cookie_policy.first_cookie)(headers, name)          | The FIRST *name* cookie a request carries, as the auth middleware reads it. |
| [`host_within`](#enlace_auth.auth.cookie_policy.host_within)(host, domain)            | Whether *host* (a bare host name, no port) is *domain* or under it.         |
| [`request_host`](#enlace_auth.auth.cookie_policy.request_host)(headers)                | The lower-case host name a request was sent to (`Host` without its port).   |
| [`request_port`](#enlace_auth.auth.cookie_policy.request_port)(headers)                | The port in a request's `Host` header, when it names one (digits only).     |

### Classes

| [`CookiePolicy`](#enlace_auth.auth.cookie_policy.CookiePolicy)([secure, domain])   | The attributes of the platform's sign-in cookies.   |
|-----------------------------------------------------------------------------------|-----------------------------------------------------|

### *class* enlace_auth.auth.cookie_policy.CookiePolicy(secure=True, domain=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The attributes of the platform’s sign-in cookies.

`secure` adds `Secure`; `domain` is `[auth] cookie_domain`.

#### clear_cookie(response, name, , path='/')

Append [`clear_headers()`](#enlace_auth.auth.cookie_policy.CookiePolicy.clear_headers) to a Starlette *response*.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### clear_headers(name, , path='/')

`Set-Cookie` values that remove *name*: host-only, and the Domain form.

Both, whatever the host: a browser holding a cookie from before
`cookie_domain` was set (or after it was unset) must lose it too.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### domain_for(host)

The `Domain` to set for a request to *host*, or None (host-only).

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

#### set_cookie(response, name, value, \*\*kwargs)

Append [`set_headers()`](#enlace_auth.auth.cookie_policy.CookiePolicy.set_headers) to a Starlette *response*.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### set_header(name, value, , max_age, host=None, path='/')

The `Set-Cookie` value for a sign-in cookie sent to *host*.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### set_headers(name, value, , max_age, host=None, path='/')

The `Set-Cookie` values that leave exactly one *name* cookie in place.

When the cookie goes on the domain, an older host-only one is cleared
first: a browser would otherwise keep sending it first, and the platform,
reading the first, would keep seeing a session that may be dead.

* **Return type:**
  [`list`](https://docs.python.org/3/builtins/stdtypes.html#list)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.cookie_policy.absolute_next_problem(raw, domain)

None when *raw* is an `https://` URL on *domain* or a host under it.

Strict on purpose: the authority must be a plain host name (an optional port),
so a backslash, `@` or percent sign that a browser reads differently from
Python is refused, not parsed.

```pycon
>>> d = "apps.example.com"
>>> absolute_next_problem("https://a.apps.example.com/x?y=1", d)
>>> absolute_next_problem("https://evil.com\\.apps.example.com/", d)
'control or ambiguous character'
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.cookie_policy.cookie_domain_problem(domain)

Why *domain* cannot be a `cookie_domain`, or None when it can.

```pycon
>>> cookie_domain_problem("apps.example.com") is None
True
>>> cookie_domain_problem("localhost")
"'localhost' has no dot: browsers refuse a Domain cookie for a single label"
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.cookie_policy.first_cookie(headers, name)

The FIRST *name* cookie a request carries, as the auth middleware reads it.

A browser sends the more specific (older, host-only) cookie first, and a
sibling subdomain can plant a second one; Starlette’s `request.cookies`
keeps the last. Anything that re-issues or ends “the session” must act on
the one that was authenticated, which is the first.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.cookie_policy.host_within(host, domain)

Whether *host* (a bare host name, no port) is *domain* or under it.

```pycon
>>> host_within("a.apps.example.com", "apps.example.com")
True
>>> host_within("apps.example.com", "apps.example.com")
True
>>> host_within("evilapps.example.com", "apps.example.com")
False
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### enlace_auth.auth.cookie_policy.request_host(headers)

The lower-case host name a request was sent to (`Host` without its port).

*headers* is an ASGI header list or a mapping. Returns None for anything that
is not a plain host name.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.cookie_policy.request_port(headers)

The port in a request’s `Host` header, when it names one (digits only).

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]
