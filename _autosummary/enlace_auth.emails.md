# enlace_auth.emails

One normal form for an email address, wherever one is compared.

Accounts are keyed by the address the HTTP routes accept (pydantic `EmailStr`,
then lowercased): `EmailStr` decodes a punycode domain to Unicode, so
`admin@xn--bcher-kva.example` is stored as `admin@bücher.example`. Every list
an address is compared against (the admin list, the registration allowlist, a
connector’s resource allowlist) must be put in the same form, or an entry
spelled the other way silently never matches.

### Functions

| [`account_spellings`](#enlace_auth.emails.account_spellings)(email)    | The keys an account for an operator-written *email* may be stored under.   |
|------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| [`bare_address_problem`](#enlace_auth.emails.bare_address_problem)(email) | Why *email* is not a bare `local@domain` address, or `None`.               |
| [`normalize_email`](#enlace_auth.emails.normalize_email)(email)      | The key an account for *email* is stored under; `ValueError` if invalid.   |

### enlace_auth.emails.account_spellings(email)

The keys an account for an operator-written *email* may be stored under.

As written, lowercased (how an OAuth sign-in keys it), and normalized (how
`add-user` and `/auth/register` key it), when those differ. For lists an
operator wrote, never for an address an untrusted party sent: normalizing
that could fold a look-alike spelling onto someone else’s account.

* **Return type:**
  [`frozenset`](https://docs.python.org/3/builtins/stdtypes.html#frozenset)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

```pycon
>>> sorted(account_spellings("Ann@XN--BCHER-KVA.example"))
['ann@bücher.example', 'ann@xn--bcher-kva.example']
>>> sorted(account_spellings("ann@corp.local"))
['ann@corp.local']
```

### enlace_auth.emails.bare_address_problem(email)

Why *email* is not a bare `local@domain` address, or `None`.

Deliberately lenient about the domain (`.local`, `localhost`): it only
refuses what is not one plain address, such as the display-name form.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

```pycon
>>> bare_address_problem("ann@corp.local") is None
True
>>> bare_address_problem("ann <mallory@evil.com>")
'not a bare email address'
```

### enlace_auth.emails.normalize_email(email)

The key an account for *email* is stored under; `ValueError` if invalid.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

```pycon
>>> normalize_email("  Admin@XN--BCHER-KVA.example ")
'admin@bücher.example'
>>> normalize_email("A@Example.COM")
'a@example.com'
```

Only a bare address is accepted. `EmailStr` also parses the display-name
form, so `ann <mallory@evil.com>` would otherwise normalize to an address
the text does not appear to name; in a list that grants access, that is a
grant to someone other than the one written down.

```pycon
>>> normalize_email("ann <mallory@evil.com>")
Traceback (most recent call last):
...
ValueError: not a bare email address: 'ann <mallory@evil.com>'
```
