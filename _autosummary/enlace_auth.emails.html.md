# enlace_auth.emails

One normal form for an email address, wherever one is compared.

Accounts are keyed by the address the HTTP routes accept (pydantic `EmailStr`,
then lowercased): `EmailStr` decodes a punycode domain to Unicode, so
`admin@xn--bcher-kva.example` is stored as `admin@bücher.example`. Every list
an address is compared against (the admin list, the registration allowlist, a
connector’s resource allowlist) must be put in the same form, or an entry
spelled the other way silently never matches.

One fold is refused rather than applied: `EmailStr` NFC-composes the local
part, but a mail system may deliver a composed and a decomposed local part to two
mailboxes, which one key would merge (#51). [`normalize_email()`](#enlace_auth.emails.normalize_email) refuses a
local part that composing would change.

Two rules keep that safe. A written list entry is widened to both canonical
spellings of its address ([`account_spellings()`](#enlace_auth.emails.account_spellings)); the address an account is
keyed under, which may come from an untrusted party (an OAuth provider), is
compared exactly as stored and never normalized.

### Functions

| [`account_spellings`](#enlace_auth.emails.account_spellings)(email)       | The keys an account for a written *email* may be stored under, as written first.   |
|---------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| [`bare_address_problem`](#enlace_auth.emails.bare_address_problem)(email)    | Why *email* is not a bare `local@domain` address, or `None`.                       |
| [`local_part_problem`](#enlace_auth.emails.local_part_problem)(email)      | Why keying *email* would change its local part's characters, or `None`.            |
| [`normalize_email`](#enlace_auth.emails.normalize_email)(email)         | The key an account for *email* is stored under; `ValueError` if invalid.           |
| [`resolve_account`](#enlace_auth.emails.resolve_account)(email, exists) | The existing account key a written *email* names, or `None`.                       |

### enlace_auth.emails.account_spellings(email)

The keys an account for a written *email* may be stored under, as written first.

A punycode domain and its Unicode form are one DNS name, so they name one
mailbox, but an account is keyed in whichever spelling made it: `add-user`
and `/auth/register` store the Unicode form, an OAuth sign-in stores the
provider’s spelling, lowercased. A list entry written in either canonical
spelling therefore admits both.

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`...`](https://docs.python.org/3/builtins/constants.html#Ellipsis)]

```pycon
>>> account_spellings("Ann@XN--BCHER-KVA.example")
('ann@xn--bcher-kva.example', 'ann@bücher.example')
>>> account_spellings("ann@bücher.example")
('ann@bücher.example', 'ann@xn--bcher-kva.example')
>>> account_spellings("ann@corp.local")  # a domain EmailStr refuses
('ann@corp.local',)
```

Only an entry already in one of the two canonical spellings gets the other.
Normalizing also folds look-alikes (fullwidth letters, the Kelvin sign) onto
plain ASCII, so an entry that only becomes canonical by normalizing stays as
written: it must not name someone else’s account. That makes this safe to
apply to any written list, an untrusted user’s included. It is never applied
to the address an account is keyed under.

```pycon
>>> account_spellings("ann@ｂücher.example")  # fullwidth b
('ann@ｂücher.example',)
```

Lowercasing alone folds a few letters (U+212A KELVIN SIGN -> `k`); such an
entry is not widened either. Over-long strings are not looked at (nor cached).

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

### enlace_auth.emails.local_part_problem(email)

Why keying *email* would change its local part’s characters, or `None`.

`EmailStr` NFC-composes the local part. Mail systems that compare local
parts as bytes (a Postfix/Dovecot host with `SMTPUTF8`, for one) deliver
`josé` composed and `josé` decomposed to two mailboxes, so composing
would map both onto one account (#51). A decomposed local part is refused,
not folded, as an OAuth callback’s address is never folded.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

```pycon
>>> local_part_problem("josé@example.com") is None
True
>>> local_part_problem("josé@example.com")
'the part before @ is not in composed (NFC) form (U+0301); retype the address'
```

The two spellings look identical, so the message names the first character
to blame.

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

Nor is a local part that composing would change (see
[`local_part_problem()`](#enlace_auth.emails.local_part_problem)): the key would name another mailbox’s spelling.

```pycon
>>> normalize_email("josé@example.com")
Traceback (most recent call last):
...
ValueError: the part before @ is not in composed (NFC) form...
```

### enlace_auth.emails.resolve_account(email, exists)

The existing account key a written *email* names, or `None`.

Tries [`account_spellings()`](#enlace_auth.emails.account_spellings) in order, so an exact match wins over the
other spelling. *exists* is `key -> bool` (e.g. `users.__contains__`).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

```pycon
>>> users = {"ann@bücher.example"}
>>> resolve_account("Ann@XN--BCHER-KVA.example", users.__contains__)
'ann@bücher.example'
>>> resolve_account("bob@example.com", set().__contains__) is None
True
```
