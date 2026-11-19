# enlace_auth.passkeys

Passkeys (WebAuthn): sign-in, a step-up confirmation, and a per-account requirement.

Turned on by `[auth.passkeys] enabled = true` (py_webauthn does the WebAuthn
checks). Four pieces, one boundary:

1. **Add passkeys to any account** from `/auth/account`: several per account,
   each named and removable, a notice mailed on each change
   (`/auth/passkeys/register/*`, `DELETE /auth/passkeys/{id}`).
2. **Sign in with a passkey**, including autofill on the sign-in page’s email
   field (`/auth/passkeys/login/*`). The email code stays the way back in.
3. **Step-up**: an app asks the signed-in user to confirm one described action
   with a passkey and gets a single-use, short-lived proof that its backend (or
   a connector’s) redeems before acting (`/auth/passkeys/step-up/*`).
4. **Policy**: `[auth.passkeys] required` lists accounts (emails, `@group`,
   `@admins`) that must sign in with a passkey once they have
   `enforce_from` of them. Enforced in `open_session`, which every sign-in
   path goes through.

The logic is in [`enlace_auth.passkeys.core`](enlace_auth.passkeys.core.html.md#module-enlace_auth.passkeys.core) (no web framework), the HTTP
surface in [`enlace_auth.passkeys.routes`](enlace_auth.passkeys.routes.html.md#module-enlace_auth.passkeys.routes), the browser side in
`passkeys.js` (served at `/auth/passkeys/passkeys.js`).

### Classes

| [`PasskeyPolicy`](#enlace_auth.passkeys.PasskeyPolicy)(required, count[, ...])        | Which accounts must sign in with a passkey.                                |
|-----------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| [`PasskeyService`](#enlace_auth.passkeys.PasskeyService)(credentials, \*, signing_key) | Register, sign in, step up, redeem and remove passkeys.                    |
| [`RelyingParty`](#enlace_auth.passkeys.RelyingParty)(id, name[, origins])            | Who the passkeys belong to: the RP ID, its display name, accepted origins. |

### Exceptions

| [`PasskeyError`](#enlace_auth.passkeys.PasskeyError)   | A passkey request that cannot be honoured; the message is safe to show.   |
|-----------------------------------------------------------------|---------------------------------------------------------------------------|

### *exception* enlace_auth.passkeys.PasskeyError

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

A passkey request that cannot be honoured; the message is safe to show.

### *class* enlace_auth.passkeys.PasskeyPolicy(required, count, enforce_from=2, synced=<function PasskeyPolicy.<lambda>>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Which accounts must sign in with a passkey.

*required* holds account keys (lower-case, every spelling already listed).
The rule applies to an account once it has *enforce_from* passkeys, or one
synced passkey (*synced*: it is on every device of its keychain); below
that it may still sign in by its other methods, so it can enrol (a lockout
guard: one lost device must not lock an account out).

```pycon
>>> p = PasskeyPolicy(frozenset({"a@x.io"}), count=lambda e: 2, enforce_from=2)
>>> p.refusal("a@x.io", "password") is not None, p.refusal("a@x.io", "passkey")
(True, None)
>>> one = PasskeyPolicy(frozenset({"a@x.io"}), count=lambda e: 1)
>>> one.refusal("a@x.io", "password")  # below enforce_from: not yet
>>> p.refusal("b@x.io", "password")
```

#### enforced(email)

True when *email* is required to use a passkey right now.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### refusal(email, method)

`None` to admit a sign-in by *method*, else the reason to refuse.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### *class* enlace_auth.passkeys.PasskeyService(credentials, \*, signing_key, usage=None, claim_once=None, challenge_ttl=300, proof_ttl=120, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Register, sign in, step up, redeem and remove passkeys.

* **Parameters:**
  * **credentials** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – credential records, `sha256(id) hex -> dict`.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the platform’s HMAC key (challenges, proofs, user handles).
  * **usage** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)]) – `sha256(id) hex -> {sign_count, last_used_at}` (default: a dict).
  * **claim_once** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]) – `claim(sha256 hex) -> bool`, True once per key; spends
    challenges and proofs (default: `memory_claim()`).
  * **proof_ttl** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – lifetimes in seconds.
  * **clock** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`float`](https://docs.python.org/3/builtins/functions.html#float)]) – `() -> epoch seconds`; tests pass a fake.

#### count(email, , rp_id=None)

How many passkeys *email* has (for *rp_id*, if given).

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### describe(key, record)

The public view of one passkey (no key material).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list(email)

The passkeys of *email*, oldest first.

* **Return type:**
  [`list`](#enlace_auth.passkeys.PasskeyService.list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### login(credential, rp)

Verify a sign-in assertion; return the account it signs in.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### login_options(rp)

`PublicKeyCredentialRequestOptionsJSON` for a sign-in by any passkey.

No `allowCredentials`: the authenticator offers the account’s passkey
(and the browser can show it in the email field’s autofill).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### records(email=None, , rp_id=None)

`(key, record)` of every readable credential (of *email*, if given).

With *rp_id*, only the credentials made for that relying party: a passkey
made for another RP ID can no longer sign in, so it must not count.
A damaged record is skipped, never raised: the store is hand-editable.

* **Return type:**
  [`list`](#enlace_auth.passkeys.PasskeyService.list)[[`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]]

#### redeem(proof, action, , email)

Spend a step-up proof for *action* by *email*; return what it proves.

`{email, action, verified_at, method, passkey}`. Raises
[`PasskeyError`](#enlace_auth.passkeys.PasskeyError) for a forged, expired, spent, other-action or
other-account proof, or one whose passkey has since been removed. The
caller names the account it expects, so “someone confirmed” can never
pass for “the owner confirmed”.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### register(email, credential, rp, , name='')

Verify a registration answer and store the passkey; return its view.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### registration_options(email, rp)

`PublicKeyCredentialCreationOptionsJSON` for adding a passkey to *email*.

A discoverable credential with user verification (a passkey proper),
excluding the account’s existing ones so a device is not enrolled twice.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### remove(email, key)

Remove the passkey *key* of *email*; return its view, or None.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### remove_account(email)

Remove every passkey of *email*; return how many went.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### step_up(email, action, credential, rp)

Verify a step-up for *action*; return `{proof, action, expires_in}`.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### step_up_options(email, action, rp)

Request options for confirming *action* with one of *email*’s passkeys.

The challenge commits to the action. Raises [`PasskeyError`](#enlace_auth.passkeys.PasskeyError) when the
account has no passkey.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### synced(email, , rp_id=None)

Whether one of *email*’s passkeys is synced (backed up by its provider).

A synced passkey lives on every device of its keychain (iCloud Keychain,
Google Password Manager), so losing one device does not lose it.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### user_handle(email)

The WebAuthn user handle of an account: opaque, stable, 32 bytes.

* **Return type:**
  [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)

### *class* enlace_auth.passkeys.RelyingParty(id, name, origins=tuple())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Who the passkeys belong to: the RP ID, its display name, accepted origins.

The RP ID is a host name every accepted origin is on or under, so one
passkey covers every app served from those origins.

```pycon
>>> rp = RelyingParty("example.com", "Example", ("https://apps.example.com",))
>>> RelyingParty("example.com", "x", ("https://evil.com",))
Traceback (most recent call last):
  ...
ValueError: origin 'https://evil.com' is not on 'example.com' or a subdomain of it
```

#### *classmethod* for_origin(origin, , rp_id=None, name=None)

The relying party of one origin (RP ID: its host, unless given).

```pycon
>>> RelyingParty.for_origin("https://apps.example.com/").id
'apps.example.com'
```

### Modules

| [`core`](enlace_auth.passkeys.core.html.md#module-enlace_auth.passkeys.core)     | Passkey ceremonies, the step-up proof, and the passkey-required policy.      |
|--------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|
| [`pages`](enlace_auth.passkeys.pages.html.md#module-enlace_auth.passkeys.pages)   | The passkey markup on the sign-in and account pages.                         |
| [`routes`](enlace_auth.passkeys.routes.html.md#module-enlace_auth.passkeys.routes) | `/auth/passkeys/*`: add, list and remove passkeys; sign in; step up; redeem. |
| [`texts`](enlace_auth.passkeys.texts.html.md#module-enlace_auth.passkeys.texts)   | The passkey screens' copy and notification mails, in English and French.     |
