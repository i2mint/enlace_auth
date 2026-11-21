# enlace_auth.passkeys.core

Passkey ceremonies, the step-up proof, and the passkey-required policy.

No web framework here: [`PasskeyService`](#enlace_auth.passkeys.core.PasskeyService) takes and returns JSON-ready
values, so the HTTP router, the CLI and a test drive the same code. The WebAuthn
checks themselves are py_webauthn’s (BSD-3-Clause, a dependency), imported on
first use so a platform that never turns passkeys on never loads it.

Three ceremonies, one challenge format. A challenge is 40 bytes:
`nonce(16) | expiry(8) | mac(16)`, the mac an HMAC of the purpose, the account
and (for a step-up) the action, under the platform’s signing key. Nothing is
stored when a challenge is issued (the sign-in page asks for one on every view);
the answer carries it back inside `clientDataJSON`, the server recomputes the
mac from what it expects, and spends the challenge once through *claim_once*.
So a step-up challenge commits to the action: an answer signed for one action
cannot be presented for another.

A verified step-up returns a **proof**: a signed token, valid for
`proof_ttl` seconds, that names the account, the action and (for a step-up a
backend requested) the audience. An app or a connector backend redeems it once
([`PasskeyService.redeem()`](#enlace_auth.passkeys.core.PasskeyService.redeem)), stating the action it is about to perform; a
proof for another action or audience, an expired one or a spent one is refused.
Proofs and requests are method-agnostic ([`enlace_auth.auth.step_up`](enlace_auth.auth.step_up.html.md#module-enlace_auth.auth.step_up)); the
passkey is one method that mints them.

Records. A credential is stored under `sha256(credential id)` (hex, a safe
file name) as `{email, credential_id, public_key, user_handle, name,
created_at, device_type, backed_up, transports}`. Its use (`sign_count`,
`last_used_at`) is kept in a second mapping, so a sign-in that races a removal
writes an orphan usage record, never a resurrected credential. The WebAuthn user
handle is `HMAC(signing key, email)`: opaque, stable, and kept on each
credential so a sign-in compares against what was registered.

### Functions

| [`b64url`](#enlace_auth.passkeys.core.b64url)(data)                     | Unpadded base64url, the encoding WebAuthn JSON uses.                                                                                                   |
|-----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`clean_action`](#enlace_auth.passkeys.core.clean_action)(action)             | The action text of a step-up, checked: 1..300 printable characters.                                                                                    |
| [`clean_name`](#enlace_auth.passkeys.core.clean_name)(name)                 | A passkey's display name: printable, at most 60 characters, never empty.                                                                               |
| [`memory_claim`](#enlace_auth.passkeys.core.memory_claim)(\*[, keep_seconds]) | `claim(key) -> bool`: True the first time a key is claimed, then False.                                                                                |
| [`passkey_key`](#enlace_auth.passkeys.core.passkey_key)(credential_id)       | The store key (and public id) of a credential: sha256 of its raw id, hex.                                                                              |
| [`required_accounts`](#enlace_auth.passkeys.core.required_accounts)(entries)       | Lower-cased account keys from already-expanded entries.                                                                                                |
| [`unb64url`](#enlace_auth.passkeys.core.unb64url)(text)                   | Inverse of [`b64url()`](#enlace_auth.passkeys.core.b64url); raises [`PasskeyError`](#enlace_auth.passkeys.core.PasskeyError) on garbage. |

### Classes

| [`PasskeyPolicy`](#enlace_auth.passkeys.core.PasskeyPolicy)(required, count[, ...])        | Which accounts must sign in with a passkey.                                |
|-----------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| [`PasskeyService`](#enlace_auth.passkeys.core.PasskeyService)(credentials, \*, signing_key) | Register, sign in, step up, redeem and remove passkeys.                    |
| [`RelyingParty`](#enlace_auth.passkeys.core.RelyingParty)(id, name[, origins])            | Who the passkeys belong to: the RP ID, its display name, accepted origins. |

### Exceptions

| [`PasskeyError`](#enlace_auth.passkeys.core.PasskeyError)   | A passkey request that cannot be honoured; the message is safe to show.   |
|-----------------------------------------------------------------|---------------------------------------------------------------------------|

### *exception* enlace_auth.passkeys.core.PasskeyError

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

A passkey request that cannot be honoured; the message is safe to show.

### *class* enlace_auth.passkeys.core.PasskeyPolicy(required, count, enforce_from=2, synced=<function PasskeyPolicy.<lambda>>)

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

### *class* enlace_auth.passkeys.core.PasskeyService(credentials, \*, signing_key, usage=None, claim_once=None, challenge_ttl=300, proof_ttl=120, request_ttl=900, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Register, sign in, step up, redeem and remove passkeys.

* **Parameters:**
  * **credentials** ([`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)) – credential records, `sha256(id) hex -> dict`.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the platform’s HMAC key (challenges, proofs, user handles).
  * **usage** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)]) – `sha256(id) hex -> {sign_count, last_used_at}` (default: a dict).
  * **claim_once** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]) – `claim(sha256 hex) -> bool`, True once per key; spends
    challenges and proofs (default: [`memory_claim()`](#enlace_auth.passkeys.core.memory_claim)).
  * **request_ttl** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – lifetimes in seconds (a
    backend’s step-up request must outlive a sign-in on the way).
  * **clock** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`float`](https://docs.python.org/3/builtins/functions.html#float)]) – `() -> epoch seconds`; tests pass a fake.

#### count(email, , rp_id=None, purpose=None)

How many general passkeys *email* has (for *rp_id*, if given).

A purpose-bound one cannot sign in, so it does not count toward the
passkey-required policy; pass *purpose* to count those instead.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

#### describe(key, record)

The public view of one passkey (no key material).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### list(email, \*, purpose=<object object>)

The passkeys of *email*, oldest first (of one *purpose*, if given).

Listing one purpose adds each credential’s id and COSE public key
(base64url), so a verifier that checks assertions itself can pin them.

* **Return type:**
  [`list`](#enlace_auth.passkeys.core.PasskeyService.list)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

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

#### proofs

Proofs and requests, shared with any other step-up method.

#### records(email=None, \*, rp_id=None, purpose=<object object>)

`(key, record)` of every readable credential (of *email*, if given).

With *rp_id*, only the credentials made for that relying party: a passkey
made for another RP ID can no longer sign in, so it must not count.
With *purpose*, only those of that purpose (`None`: the general ones).
A damaged record is skipped, never raised: the store is hand-editable.

* **Return type:**
  [`list`](#enlace_auth.passkeys.core.PasskeyService.list)[[`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]]

#### redeem(proof, action, , email, audience=None, methods=None, purpose=None)

Spend a step-up proof for *action* by *email*; return what it proves.

`{email, action, audience, verified_at, method, passkey}`. Raises
[`PasskeyError`](#enlace_auth.passkeys.core.PasskeyError) for a forged, expired, spent, other-action,
other-account or other-audience proof, one confirmed by a method outside
*methods*, or one whose passkey has since been removed. The caller names
the account it expects, so “someone confirmed” can never pass for “the
owner confirmed”.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### register(email, credential, rp, , name='', purpose=None)

Verify a registration answer and store the passkey; return its view.

*purpose* must be the one the options were made for (the challenge
commits to it).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### registration_options(email, rp, , purpose=None, label='')

`PublicKeyCredentialCreationOptionsJSON` for adding a passkey to *email*.

A discoverable credential with user verification (a passkey proper),
excluding the account’s existing ones of the same purpose so a device is
not enrolled twice. With *purpose* (#97) the credential gets a user
handle of its own and the system sheet’s name is *label* (“Start a job
on my Mac”), so the person recognises it at the tap.

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

#### step_up(email, action, credential, rp, , audience=None, purpose=None)

Verify a step-up for *action*; return `{proof, action, expires_in}`.

With *audience* (a step-up a backend requested), the challenge must have
committed to it and the proof redeems only where it is named. The passkey
used must be of *purpose* (`None`: a general one).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### step_up_options(email, action, rp, , audience=None, purpose=None)

Request options for confirming *action* with one of *email*’s passkeys.

The challenge commits to the action and the audience. Only passkeys of
*purpose* are offered (`None`: the general ones, never a purpose-bound
one). Raises [`PasskeyError`](#enlace_auth.passkeys.core.PasskeyError) when the account has none.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### synced(email, , rp_id=None)

Whether one of *email*’s passkeys is synced (backed up by its provider).

A synced passkey lives on every device of its keychain (iCloud Keychain,
Google Password Manager), so losing one device does not lose it.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

#### user_handle(email, purpose=None)

The WebAuthn user handle of an account: opaque, stable, 32 bytes.

A purpose-bound passkey gets a handle of its own, so an authenticator
keeps it beside the account’s sign-in passkey instead of replacing it.

* **Return type:**
  [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)

### *class* enlace_auth.passkeys.core.RelyingParty(id, name, origins=tuple())

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

### enlace_auth.passkeys.core.b64url(data)

Unpadded base64url, the encoding WebAuthn JSON uses.

```pycon
>>> b64url(b"\xfb\xff")
'-_8'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.core.clean_action(action)

The action text of a step-up, checked: 1..300 printable characters.

```pycon
>>> clean_action("  start job: repo, title ")
'start job: repo, title'
>>> clean_action("two\nlines")
Traceback (most recent call last):
  ...
enlace_auth.passkeys.core.PasskeyError: An action is one line of at most 300 ...
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.core.clean_name(name)

A passkey’s display name: printable, at most 60 characters, never empty.

```pycon
>>> clean_name(""), clean_name("  Touch ID on the Mac ")
('Passkey', 'Touch ID on the Mac')
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.core.memory_claim(, keep_seconds=3600.0)

`claim(key) -> bool`: True the first time a key is claimed, then False.

In-process only: right for one worker and for tests. A platform running
several worker processes injects a cross-process claim instead (the plugin
uses the same `O_EXCL` file claim as the OAuth server). Claims older than
*keep_seconds* are forgotten, which is safe because every claimed thing
(a challenge, a proof) expires well before.

```pycon
>>> claim = memory_claim()
>>> claim("a"), claim("a"), claim("b")
(True, False, True)
```

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]

### enlace_auth.passkeys.core.passkey_key(credential_id)

The store key (and public id) of a credential: sha256 of its raw id, hex.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.passkeys.core.required_accounts(entries)

Lower-cased account keys from already-expanded entries.

```pycon
>>> sorted(required_accounts(["A@x.io", "b@x.io", ""]))
['a@x.io', 'b@x.io']
```

* **Return type:**
  [`frozenset`](https://docs.python.org/3/builtins/stdtypes.html#frozenset)

### enlace_auth.passkeys.core.unb64url(text)

Inverse of [`b64url()`](#enlace_auth.passkeys.core.b64url); raises [`PasskeyError`](#enlace_auth.passkeys.core.PasskeyError) on garbage.

```pycon
>>> unb64url("-_8")
b'\xfb\xff'
```

* **Return type:**
  [`bytes`](https://docs.python.org/3/builtins/stdtypes.html#bytes)
