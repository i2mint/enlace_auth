# enlace_auth.auth.reset_tokens

Password-reset tokens — minting, verification, and the link they live in.

Single source of truth for the reset-link format, shared by the three callers
that must agree on it byte-for-byte: the self-service
`/auth/password-reset/*` endpoints, the admin
`POST /_admin/api/users/{email}/reset-link` endpoint, and the
`enlace-auth reset-link` CLI.

The token is a *signed* (never encrypted) string carrying three fields:

```default
<password fingerprint> | <absolute expiry, epoch seconds> | <email>
```

Two properties fall out of that shape, and neither needs a server-side token
store:

- **Single use.** The fingerprint is a hash of the account’s *current* password
  hash. Consuming a link changes the password, which changes the hash, which
  invalidates that token — and every other link outstanding for the account.
- **Per-link lifetime.** The expiry lives *inside* the signed payload rather
  than being applied at verification time, so one verifier serves both the
  short-lived link sent by email and the longer-lived link an admin hands over
  out-of-band (chat, a phone call) when SMTP isn’t configured.

The signature covers the expiry, so a longer lifetime cannot be forged. A
second, independent ceiling ([`MAX_TTL_SECONDS`](#enlace_auth.auth.reset_tokens.MAX_TTL_SECONDS)) is still applied at the
signature layer, so no token can outlive it even if the embedded expiry is
somehow mis-parsed.

### Module Attributes

| [`DEFAULT_EMAIL_TTL`](#enlace_auth.auth.reset_tokens.DEFAULT_EMAIL_TTL)   | Lifetime of a link delivered by email — short, because the inbox is a hostile place to leave a credential lying around.             |
|----------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------|
| [`DEFAULT_HANDOFF_TTL`](#enlace_auth.auth.reset_tokens.DEFAULT_HANDOFF_TTL) | Lifetime of a link an admin mints and delivers by hand.                                                                             |
| [`MAX_TTL_SECONDS`](#enlace_auth.auth.reset_tokens.MAX_TTL_SECONDS)     | Absolute ceiling on any reset link, enforced at the signature layer as a second bound independent of the expiry inside the payload. |

### Functions

| [`mint_reset_token`](#enlace_auth.auth.reset_tokens.mint_reset_token)(\*, record, email, signing_key)   | Return a signed reset token for `email`, valid for `ttl_seconds`.     |
|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| [`password_fingerprint`](#enlace_auth.auth.reset_tokens.password_fingerprint)(record)                       | Return a short, stable fingerprint of a user's current password hash. |
| [`reset_url`](#enlace_auth.auth.reset_tokens.reset_url)(base_url, token)                         | Return the full `/auth/reset-password` link carrying `token`.         |
| [`verify_reset_token`](#enlace_auth.auth.reset_tokens.verify_reset_token)(token, \*, signing_key, ...)    | Return `(email, record)` for a valid token, else `(None, None)`.      |

### enlace_auth.auth.reset_tokens.DEFAULT_EMAIL_TTL *= 1800*

Lifetime of a link delivered by email — short, because the inbox is a
hostile place to leave a credential lying around.

### enlace_auth.auth.reset_tokens.DEFAULT_HANDOFF_TTL *= 259200*

Lifetime of a link an admin mints and delivers by hand. Longer because the
round trip is human: the admin sends it, the recipient reads it later.

### enlace_auth.auth.reset_tokens.MAX_TTL_SECONDS *= 2592000*

Absolute ceiling on any reset link, enforced at the signature layer as a
second bound independent of the expiry inside the payload.

### enlace_auth.auth.reset_tokens.mint_reset_token(, record, email, signing_key, ttl_seconds=1800)

Return a signed reset token for `email`, valid for `ttl_seconds`.

* **Parameters:**
  * **record** ([`Mapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Mapping)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`Any`](https://docs.python.org/3/library/typing.html#typing.Any)]) – the user’s stored record (read for its `password_hash`).
  * **email** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the account the token authorizes a password change for.
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – platform HMAC key.
  * **ttl_seconds** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – how long the link stays usable. Clamped to
    [`MAX_TTL_SECONDS`](#enlace_auth.auth.reset_tokens.MAX_TTL_SECONDS).
* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.reset_tokens.password_fingerprint(record)

Return a short, stable fingerprint of a user’s current password hash.

Embedded in reset tokens so a token stops working the moment the password
changes. That is what makes every link naturally single-use (using it
changes the hash) and what invalidates outstanding links after any other
password change.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.reset_tokens.reset_url(base_url, token)

Return the full `/auth/reset-password` link carrying `token`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.reset_tokens.verify_reset_token(token, , signing_key, user_store)

Return `(email, record)` for a valid token, else `(None, None)`.

Four independent checks must all pass: the signature, the signature-layer
age ceiling, the expiry embedded in the payload, and that the password
fingerprint still matches the stored hash (the single-use property).

* **Return type:**
  [`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]]
