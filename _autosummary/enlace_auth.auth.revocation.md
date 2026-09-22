# enlace_auth.auth.revocation

Credential revocation: end everything an account holds when its credentials change.

An account’s access outlives a password change in three places, each with its own
lifetime: browser **sessions** (`session_max_age`), OAuth connector
**refresh-token families** (`refresh_family_max_lifetime`), and the per-app
**shared-password cookies** (which are not per account at all – see
[`shared_password_fingerprint()`](#enlace_auth.auth.revocation.shared_password_fingerprint)). This module is the one place that knows how
to end the first two, so every path that changes an account’s credentials
(admin delete, admin password set, self-service change, reset-link redemption,
the `set-password` CLI) calls a single [`make_on_credentials_changed()`](#enlace_auth.auth.revocation.make_on_credentials_changed) hook
instead of each remembering its own list.

Kept free of FastAPI/Authlib imports so the CLI can use it without the
`[oauth]` extra.

### Functions

| [`make_on_credentials_changed`](#enlace_auth.auth.revocation.make_on_credentials_changed)(session_store, \*)    | Return the hook every credential-changing path calls.                       |
|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| [`refresh_tombstone_ttl`](#enlace_auth.auth.revocation.refresh_tombstone_ttl)(\*, refresh_token_ttl, ...) | How long a family tombstone must live: past every token of the family.      |
| [`revoke_refresh_family`](#enlace_auth.auth.revocation.revoke_refresh_family)(refresh_store, family, ...) | Revoke one refresh-token family; return how many token records went.        |
| [`revoke_refresh_subject`](#enlace_auth.auth.revocation.revoke_refresh_subject)(refresh_store, email, ...) | Revoke every refresh family issued to *email*; return how many families.    |
| [`revoked_family_key`](#enlace_auth.auth.revocation.revoked_family_key)(family)                        | Store key of the tombstone that marks a whole refresh family revoked.       |
| [`subject_marker_key`](#enlace_auth.auth.revocation.subject_marker_key)(email)                         | Store key of the marker that says "nothing *email* authorized before T".    |
| [`subject_revoked_before`](#enlace_auth.auth.revocation.subject_revoked_before)(refresh_store, email)      | The time before which every authorization by *email* is revoked, if any.    |
| [`shared_cookie_valid`](#enlace_auth.auth.revocation.shared_cookie_valid)(value, password_hash, ...)    | True iff a verified shared-cookie *value* was minted under *password_hash*. |
| [`shared_password_fingerprint`](#enlace_auth.auth.revocation.shared_password_fingerprint)(password_hash, ...)   | A short keyed fingerprint of an app's CURRENT shared-password hash.         |

### Classes

| [`CredentialsChanged`](#enlace_auth.auth.revocation.CredentialsChanged)(\*args, \*\*kwargs)   | `on_credentials_changed(email, *, keep=None) -> None`.   |
|-------------------------------------------------------------------------------------------|----------------------------------------------------------|

### *class* enlace_auth.auth.revocation.CredentialsChanged(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

`on_credentials_changed(email, *, keep=None) -> None`.

*keep* names one browser session id to spare (the browser that just changed
its own password stays signed in).

### enlace_auth.auth.revocation.make_on_credentials_changed(session_store, , refresh_store=None, code_store=None, tombstone_ttl=0, marker_ttl=0, reason="the account's credentials changed")

Return the hook every credential-changing path calls.

Always revokes the account’s browser sessions (sparing *keep*); when a
*refresh_store* is given, also revokes the account’s connector refresh
families (and unredeemed codes in *code_store*). A failure to revoke
connector families is logged loudly but does not undo the password change,
which has already been written by the caller.

* **Return type:**
  [`CredentialsChanged`](#enlace_auth.auth.revocation.CredentialsChanged)

### enlace_auth.auth.revocation.refresh_tombstone_ttl(, refresh_token_ttl, refresh_reuse_detection)

How long a family tombstone must live: past every token of the family.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### enlace_auth.auth.revocation.revoke_refresh_family(refresh_store, family, , reason, tombstone_ttl, now=None)

Revoke one refresh-token family; return how many token records went.

The tombstone is written FIRST: revocation expressed only as the absence of
records loses to a worker concurrently rotating the family (its successor is
written after our scan). A positive marker cannot be raced – the refresh
grant refuses any record whose family carries one.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### enlace_auth.auth.revocation.revoke_refresh_subject(refresh_store, email, , reason, tombstone_ttl, code_store=None, marker_ttl=0, now=None)

Revoke every refresh family issued to *email*; return how many families.

Matches the subject case-insensitively. First writes a subject marker (see
[`subject_revoked_before()`](#enlace_auth.auth.revocation.subject_revoked_before)) that lives *marker_ttl* seconds – give it
the family max lifetime – so authorizations racing this call are refused
too. Then tombstones each existing family and drops the subject’s
unredeemed authorization codes from *code_store* when given. Access JWTs
already issued are self-contained and live out their (short) TTL.

* **Return type:**
  [`int`](https://docs.python.org/3/builtins/functions.html#int)

### enlace_auth.auth.revocation.revoked_family_key(family)

Store key of the tombstone that marks a whole refresh family revoked.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.revocation.shared_cookie_valid(value, password_hash, signing_key)

True iff a verified shared-cookie *value* was minted under *password_hash*.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### enlace_auth.auth.revocation.shared_password_fingerprint(password_hash, signing_key)

A short keyed fingerprint of an app’s CURRENT shared-password hash.

Signed into the `shared_auth_<app>` cookie and compared by the middleware,
so rotating the shared password invalidates every cookie minted under the
old one. Keyed with *signing_key* so the cookie (whose payload is readable,
only signed) reveals nothing about the hash.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.revocation.subject_marker_key(email)

Store key of the marker that says “nothing *email* authorized before T”.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.revocation.subject_revoked_before(refresh_store, email)

The time before which every authorization by *email* is revoked, if any.

A scan-and-delete revocation cannot see a family that another worker is
creating at that very moment (its code already consumed, its first refresh
record not yet written), nor a code issued from a session read just before
the change. The marker closes both: the code grant refuses codes issued at
or before it, and the refresh grant refuses families authorized at or
before it.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`int`](https://docs.python.org/3/builtins/functions.html#int)]
