# enlace_auth.oauth_rules

The stateless rules of the OAuth 2.1 authorization server, importable alone.

PKCE S256 verification, redirect-URI vetting, refresh-token hashing and the RS256
signing key: the security-critical checks a second gateway would otherwise copy
and let drift (i2mint/enlace_auth#98). No web framework is imported here;
`OAuthKeys` needs `cryptography` and `joserfc` (the `oauth` extra), on
first use. [`enlace_auth.auth.oauth_server`](enlace_auth.auth.oauth_server.html.md#module-enlace_auth.auth.oauth_server) uses these same functions.

```pycon
>>> import base64, hashlib
>>> verifier = "a" * 43
>>> challenge = b64url(hashlib.sha256(verifier.encode()).digest())
>>> verify_pkce_s256(verifier, challenge), verify_pkce_s256("b" * 43, challenge)
(True, False)
>>> len(hash_refresh("token")), hash_refresh("token") == hash_refresh("token")
(64, True)
```

### Functions

| [`b64url`](#enlace_auth.oauth_rules.b64url)(raw)                                       | URL-safe base64 without padding (the PKCE / JOSE encoding).                |
|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| [`hash_refresh`](#enlace_auth.oauth_rules.hash_refresh)(token)                               | Storage key for a refresh token — the token itself is never persisted.     |
| [`redirect_uri_problem`](#enlace_auth.oauth_rules.redirect_uri_problem)(uri, \*[, https_hosts, ...]) | Why *uri* is not an acceptable registered redirect URI, or `None`.         |
| [`verify_pkce_s256`](#enlace_auth.oauth_rules.verify_pkce_s256)(verifier, challenge)             | True iff `BASE64URL(SHA256(verifier)) == challenge` (PKCE S256, RFC 7636). |

### Classes

| [`OAuthKeys`](#enlace_auth.oauth_rules.OAuthKeys)(key_dir)   | The server's RSA signing key — persisted, exposed as a JWKS.   |
|-----------------------------------------------------------------------|----------------------------------------------------------------|

### *class* enlace_auth.oauth_rules.OAuthKeys(key_dir)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The server’s RSA signing key — persisted, exposed as a JWKS.

Generates a 2048-bit RSA key on first use under *key_dir* (`private_key.pem`,
mode 0600) and reuses it thereafter, so tokens stay verifiable across restarts.
Signs JWTs (RS256) and publishes the public half as a one-key JWKS for the
connector’s verifier to fetch.

### enlace_auth.oauth_rules.b64url(raw)

URL-safe base64 without padding (the PKCE / JOSE encoding).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.oauth_rules.hash_refresh(token)

Storage key for a refresh token — the token itself is never persisted.

Refresh tokens are long-lived credentials. Storing them verbatim would make a
read of the store (a backup, a stray `cat`, a misconfigured store API) a
credential dump. Hashing means the store holds only something that can
*recognise* a token presented back to us, never mint one.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.oauth_rules.redirect_uri_problem(uri, , https_hosts=None, allow_loopback=True, allow_private_schemes=True)

Why *uri* is not an acceptable registered redirect URI, or `None`.

Follows OAuth 2.1 / RFC 8252 for public clients: an absolute URI with no
fragment; `https` for web clients; plain `http` only on a loopback host
(native apps on a local port); private-use schemes (`cursor://...`) are
allowed for native apps; script- and local-content schemes never are.
Registration is anonymous, so this is the only gate on where an
authorization code can be sent.

*https_hosts*, when given, narrows `https` redirects to those hosts (a
gateway whose clients are known); it does not touch the other kinds, so a
server that wants only those hosts also passes *allow_loopback* False (no
loopback `http`) and *allow_private_schemes* False (no `cursor://`).

```pycon
>>> redirect_uri_problem("cursor://cb", allow_private_schemes=False)
"redirect_uri scheme 'cursor' is not allowed here"
```

```pycon
>>> redirect_uri_problem("https://claude.ai/api/mcp/auth_callback") is None
True
>>> redirect_uri_problem("http://127.0.0.1:8765/cb", allow_loopback=False)
'plain-http redirect_uri is only allowed on a loopback host'
>>> redirect_uri_problem("https://evil.example/cb", https_hosts=["claude.ai"])
"redirect_uri host 'evil.example' is not one this server accepts"
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.oauth_rules.verify_pkce_s256(verifier, challenge)

True iff `BASE64URL(SHA256(verifier)) == challenge` (PKCE S256, RFC 7636).

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)
