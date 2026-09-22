# enlace_auth.auth.oauth_server

OAuth 2.1 authorization server — issue tokens for MCP custom connectors.

The companion to [`enlace_auth.auth.oauth`](enlace_auth.auth.oauth.html.md#module-enlace_auth.auth.oauth) (which is a login *client*, “sign in
with Google”). This module makes `enlace_auth` an authorization **server**: it
issues and signs the bearer tokens a Claude.ai custom connector — an OAuth
*resource server* — validates. It reuses the platform’s existing user store and
session login, so a connector authenticates against the same accounts as the rest
of the platform.

The flow Claude.ai drives (OAuth 2.1 authorization-code + PKCE, RFC 7591 dynamic
client registration, RFC 8707 resource indicators):

1. The connector replies 401, pointing at its protected-resource metadata, which
   names this server as the authorization server.
2. The client discovers our endpoints via `/.well-known/oauth-authorization-server`.
3. It registers itself (DCR) at `/auth/oauth/register`.
4. `GET /auth/oauth/authorize` — the user signs in (reusing `/auth/login`) and
   consents; we issue a short-lived, PKCE-bound authorization code.
5. `POST /auth/oauth/token` — the code + PKCE verifier is exchanged for a signed
   JWT whose `aud` is the connector (the `resource` parameter).
6. The connector’s FastMCP `JWTVerifier` validates that JWT against
   `/auth/oauth/jwks`.
7. Before the access token expires, the client exchanges its **refresh token**
   (`grant_type=refresh_token`) for a fresh pair — no browser, no human. This is
   what keeps a connector alive: without it an access token’s expiry ends the
   session outright, and the only way back is for a person to re-run the whole
   browser authorization. See [`make_oauth_server_router()`](#enlace_auth.auth.oauth_server.make_oauth_server_router) for the rotation and
   reuse-detection rules.

Endpoints (mounted on the platform root, so they sit at the issuer origin):

```default
GET  /.well-known/oauth-authorization-server   metadata (RFC 8414)
GET  /auth/oauth/jwks                            signing public keys
POST /auth/oauth/register                        dynamic client registration
GET  /auth/oauth/authorize                        sign-in + consent → code
POST /auth/oauth/authorize                        consent submit → code
POST /auth/oauth/token                            code + PKCE → JWT
                                                  refresh_token → JWT
```

### Functions

| [`make_oauth_server_router`](#enlace_auth.auth.oauth_server.make_oauth_server_router)(\*, session_store, ...)   | Build the OAuth 2.1 authorization-server router (see the module docstring).   |
|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------|

### Classes

| [`OAuthKeys`](#enlace_auth.auth.oauth_server.OAuthKeys)(key_dir)   | The server's RSA signing key — persisted, exposed as a JWKS.   |
|-----------------------------------------------------------------------|----------------------------------------------------------------|

### *class* enlace_auth.auth.oauth_server.OAuthKeys(key_dir)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

The server’s RSA signing key — persisted, exposed as a JWKS.

Generates a 2048-bit RSA key on first use under *key_dir* (`private_key.pem`,
mode 0600) and reuses it thereafter, so tokens stay verifiable across restarts.
Signs JWTs (RS256) and publishes the public half as a one-key JWKS for the
connector’s verifier to fetch.

### enlace_auth.auth.oauth_server.make_oauth_server_router(, session_store, signing_key, cookie_name, session_max_age, client_store, code_store, keys, issuer=None, refresh_store=None, claim_once=None, release_claim=None, is_active=None, access_token_ttl=3600, refresh_token_ttl=2592000, refresh_reuse_grace=60, refresh_reuse_detection=86400, refresh_family_max_lifetime=7776000, client_ttl=15552000, code_ttl=120, scopes_supported=('mcp:read',), require_consent=True, resource_allowlist=None, resource_display_names=None)

Build the OAuth 2.1 authorization-server router (see the module docstring).

*issuer* pins the token `iss` and the discovery URLs; when `None` it is
derived from each request’s base URL (so the same code serves any domain). The
consent step reuses the platform session — an unauthenticated `/authorize`
redirects to `/auth/login` and returns.

*refresh_store* backs the `refresh_token` grant. Supply it and clients renew
their own access tokens in the background, unattended; omit it and this server
issues bare access tokens whose expiry silently ends the session, recoverable
only by a human re-running the browser authorization. It is optional purely for
backwards compatibility — **always pass it in a deployment**, and see
`enlace_auth.diagnostics.check_oauth_server()` which reports its absence as
a fault. Tokens are stored hashed (`_hash_refresh()`), never verbatim.

Refresh tokens **rotate**: each use consumes the presented token and returns a
new one. Consumption goes through *claim_once*, which must be atomic across
PROCESSES — several workers share one store, and a plain read-then-write lets
two concurrent redemptions both mint a live successor, which is precisely the
double-spend rotation exists to detect.

A spent token presented again is theft *unless* it looks like a retry. The
token is consumed before the response is written, so a dropped response
leaves an honest client holding a spent token; revoking there would strand
the connector exactly as having no refresh grant does. Within
*refresh_reuse_grace*, from the same client, with the successor still unused
and the subject still authorized, it is reissued instead. Anything else
revokes the whole family (OAuth 2.1 §4.3.1). Spent tokens are remembered for
*refresh_reuse_detection* so a replay is recognised rather than merely
unknown.

*refresh_token_ttl* is an IDLE timeout that each rotation resets;
*refresh_family_max_lifetime* is the absolute ceiling, fixed when the session
is authorized. Both *resource_allowlist* and *is_active* are re-evaluated on
every refresh — with no denylist and no revocation endpoint, they are the
only way a session ends before its own expiry, which is why access tokens
should stay short.

*resource_allowlist* maps a connector resource URL to the emails permitted to
authorize for it. A resource **not** in the map is open to any authenticated
user (back-compatible); a resource that **is** in the map denies everyone
else — per-connector access control (e.g. restrict a private connector to its
own staff). Secure to key on the resource: the connector only accepts tokens
whose `aud` is that exact resource, so a denied user can’t get a usable token
another way.

*resource_display_names* maps the **same** resource URL to the human name the
consent screen shows. One authorization server serves every connector on the
platform, so this string must be per-connector: a name baked into the template
is correct for one connector and wrong — and disclosing — for every other. A
resource with no entry gets generic copy that names no product at all; never
default to a specific connector’s name, or the next connector added inherits
it.

* **Return type:**
  `APIRouter`
