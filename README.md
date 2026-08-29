# enlace_auth

Authentication, sessions, an admin dashboard, and per-user stores for the
[enlace](https://github.com/i2mint/enlace) multi-app platform.

`enlace` itself is auth-agnostic — it composes apps and routes traffic. This
package plugs in at compose time and adds:

- `/auth/login`, `/auth/logout`, `/auth/register`, `/auth/whoami`,
  `/auth/csrf`, `/auth/me/password`, `/auth/shared-login`
- `/auth/account` — the signed-in user changes their own password
- `/auth/forgot-password` — self-service reset by emailed link
- `/_admin/api/*` — list/create/delete users, mint a password-reset link,
  set a password directly, view app policy, and **grant/revoke per-app access
  at runtime** (optional expiry). Gated by an admin allowlist.
- per-user data injection via `request.state.store`
- `PlatformAuthMiddleware` + `CSRFMiddleware`
- optional OAuth2 / OIDC via Authlib

## Quick start

```python
from enlace import build_backend, PlatformConfig
from enlace_auth import plugin as auth_plugin

config = PlatformConfig.from_toml("platform.toml")
app = build_backend(config, plugins=[auth_plugin])
```

Or, if you serve via `uvicorn --factory enlace.compose:create_app`, set:

```bash
export ENLACE_PLUGINS=enlace_auth:plugin
```

## Configuration

In `platform.toml`:

```toml
[auth]
enabled = true
session_cookie_name = "enlace_session"
session_max_age_seconds = 86400
signing_key_env = "ENLACE_SIGNING_KEY"
secure_cookies = true

[auth.stores]
backend = "file"
path = "~/.enlace/platform_store"

[stores.user_data]
backend = "file"
path = "~/.enlace/user_data"
```

### OAuth 2.1 authorization server (MCP connectors)

`enlace_auth` can act as the authorization server that issues the JWTs an MCP
custom connector validates. **One** server serves *every* connector on the
platform, so anything a user reads during the connect flow must be keyed on the
connector — the `resource` the client asks for:

```toml
[auth.oauth_server]
enabled = true
issuer = "https://apps.example.com"

# How long a connector works before it must renew (default 3600); how long it
# may sit IDLE before its refresh token lapses (default 30 days); and the
# absolute ceiling on one authorization regardless of activity (default 90 days).
access_token_ttl_seconds = 3600
refresh_token_ttl_seconds = 2592000
refresh_family_max_lifetime_seconds = 7776000

# Who may authorize for each connector. A resource that is not listed is open
# to any authenticated user; a listed one denies everyone else.
[auth.oauth_server.resource_allowlist]
"https://apps.example.com/connector-a-mcp" = ["alice@example.com"]

# The name the consent screen shows, keyed by the SAME resource URL. A resource
# with no entry gets generic copy that names no product — never default to one
# connector's name, or every other connector's consent screen inherits it.
[auth.oauth_server.resource_display_names]
"https://apps.example.com/connector-a-mcp" = "Connector A"
"https://apps.example.com/connector-b-mcp" = "Connector B"
```

#### Keeping a connector alive

Access tokens are short-lived by design; **refresh tokens are what keep a
connector working**. With the refresh grant enabled (the default) a client
renews its own access token in the background and a person is involved only
once, at first connect. Set `refresh_token_ttl_seconds = 0` and you get the
opposite: every session dies `access_token_ttl_seconds` after it started, the
connector returns 401 forever, and the *only* way back is a human re-running the
browser authorization. Nothing errors when this happens — the connector process
stays healthy and expiry is logged at INFO on the resource server — so it
surfaces as a user saying the connector "has been down all day". `enlace_auth`'s
doctor checks (`oauth_refresh` and the discovery-metadata HTTP check) fail on
exactly this, including the case where config enables refresh but the *deployed*
build is older than the config and cannot honour it. They run wherever
`enlace doctor` runs, via `enlace.doctor.discover_plugin_checks` — which needs
`enlace` new enough to have it (i2mint/enlace#34); on older `enlace` the checks
exist but nothing invokes them.

`refresh_token_ttl_seconds` is an **idle** timeout, not a session ceiling: every
rotation resets it, so a connector refreshing hourly would otherwise never face a
human again. `refresh_family_max_lifetime_seconds` is the absolute cap, set once
when the session is authorized and carried unchanged through every rotation.

Refresh tokens rotate: each use consumes the presented token and returns a
successor. Tokens are stored hashed, never verbatim.

Replaying a spent token is theft *unless* it looks like a retry. The server
consumes a token before its response is written, so a dropped response (proxy
502, TLS reset, client timeout) leaves an honest client holding a spent token —
and revoking there would strand the connector exactly as an absent refresh grant
does. Within `refresh_reuse_grace_seconds`, from the same client, with the
successor still unused and the subject still authorized, that is treated as a
retry and reissued. Anything else revokes the whole family. Spent tokens are
remembered for `refresh_reuse_detection_seconds` so that a replay is recognised
rather than merely unknown.

Because access tokens are self-contained JWTs with no denylist, **the allowlist
is re-evaluated on every refresh** — that is the only revocation path this server
has. Removing someone from `resource_allowlist` (and redeploying) stops them
within one access-token lifetime rather than one refresh-token lifetime. Keep
`access_token_ttl_seconds` short for that reason: with refresh in place, a short
access token costs nothing and is what bounds revocation lag.

Plus environment variables:

- `ENLACE_SIGNING_KEY` — signing key (32+ chars). Generate with `python -c
  "import secrets; print(secrets.token_urlsafe(32))"`.
- `ENLACE_ADMIN_EMAILS` — comma-separated admin emails (gate `/_admin`).
- `ENLACE_ALLOW_UNSIGNED=1` — opt-out from fail-fast (diagnostics only).
- `ENLACE_SMTP_HOST` (+ `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TLS`) — mail
  sender for password-reset emails. Unset means **no email is sent**; see below.

## Passwords

Three ways a password gets set, for three different situations:

| Situation | Path |
|---|---|
| User knows their password, wants a new one | `/auth/account` |
| User is locked out, **SMTP configured** | `/auth/forgot-password` → emailed link |
| User is locked out, **no SMTP** | admin mints a link and delivers it by hand |

That last one is what keeps the platform usable with no mail server:

```bash
enlace-auth reset-link someone@example.com          # prints a 72h, single-use link
enlace-auth reset-link someone@example.com --hours 4
```

or the **Reset link** button in `/_admin/`. Prefer it to setting a password for
someone: the admin never invents, learns, or transmits another person's
credential, and the recipient chooses their own.

`enlace-auth set-password <email>` still exists for break-glass use.

Reset links are signed, not stored. Each carries the account's current
password-hash fingerprint and its own absolute expiry, so a link dies on first
use — and any other password change invalidates every link outstanding for that
account. With no SMTP configured, `/auth/forgot-password` says so and points at
the admin rather than promising an email that only reaches the log.

## Per-app access & runtime grants

Each app declares an `access` level in its `app.toml`
(`public | protected:shared | protected:user`). A `protected:user` app may also
declare a static baseline allow-list:

```toml
access = "protected:user"
allowed_users = ["owner@example.com"]   # always allowed; edit-in-code baseline
```

On top of that baseline you can grant access **at runtime — no redeploy** — from
the admin dashboard or the CLI. Runtime grants are *additive* (effective access =
`allowed_users ∪ active grants`) and may carry an optional UTC expiry:

```bash
enlace-auth grant vault alice@example.com --expires 2026-12-31   # end of day UTC
enlace-auth list-grants --app vault
enlace-auth revoke-grant vault alice@example.com
```

Grants live in a `grants/` store alongside `sessions/` and `users/` under
`[auth.stores] path`, so they persist across restarts and redeploys. A grant on
an app with an *empty* `allowed_users` (open to any authenticated user) is
rejected — it would have no additive effect and would unintentionally restrict an
open app. To remove a user listed in `allowed_users`, edit `app.toml` (that layer
is intentionally code-managed); the admin panel manages the runtime layer.

## Doctor checks

```python
from enlace.doctor import run_doctor
from enlace_auth.diagnostics import static_checks, http_checks

report = run_doctor(
    config,
    base_url="http://localhost:8000",
    extra_static_checks=static_checks,
    extra_http_checks=http_checks,
)
```

## Status

Extracted from `enlace` 0.0.11. The Python API is stable; an admin frontend
ships separately as a normal enlaced app.
