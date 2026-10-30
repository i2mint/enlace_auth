# enlace_auth

Sign-in, sessions, CSRF protection, an admin dashboard and per-user data stores for the [enlace](https://github.com/i2mint/enlace) multi-app platform, added as a plugin.

Humans who still type their code by hand: [For the free-range, hand-coded developer](#for-the-free-range-hand-coded-developer).

## For coding agents

Read [`CLAUDE.md`](CLAUDE.md) first: it has the architecture map, the test command and the invariants a change must keep. This package is the security boundary of the platform, so a behavior change here is a security change.

Two skills live in this repo:

| Skill | For | Where |
|---|---|---|
| `enlace-auth-usage` | using the plugin: wiring, access levels, CLI, the CSRF flow | `enlace_auth/data/skills/enlace-auth-usage` (ships in the wheel) |
| `enlace-auth-dev` | working on this codebase: tests, invariants, the fix loop | `skills/enlace-auth-dev` |

Enable them with either route:

```bash
gh skill install i2mint/enlace_auth enlace-auth-usage --agent claude-code
gh skill install i2mint/enlace_auth enlace-auth-dev --agent claude-code

# or, from the installed package (needs `pip install skill`):
skill link-skills "$(python -c 'import enlace_auth, os; print(os.path.join(enlace_auth.__path__[0], "data", "skills"))')"
```

Inside a checkout, `.claude/skills/` already holds relative symlinks to both.

What an agent can do with it: put `public`, `protected:shared` and `protected:user` gates in front of any enlace app, manage accounts, grants and data shares with the `enlace-auth` CLI, and give each signed-in user a private `request.state.store`. This example builds a platform in a temp directory and checks the gates end to end:

<!-- readme-example -->
```python
import os, tempfile
from pathlib import Path

from enlace import PlatformConfig, build_backend
from enlace.discover import discover_apps
from starlette.testclient import TestClient

from enlace_auth import plugin as auth_plugin

os.environ["ENLACE_SIGNING_KEY"] = "a-demo-key-of-at-least-32-characters"
root = Path(tempfile.mkdtemp())

# Two apps: a public one and one that needs a signed-in user.
for name, access in [("hello", "public"), ("vault", "protected:user")]:
    (root / "apps" / name).mkdir(parents=True)
    (root / "apps" / name / "server.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/ping')\n"
        "def ping():\n"
        "    return {'ok': True}\n"
    )
    (root / "apps" / name / "app.toml").write_text(f'access = "{access}"\n')

config = PlatformConfig(
    apps_dir=root / "apps",
    auth={
        "enabled": True,
        "secure_cookies": False,  # plain http in this demo
        "registration_open": True,
        "stores": {"backend": "file", "path": str(root / "platform")},
    },
    stores={"user_data": {"backend": "file", "path": str(root / "user_data")}},
)
client = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))

assert client.get("/api/hello/ping").status_code == 200  # public: open, no cookie set
assert "enlace_csrf" not in client.cookies
assert client.get("/api/vault/ping").status_code == 401  # protected: denied

token = client.get("/auth/csrf").json()["csrf"]  # every POST echoes this token
headers = {"X-CSRF-Token": token}
body = {"email": "ada@example.com", "password": "correct horse battery"}
assert client.post("/auth/register", json=body, headers=headers).status_code == 200
assert client.get("/api/vault/ping").status_code == 200  # now signed in
print(client.get("/auth/whoami").json())
```

## What it adds

- `/auth/login`, `/auth/logout`, `/auth/register`, `/auth/whoami`, `/auth/csrf`, `/auth/me/password`, `/auth/shared-login`
- `/auth/account`: the signed-in user changes their own password
- `/auth/forgot-password`: self-service reset by emailed link
- `/_admin/api/*`: list, create and delete users, mint a password-reset link, set a password directly, view app policy, and **grant or revoke per-app access at runtime** (optional expiry). Gated by an admin allowlist.
- per-user data injection via `request.state.store`
- `PlatformAuthMiddleware` and `CSRFMiddleware`
- optional OAuth2 / OIDC login via Authlib, and an OAuth 2.1 authorization server for MCP connectors

`enlace` itself is auth-agnostic: it composes apps and routes traffic. This package plugs in at compose time.

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

# Who may authorize for each connector. Fails closed: a resource this table does
# not list is refused to everyone, so a new or renamed connector stays shut until
# it is added here. "*" opens a resource to every authenticated account, and has
# to be written out. It fails loudly too: an unknown key anywhere under [auth]
# (a misspelled or misnested table), a key that is not an http(s) URL, a value
# that is not a list of emails, or a pattern such as "*@example.com" stops the
# platform at startup, and `enlace doctor` names it. An enabled server with no
# allowlist refuses to start unless `allow_unlisted_resources = true` says an
# open server is intended.
[auth.oauth_server.resource_allowlist]
"https://apps.example.com/connector-a-mcp" = ["alice@example.com"]
"https://apps.example.com/connector-b-mcp" = ["*"]

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

**A credential change ends connector sessions too.** Deleting a user, an admin
password set, a self-service password change, a reset-link redemption and the
`set-password` CLI all revoke the account's browser sessions *and* its refresh
families (plus any unredeemed authorization codes); the connector must be
re-authorized. Already-issued access tokens live out their TTL.

**Rotating a shared password ends its cookies.** A `shared_auth_<app>` cookie
carries a keyed fingerprint of the app's shared-password hash at the time it was
minted, so after you change the hash (and restart), every cookie from the old
password is refused. Upgrading to this version signs everyone out of
shared-password apps once.

Plus environment variables:

- `ENLACE_SIGNING_KEY` — signing key (32+ chars). Generate with `python -c
  "import secrets; print(secrets.token_urlsafe(32))"`.
- `ENLACE_ADMIN_EMAILS` — comma-separated admin emails (gate `/_admin`). Admins can also be declared in `platform.toml` as `[auth] admin_emails = [...]`, which makes granting admin a reviewable config change; the two lists are unioned. A signed-in account that is not an admin gets a 403 page at `/_admin` (saying who is signed in, with a link to switch account), not a sign-in redirect. An admin address can never self-register, not even with `registration_open` or an allowlist entry, because `/auth/register` cannot prove who owns it. An admin account comes from `enlace-auth add-user <email>` (a password account), or from the admin's first sign-in through a configured OAuth provider that itself verifies the address (an `email_verified` claim, or the `github` preset; `trust_unverified_email` does not count). Every account records how it was made (`created_via`). `enlace doctor` warns about an admin address with no account, and about an admin account that was self-registered.
- `ENLACE_REGISTRATION_ALLOWLIST` — comma-separated emails allowed to self-register while `registration_open` is false (the default).
- `ENLACE_ALLOW_UNSIGNED=1` — opt-out from fail-fast (diagnostics only).
- `ENLACE_SMTP_HOST` (+ `_PORT`, `_USER`, `_PASSWORD`, `_FROM`, `_TLS`) — mail
  sender for password-reset emails. Unset means **no email is sent**; see below.

## CSRF

Every `POST`, `PUT`, `PATCH` and `DELETE` must carry an `X-CSRF-Token` header that matches the signed `enlace_csrf` cookie. That covers `/auth`, `/_admin`, `/_apps/{name}/meta` and the per-user store `/api/{app}/store`. Exempt: `/auth/callback`, `/auth/login/<provider>`, `/auth/oauth/`, other sub-app APIs under `/api/`, and proxied `process` and `external` apps. A client gets the token from `GET /auth/csrf`, which also sets the cookie.

The cookie is set only on `/auth/*`, `/_admin` and `protected:*` apps. A `public` app's pages set no cookie, so an app that promises "nothing is stored on your device" keeps that promise on this platform. A public page that has to `POST` to the auth routes fetches `/auth/csrf` first. Sub-app APIs under `/api/` are exempt from the check because the session cookie is `SameSite=Lax`, except the per-user store routes.

If you use `CSRFMiddleware` directly, `mint_prefixes` limits where it sets the cookie (default: every safe request); the check itself always runs.

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

`"@admins"` in that list stands for the platform admins (the emails in
`admin_emails_env`), so an owner-only tool can be declared without committing
an address: `allowed_users = ["@admins"]`. If no admins are configured, such an
app admits nobody. Because `allowed_users` is only enforced for
`protected:user`, an app using the alias is treated as `protected:user` even if
its `access` says otherwise (an error is logged) — it never falls open.

A signed-in user who is not on `allowed_users` (or an active grant) gets a **403** (a 403 page in a browser, JSON `{"auth": "forbidden"}` otherwise), not the sign-in redirect or a 401; a signed-out request still gets the redirect or 401. This is `AccessRule.deny_signed_in`, now `True` by default for every rule (it was admin-only). Upgrade note: a frontend that treats any 401 as "go sign in" will now see a 403 for a signed-in user who lacks access, and should show a "not allowed for this account" message instead.

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

## Owner-granted data shares

Grants say who may *open* an app. A **share** says who may act on *someone else's* data in it: in app `A`, the owner's per-user store is readable (and, by default, writable) by a named grantee, signed in as themselves. Use it for data that belongs to one person and is looked after by others — a child's practice log kept by her parents.

```bash
enlace-auth share practice kid@example.com parent@example.com --label Kid   # admin, from the server
enlace-auth share practice kid@example.com teacher@example.com --access ro
enlace-auth list-shares
enlace-auth revoke-share practice kid@example.com parent@example.com
```

A signed-in owner manages their own shares at `/auth/shares/{app}` (`GET`, `PUT …/{grantee}`, `DELETE …/{grantee}`; a grantee leaves with `DELETE …/received/{owner}`); an admin uses `/_admin/api/shares`. A grantee then reads the owner's data with `?owner=<email>` on the per-user store: `GET /api/{app}/store?prefix=…&owner=…` lists it, and every route takes `If-Match` so two devices cannot silently overwrite each other. A share names existing accounts only and is removed with either account.

Upgrading: store writes (`PUT`/`DELETE /api/{app}/store/...`) now require the `X-CSRF-Token` header (from `GET /auth/csrf`), and `/api/{app}/store` is reserved for the platform. A share does not bypass an app's `allowed_users`.

An app gets a per-user store when its `access` is `protected:user`, or when its `app.toml` sets `user_store = true` — which lets a **public** app keep data for the visitors who sign in while staying open to everyone else. The design and its review are in [`misc/docs/decisions/0001-owner-granted-data-shares.md`](misc/docs/decisions/0001-owner-granted-data-shares.md).

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

## For the free-range, hand-coded developer

Set up and run the tests:

```bash
git clone https://github.com/i2mint/enlace_auth && cd enlace_auth
uv venv -q .venv && . .venv/bin/activate
uv pip install -q -e ".[dev,oauth]" pip
python -m pytest -q --doctest-modules enlace_auth tests
```

- **Design.** Pure ASGI middleware, deny by default, storage behind `MutableMapping`s so tests use dicts or a temp directory. The reasoning for owner-granted shares is in [`misc/docs/decisions/0001-owner-granted-data-shares.md`](misc/docs/decisions/0001-owner-granted-data-shares.md).
- **Status.** Extracted from `enlace` 0.0.11. The Python API is stable; an admin frontend ships separately as a normal enlaced app.
- **Contributing.** Open an issue first for anything larger than a focused fix. A fix comes with a test that fails without it. CI formats the code and bumps the version, so leave `version` alone.
- **Questions and bugs.** [GitHub issues](https://github.com/i2mint/enlace_auth/issues).
- **License.** MIT.
