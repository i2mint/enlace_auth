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
        "stores": {"backend": "file", "path": str(root / "platform")},
    },
    stores={"user_data": {"backend": "file", "path": str(root / "user_data")}},
)
client = TestClient(build_backend(discover_apps(config), plugins=[auth_plugin]))

assert client.get("/api/hello/ping").status_code == 200  # public: open, no cookie set
assert "enlace_csrf" not in client.cookies
assert client.get("/api/vault/ping").status_code == 401  # protected: denied

# An account, made the way `enlace-auth add-user` makes one.
from enlace_auth.auth import hash_password
from enlace_auth.stores import make_file_store_factory

users = make_file_store_factory(str(root / "platform"))("users")
users["ada@example.com"] = {"password_hash": hash_password("correct horse battery")}

token = client.get("/auth/csrf").json()["csrf"]  # every POST echoes this token
headers = {"X-CSRF-Token": token}
body = {"email": "ada@example.com", "password": "correct horse battery"}
assert client.post("/auth/login", json=body, headers=headers).status_code == 200
assert client.get("/api/vault/ping").status_code == 200  # now signed in
print(client.get("/auth/whoami").json())
```

## What it adds

- `/auth/login`, `/auth/logout`, `/auth/whoami`, `/auth/csrf`, `/auth/me/password`, `/auth/shared-login`
- self-service sign-up and sign-in by emailed code (`/auth/email/*`, the verify-first `/auth/register`), with a per-app sign-up policy; see [Self-service sign-up](#self-service-sign-up)
- `/auth/account`: the signed-in user changes their own password, adds or removes passkeys, or deletes their account
- passkeys (WebAuthn): sign-in with autofill, a step-up confirmation that hands an app a single-use proof, and a per-account "passkey required" policy; see [Passkeys and step-up](#passkeys-and-step-up)
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

### One sign-in across sibling subdomains

To give each app its own browser origin (its own storage, its own service worker) and still sign in once, serve the apps on subdomains of one parent and name the parent:

```toml
[auth]
cookie_domain = "apps.example.com"   # sign-in on apps.example.com; apps on a.apps.example.com, ...
```

Then sign-in cookies set on that host or one under it carry `Domain=apps.example.com`, so every app host receives the session. A signed-out visitor on an app host is sent to `https://apps.example.com/auth/login` with an absolute `next` back to the page, and `next` may name an `https://` URL on a host under the domain (nothing else absolute is accepted). A request to any other host (an IP address, a second name) keeps a host-only cookie. Sign-out clears both forms. A session made before the key was set moves onto the domain the next time its holder opens the sign-in page, so nobody has to sign in again. The CSRF cookie stays host-only: each host mints its own.

Every host under `cookie_domain` receives the session cookie, so each must be served by the platform; never point a subdomain under it at an outside service. Separate hosts isolate the apps' browser storage, not the platform: every host serves the whole backend, so a script running on one app host can still call `/_admin/api` or another app's `/api/` there with the visitor's cookie, exactly as on a single origin. Keep the platform's own pages (`/auth`, `/_admin`) on the parent. Unset (the default), cookies are host-only and `next` is a relative path, as before. For passkeys to work on every app host, set `[auth.passkeys] rp_id` to the same parent. OAuth sign-in still lands on `/` (#85).

### Self-service sign-up

"Continue with email" signs a person in with a 6-digit code mailed to them, and creates their account only once the code checks out, so nobody can claim an address they do not receive mail at, and the answer never says whether an address has an account. Where an account may be created is a policy per app:

```toml
[auth.signup]
default = "closed"               # closed | allowlist | invite | open
apps = { game = "open", studio = "invite" }
allowlist = ["friend@example.com"]
privacy_url = "https://example.com/privacy"
terms_url = "https://example.com/terms"
terms_version = "2026-11"
```

- `open` admits anyone, and the page says sign-up is for people aged 15 and over. `invite` admits invited addresses (`enlace-auth invite friend@example.com --apps studio`) and allowlisted ones. `allowlist` admits only the allowlist. An admin address is never created this way.
- The account is platform-wide; which apps it opens is still each app's `access` and `allowed_users`. A `protected:user` app with no `allowed_users` opens to every account, so give it one before opening sign-up anywhere: `enlace doctor` fails until you do, and warns about the app whatever the sign-up policy.
- The mail goes through `ENLACE_SMTP_*` (SMTP). Without it the sign-in page does not offer the email step, and the code only reaches the server log. Set SPF, DKIM and DMARC for the sending domain.
- Mail and code checks are rate-limited per address, per IP and overall (`[auth.signup.limits]`), and the form carries a honeypot plus a time-to-submit check. Behind a proxy, run uvicorn with `--forwarded-allow-ips` set to the proxy so the per-IP limit sees real clients.
- A signed-in user deletes their own account from `/auth/account`, confirmed by a mailed code; that removes its sessions, connector sessions, shares, grants and per-user data.
- An operator deletes an account on someone's behalf (a data-erasure request, say) from the **Delete** button in `/_admin/` or with `enlace-auth delete-user EMAIL` (add `--keep-data` to keep its per-user data). Both remove exactly what the self-service deletion removes, the last sign-in time and passkeys included, and say what they removed from each store.
- `registration_open = true` still works and means `default = "open"`. `/auth/register` (email plus a password of at least 15 characters) now mails a code too, and creates the account at verify.

### Passkeys and step-up

Off by default; py_webauthn comes with enlace_auth. Turn them on:

```toml
[auth.passkeys]
enabled = true
# rp_id = "example.com"          # default: the host of the public origin
# required = ["@admins"]         # must sign in by passkey, once they have enforce_from
# enforce_from = 2               # passkeys before the rule applies (lockout guard)
```

- Any signed-in account adds passkeys from `/auth/account`. Adding or removing one needs a sign-in from the last 15 minutes, made with a passkey once the account has one; each change is mailed to the account, and a removal ends its other sessions. The sign-in page gets a passkey button and passkey autofill on its email field.
- **Step-up**: a page prepares `enlacePasskeys.prepareStepUp("myapp: start job 42")` (from `/auth/passkeys/passkeys.js`), then on the tap calls `enlacePasskeys.stepUp(prepared)`; the user confirms with Face ID or Touch ID and gets a proof, valid once for 120 seconds; the app or connector backend calls `POST /auth/passkeys/step-up/redeem {proof, action, email}` before acting. The answer the authenticator signs commits to the action text, so a proof for one action never redeems for another. Stronger: the backend creates the request itself (`POST /auth/passkeys/step-up/request`, authenticated by its audience key from `enlace-auth step-up-key AUDIENCE`), the platform's own page `/auth/passkeys/confirm` shows the backend's text, and the one proof it mints redeems only where that audience is named. The displayed text is guaranteed only when `/auth` is on an origin no app shares (`cookie_domain`); on one origin an app's script can drive the same calls. Proofs are method-agnostic (`enlace_auth/auth/step_up.py`): `redeem` reports the `method` and accepts `methods=[...]` to refuse weaker ones. Details in the consumer skill (`enlace_auth/data/skills/enlace-auth-usage`).
- `required` accounts refuse every other sign-in method once they have `enforce_from` passkeys (or one synced passkey). A lost device is removed with `enlace-auth remove-passkey EMAIL --passkey-id ID`.

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

The cookie is `Secure` when `secure_cookies` is on, and on any HTTPS request (directly, or per `X-Forwarded-Proto`). If you use `CSRFMiddleware` directly, pass `secure=True` to mark it always; `mint_prefixes` limits where it sets the cookie (default: every safe request); the check itself always runs.

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

A team listed once in `platform.toml` (`[auth.groups] acme = ["ann@acme.com", "bob@acme.com"]`) is written `"@acme"` in any app's `allowed_users` and in any `[auth.oauth_server.resource_allowlist]` entry, so adding or removing a person is one edit. An undefined group admits nobody in `allowed_users` and stops the config from loading in an allowlist; an empty group is refused (an empty `allowed_users` would admit everyone); `admins` is reserved, and `@admins` is not expanded in an allowlist. A host that decides from `app.toml` alone whether an app is public (a deploy writing an edge config) must treat any `@name` entry as `protected:user`, as enlace_auth does.

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
