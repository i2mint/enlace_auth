---
name: enlace-auth-usage
description: >-
  How to add sign-in, sessions, CSRF protection, admin accounts, per-app access
  levels, runtime grants and per-user storage to an enlace multi-app platform
  with the enlace_auth plugin. Use when the user mentions enlace_auth, the
  enlace-auth CLI, protected:user or protected:shared apps, ENLACE_SIGNING_KEY,
  ENLACE_ADMIN_EMAILS, X-CSRF-Token or /auth/csrf, request.state.store, add-user,
  reset-link, grant, or share; or wants to put login in front of apps served by
  enlace.
metadata:
  audience: users
---

# Using enlace_auth

`enlace_auth` is an enlace plugin. Install it next to enlace, give the platform a signing key, mark apps with an access level, and every request is gated.

## 1. Wire it in

```python
from enlace import PlatformConfig, build_backend
from enlace_auth import plugin as auth_plugin

config = PlatformConfig.from_toml("platform.toml")
app = build_backend(config, plugins=[auth_plugin])
```

With `uvicorn --factory enlace.compose:create_app`, set `ENLACE_PLUGINS=enlace_auth:plugin` instead. The plugin does nothing unless `[auth] enabled = true`.

## 2. Configure

`python -m enlace_auth init` prints a starter `[auth]` block. `python -m enlace_auth generate-signing-key` prints a value for `ENLACE_SIGNING_KEY` (32+ characters; the platform refuses to start without one, and `ENLACE_ALLOW_UNSIGNED=1` boots it with authentication disabled, for diagnostics only). `ENLACE_ADMIN_EMAILS` (comma separated) names who may open `/_admin`.

An app declares `access` in its `app.toml`: `public`, `protected:shared` (one shared password, `shared_password_env` holds its argon2 hash from `python -m enlace_auth hash-password`) or `protected:user` (a signed-in account, optionally narrowed by `allowed_users`). **An app with no `access` is `local`, which the gate treats as open to everyone.** Always write `access` explicitly. A request path that matches no app falls under the platform's public root rule, and an unrecognized `access` value is denied.

## 3. Accounts and access from the CLI

All commands take `--toml platform.toml`.

| Task | Command |
|---|---|
| Create an account (the only way to make an admin) | `enlace-auth add-user EMAIL` |
| Give someone a one-time password link | `enlace-auth reset-link EMAIL` |
| Grant an app to a user at runtime | `enlace-auth grant APP EMAIL --expires 2026-12-31` |
| Share one user's data in an app | `enlace-auth share APP OWNER GRANTEE --access ro` |
| List what exists | `list-users`, `list-sessions`, `list-grants`, `list-shares` |

Self-registration is off by default. `registration_open = true` in `[auth]` or `ENLACE_REGISTRATION_ALLOWLIST` opens it. An admin address can never self-register.

## 4. Calling the HTTP API correctly

Every POST, PUT, PATCH and DELETE needs the CSRF pair, except the OAuth callback and consent routes (`/auth/callback`, `/auth/login/<provider>`, `/auth/oauth/`), sub-app APIs under `/api/` (but not `/api/{app}/store`), and proxied `process`/`external` apps. That covers `/auth`, `/_admin`, `/_apps/{name}/meta` and the per-user store. Fetch the token first, then echo it in a header:

```python
token = client.get("/auth/csrf").json()["csrf"]
client.post("/auth/login", json={"email": e, "password": p},
            headers={"X-CSRF-Token": token})
```

The cookie is set only by `/auth/*`, `/_admin` and `protected:*` apps. Public pages set no cookie, so a public page that must POST has to call `/auth/csrf` itself. Sub-app APIs under `/api/` are exempt because the session cookie is `SameSite=Lax`.

## 5. Inside an app

For `protected:user` apps (and public apps with `user_store = true`), read `request.state.user_id`, `request.state.user_email` and `request.state.store`, a `MutableMapping` scoped to that user and app. Never trust an `X-User-ID`-style header: the middleware strips them.

## Gotchas

- Changing a password, deleting a user or rotating a shared password ends the affected sessions (and connector refresh tokens). That is intended.
- `enlace doctor` runs this package's checks (signing key, admin accounts, OAuth refresh) when enlace is new enough to discover plugin checks.
- To test an app behind the plugin, build a platform in a temp directory and use Starlette's `TestClient`; `README.md` has a complete runnable example.
