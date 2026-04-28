# enlace_auth

Authentication, sessions, an admin dashboard, and per-user stores for the
[enlace](https://github.com/i2mint/enlace) multi-app platform.

`enlace` itself is auth-agnostic — it composes apps and routes traffic. This
package plugs in at compose time and adds:

- `/auth/login`, `/auth/logout`, `/auth/register`, `/auth/whoami`,
  `/auth/csrf`, `/auth/me/password`, `/auth/shared-login`
- `/_admin/api/*` — list/create/delete users, admin password reset, view app
  policy. Gated by an admin allowlist.
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

Plus environment variables:

- `ENLACE_SIGNING_KEY` — signing key (32+ chars). Generate with `python -c
  "import secrets; print(secrets.token_urlsafe(32))"`.
- `ENLACE_ADMIN_EMAILS` — comma-separated admin emails (gate `/_admin`).
- `ENLACE_ALLOW_UNSIGNED=1` — opt-out from fail-fast (diagnostics only).

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
