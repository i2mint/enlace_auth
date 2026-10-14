# enlace_auth

Authentication layer for the [enlace](https://github.com/i2mint/enlace) multi-app platform: sessions, CSRF, admin dashboard, per-user stores, owner-granted shares, runtime access grants, OAuth2/OIDC login, and an OAuth 2.1 authorization server for MCP connectors. enlace itself is auth-agnostic; this package plugs in at compose time through `build_backend(config, plugins=[enlace_auth.plugin])`. It is the security boundary for every app on the platform, so treat a behavior change here as a security change.

## Run the tests

```bash
uv venv -q .venv && . .venv/bin/activate
uv pip install -q -e ".[dev,oauth]" pip
python -m pytest -q --doctest-modules enlace_auth tests
```

CI installs the `dev` extra (`[tool.wads.ci.install]`): without `httpx` and `authlib` the TestClient-based tests fail at collection. Python 3.10 and 3.12 are tested. Lint with `ruff check` and `ruff format`; CI reformats after merge and bumps the version itself, so do not edit `version` in `pyproject.toml`.

## Architecture

- `plugin.py` is the only wiring point. `wire(app, config)` builds the stores, routers and middleware. It is a no-op when `config.auth.enabled` is false. Order of execution per request: `PlatformAuthMiddleware` (outermost) -> `StoreInjectionMiddleware` -> `CSRFMiddleware` -> app.
- `auth/middleware.py` holds `PlatformAuthMiddleware` (access rule by longest route prefix, deny by default) and `CSRFMiddleware` (signed double-submit). Both are pure ASGI. Never use `BaseHTTPMiddleware`.
- `auth/routes.py` is `/auth/*`. `auth/pages.py` is the sign-in HTML. `auth/oauth.py` is OAuth login. `auth/oauth_server.py` is the connector authorization server. `auth/share_routes.py` is `/auth/shares/*`.
- `auth/sessions.py`, `grants.py`, `shares.py`, `reset_tokens.py`, `revocation.py` are storage-backed state, each over a `MutableMapping` (see `stores/backends.py`). Tests use plain dicts or the file backend under `tmp_path`.
- `admin/routes.py` is `/_admin/api/*` and the dashboard page (`admin/static/index.html`). `appmeta.py` is the launcher-metadata overlay. `stores/` is the per-user store (`request.state.store`).
- `emails.py` is the single normal form for an address. Compare addresses only through it (`normalize_email`, `account_spellings`); an account key from an untrusted party is compared exactly as stored.
- `diagnostics.py` holds the doctor checks that `enlace doctor` discovers. `__main__.py` is the `enlace-auth` CLI (`python -m enlace_auth --help`).

## Conventions that bite

- Fail closed. An unknown access level, an unlisted connector resource, an app with no shared password all deny.
- `enlace.access.is_user_allowed` is the one predicate for "may this user open this app". The gate and the launcher both call it. Do not fork it.
- Every state-changing request needs the `X-CSRF-Token` header from `GET /auth/csrf`. The CSRF cookie is minted only on `/auth`, `/_admin` and `protected:*` app prefixes (`mint_prefixes`), never on public pages (#31). A test that needs a token calls `/auth/csrf`, not an arbitrary GET.
- A credential change must end sessions and connector refresh families together: route it through `on_credentials_changed` (`auth/revocation.py`).
- Tests build a real platform: write apps into `tmp_path`, `discover_apps`, `build_backend(config, plugins=[auth_plugin])`, `TestClient`. Copy a nearby test (`tests/test_csrf_scope.py` is the smallest) rather than mocking the middleware.
- A bug fix lands with a test that fails first. Security-relevant changes also get a test for the unchanged denial path.

## Skills

Consumer skill (ships with the wheel): `enlace_auth/data/skills/enlace-auth-usage`. Developer skill: `skills/enlace-auth-dev`. `.claude/skills/` holds relative symlinks to both.
