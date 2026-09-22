# enlace_auth.auth.oauth

OAuth2/OIDC login via Authlib.

Lazy import — `authlib` lives behind the `enlace[oauth]` extra. Providers
are configured in `platform.toml` under `[auth.oauth.{name}]` with
`client_id_env` / `client_secret_env` pointing at env vars (secrets never
in TOML). On callback we create a local session — the upstream tokens are
discarded because we use OAuth for identity only, not API access.

Built-in provider presets for Google and GitHub auto-fill the well-known
endpoints; other providers need explicit URLs in the config.

### Functions

| [`make_oauth_router`](#enlace_auth.auth.oauth.make_oauth_router)(\*, providers, ...[, ...])   | Build an OAuth router or return None if no providers are configured.   |
|-------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|

### enlace_auth.auth.oauth.make_oauth_router(\*, providers, session_store, user_store, signing_key, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, can_register=<function <lambda>>)

Build an OAuth router or return None if no providers are configured.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[`APIRouter`]
