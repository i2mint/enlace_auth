# enlace_auth.auth.oauth

OAuth2/OIDC login via Authlib.

Lazy import — `authlib` lives behind the `enlace[oauth]` extra. Providers
are configured in `platform.toml` under `[auth.oauth.{name}]` with
`client_id_env` / `client_secret_env` pointing at env vars (secrets never
in TOML). On callback we create a local session — the upstream tokens are
discarded because we use OAuth for identity only, not API access.

Two rules keep an OAuth login from being weaker than the account it opens:

- **The anti-CSRF state lives in a signed cookie** scoped to `/auth`
  (`_oauth_state_session()`). Authlib keeps the `state`, nonce and PKCE
  verifier in `request.session`; the plugin installs no Starlette
  `SessionMiddleware`, so this module supplies that session itself. A callback
  whose `state` was not issued to *this* browser is refused.
- **An identity is bound to the provider’s stable subject** (`sub`, or
  `tid`/`oid` for Microsoft, GitHub’s numeric `id`), recorded as
  `oauth_links[provider]` on the account. A later login must present the same
  subject. An existing *password* account, or one linked to another provider, is
  never taken over by an email match alone.

Residual limits, by design: the state cookie is signed but not bound to the
browser, so a script that can set cookies on the platform origin (any
co-hosted app) could plant its own state for a browser that has none and so
log that browser in as the attacker (two cookies of the name are refused). An
account created by a provider before links existed is bound to the first
subject that signs in to it after the upgrade. A password reset (admin, emailed
link, CLI) unlinks every external sign-in. The cookie path assumes the router
is mounted at `/auth` with no root path.

Built-in provider presets for Google and GitHub auto-fill the well-known
endpoints; other providers need explicit URLs in the config.

### Functions

| [`make_oauth_router`](#enlace_auth.auth.oauth.make_oauth_router)(\*, providers, ...[, ...])   | Build an OAuth router or return None if no providers are configured.   |
|-------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|

### enlace_auth.auth.oauth.make_oauth_router(\*, providers, session_store, user_store, signing_key, cookie_name='enlace_session', session_max_age=86400, secure_cookies=True, can_register=<function <lambda>>, state_cookie_name='enlace_oauth_state', state_max_age=600)

Build an OAuth router or return None if no providers are configured.

*state_cookie_name* / *state_max_age* name and bound the signed cookie that
carries Authlib’s per-login state between `/auth/login/{provider}` and the
callback (see the module docstring). It is only used when no Starlette
`SessionMiddleware` already provides `request.session`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[`APIRouter`]
