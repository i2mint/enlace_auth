# enlace_auth.config

Auth-side configuration models.

These were originally in `enlace.base`. They have moved here because they
describe the auth subsystem’s behavior, not the platform’s composition. enlace
itself no longer imports anything from here; `enlace_auth.plugin` reads them
off `PlatformConfig` via `getattr(config, "auth", None)` and the loose
`stores` mapping.

The TOML loader in `enlace.base.PlatformConfig.from_toml` accepts
`[auth.*]` and `[stores.*]` tables and forwards them through the model;
we just deserialize them into typed objects here when the plugin runs.

### Functions

| [`coerce_auth_config`](#enlace_auth.config.coerce_auth_config)(raw)   | Accept dict / AuthConfig / None and return an AuthConfig.      |
|----------------------------------------------------------------------------|----------------------------------------------------------------|
| [`coerce_stores_map`](#enlace_auth.config.coerce_stores_map)(raw)    | Accept the loose `config.stores` dict and yield typed configs. |

### Classes

| [`AuthConfig`](#enlace_auth.config.AuthConfig)(\*[, enabled, ...])                     | Platform-wide authentication configuration.                   |
|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| [`OAuthProviderConfig`](#enlace_auth.config.OAuthProviderConfig)(\*, client_id_env, ...[, ...]) | Configuration for a single OAuth2/OIDC provider.              |
| [`OAuthServerConfig`](#enlace_auth.config.OAuthServerConfig)(\*[, enabled, issuer, ...])      | OAuth 2.1 authorization-server settings (for MCP connectors). |
| [`StoreBackendConfig`](#enlace_auth.config.StoreBackendConfig)(\*[, backend, path])            | Backend configuration for a MutableMapping-backed store.      |

### *class* enlace_auth.config.AuthConfig(\*, enabled=False, session_cookie_name='enlace_session', session_max_age_seconds=86400, signing_key_env='ENLACE_SIGNING_KEY', secure_cookies=True, stores=<factory>, oauth=<factory>, oauth_server=<factory>, admin_emails_env='ENLACE_ADMIN_EMAILS', registration_open=False, registration_allowlist_env='ENLACE_REGISTRATION_ALLOWLIST')

Bases: `_StrictModel`

Platform-wide authentication configuration.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {'extra': 'forbid'}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.OAuthProviderConfig(\*, client_id_env, client_secret_env, scopes=<factory>, authorize_url=None, token_url=None, userinfo_url=None, server_metadata_url=None, trust_unverified_email=False)

Bases: `_StrictModel`

Configuration for a single OAuth2/OIDC provider.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {'extra': 'forbid'}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.OAuthServerConfig(\*, enabled=False, issuer=None, key_dir='~/.enlace/oauth_keys', access_token_ttl_seconds=3600, refresh_token_ttl_seconds=2592000, refresh_reuse_grace_seconds=60, refresh_reuse_detection_seconds=86400, refresh_family_max_lifetime_seconds=7776000, client_ttl_seconds=15552000, code_ttl_seconds=120, consent_ttl_seconds=600, scopes_supported=<factory>, require_consent=True, resource_allowlist=<factory>, allow_unlisted_resources=False, resource_display_names=<factory>)

Bases: `_StrictModel`

OAuth 2.1 authorization-server settings (for MCP connectors).

When `enabled`, `enlace_auth` issues signed JWT access tokens that a
Claude.ai custom connector validates — reusing the platform user store and
session login. See [`enlace_auth.auth.oauth_server`](enlace_auth.auth.oauth_server.html.md#module-enlace_auth.auth.oauth_server).

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {'extra': 'forbid'}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.StoreBackendConfig(, backend='file', path='~/.enlace/platform_store')

Bases: `_StrictModel`

Backend configuration for a MutableMapping-backed store.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {'extra': 'forbid'}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### enlace_auth.config.coerce_auth_config(raw)

Accept dict / AuthConfig / None and return an AuthConfig.

Used by the plugin so it can read whatever `PlatformConfig` happens to
hold without forcing enlace to know about `AuthConfig` itself.

* **Return type:**
  [`AuthConfig`](#enlace_auth.config.AuthConfig)

### enlace_auth.config.coerce_stores_map(raw)

Accept the loose `config.stores` dict and yield typed configs.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`StoreBackendConfig`](#enlace_auth.config.StoreBackendConfig)]
