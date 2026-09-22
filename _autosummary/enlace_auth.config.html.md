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

| [`AuthConfig`](#enlace_auth.config.AuthConfig)(\*\*data)          | Platform-wide authentication configuration.                   |
|--------------------------------------------------------------------------------|---------------------------------------------------------------|
| [`OAuthProviderConfig`](#enlace_auth.config.OAuthProviderConfig)(\*\*data) | Configuration for a single OAuth2/OIDC provider.              |
| [`OAuthServerConfig`](#enlace_auth.config.OAuthServerConfig)(\*\*data)   | OAuth 2.1 authorization-server settings (for MCP connectors). |
| [`StoreBackendConfig`](#enlace_auth.config.StoreBackendConfig)(\*\*data)  | Backend configuration for a MutableMapping-backed store.      |

### *class* enlace_auth.config.AuthConfig(\*\*data)

Bases: `BaseModel`

Platform-wide authentication configuration.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.OAuthProviderConfig(\*\*data)

Bases: `BaseModel`

Configuration for a single OAuth2/OIDC provider.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.OAuthServerConfig(\*\*data)

Bases: `BaseModel`

OAuth 2.1 authorization-server settings (for MCP connectors).

When `enabled`, `enlace_auth` issues signed JWT access tokens that a
Claude.ai custom connector validates — reusing the platform user store and
session login. See [`enlace_auth.auth.oauth_server`](enlace_auth.auth.oauth_server.html.md#module-enlace_auth.auth.oauth_server).

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.config.StoreBackendConfig(\*\*data)

Bases: `BaseModel`

Backend configuration for a MutableMapping-backed store.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

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
