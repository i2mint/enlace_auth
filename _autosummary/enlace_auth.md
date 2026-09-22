# enlace_auth

enlace_auth — authentication, sessions, admin dashboard, and per-user stores.

Plug into `enlace` at compose time:

```default
from enlace import build_backend, PlatformConfig
from enlace_auth import plugin as auth_plugin

config = PlatformConfig.from_toml()
app = build_backend(config, plugins=[auth_plugin])
```

When `config.auth.enabled` is True the plugin mounts:

- `/auth/*`      — login, logout, register, whoami, csrf, me/password,
  account (change your own), forgot-password / reset-password
- `/_admin/api/*` — admin user/app management (gated by admin allowlist)
- `/api/{app}/store/*` — per-user data store
- middleware: PlatformAuthMiddleware, CSRFMiddleware, StoreInjectionMiddleware

When it’s False the plugin is a no-op, so installing this package never
changes platform behavior unless the operator opts in.

### Functions

| [`plugin`](#enlace_auth.plugin)(parent, config)   | Mount /auth/ *, /_admin/*, store routes, and middleware on `parent`.   |
|---------------------------------------------------------------------------|------------------------------------------------------------------------|
| [`wire`](#enlace_auth.wire)(parent, config)     | Mount /auth/ *, /_admin/*, store routes, and middleware on `parent`.   |

### Classes

| [`AuthConfig`](#enlace_auth.AuthConfig)(\*\*data)          | Platform-wide authentication configuration.              |
|--------------------------------------------------------------------------------|----------------------------------------------------------|
| [`OAuthProviderConfig`](#enlace_auth.OAuthProviderConfig)(\*\*data) | Configuration for a single OAuth2/OIDC provider.         |
| [`StoreBackendConfig`](#enlace_auth.StoreBackendConfig)(\*\*data)  | Backend configuration for a MutableMapping-backed store. |

### Exceptions

| [`EnlaceAuthConfigError`](#enlace_auth.EnlaceAuthConfigError)   | Raised when auth configuration is unusable at startup.   |
|--------------------------------------------------------------------------|----------------------------------------------------------|

### *class* enlace_auth.AuthConfig(\*\*data)

Bases: `BaseModel`

Platform-wide authentication configuration.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *exception* enlace_auth.EnlaceAuthConfigError

Bases: [`RuntimeError`](https://docs.python.org/3/builtins/exceptions.html#RuntimeError)

Raised when auth configuration is unusable at startup.

### *class* enlace_auth.OAuthProviderConfig(\*\*data)

Bases: `BaseModel`

Configuration for a single OAuth2/OIDC provider.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### *class* enlace_auth.StoreBackendConfig(\*\*data)

Bases: `BaseModel`

Backend configuration for a MutableMapping-backed store.

#### model_config *: [ClassVar](https://docs.python.org/3/library/typing.html#typing.ClassVar)[ConfigDict]* *= {}*

Configuration for the model, should be a dictionary conforming to [`ConfigDict`][pydantic.config.ConfigDict].

### enlace_auth.plugin(parent, config)

Mount /auth/ *, /_admin/*, store routes, and middleware on `parent`.

Plugin entry point. Safe to call when auth is disabled — does nothing.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### enlace_auth.wire(parent, config)

Mount /auth/ *, /_admin/*, store routes, and middleware on `parent`.

Plugin entry point. Safe to call when auth is disabled — does nothing.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### Modules

| [`admin`](enlace_auth.admin.md#module-enlace_auth.admin)             | Admin subsystem for enlace_auth.                                       |
|---------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| [`appmeta`](enlace_auth.appmeta.md#module-enlace_auth.appmeta)         | Editable app-metadata overlay: the write surface for the launcher.     |
| [`auth`](enlace_auth.auth.md#module-enlace_auth.auth)               | Authentication subsystem for enlace.                                   |
| [`config`](enlace_auth.config.md#module-enlace_auth.config)           | Auth-side configuration models.                                        |
| [`diagnostics`](enlace_auth.diagnostics.md#module-enlace_auth.diagnostics) | Auth-specific doctor checks that plug into `enlace.doctor.run_doctor`. |
| [`stores`](enlace_auth.stores.md#module-enlace_auth.stores)           | Per-user stores for enlace.                                            |
