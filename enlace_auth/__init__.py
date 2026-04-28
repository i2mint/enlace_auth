"""enlace_auth — authentication, sessions, admin dashboard, and per-user stores.

Plug into ``enlace`` at compose time::

    from enlace import build_backend, PlatformConfig
    from enlace_auth import plugin as auth_plugin

    config = PlatformConfig.from_toml()
    app = build_backend(config, plugins=[auth_plugin])

When ``config.auth.enabled`` is True the plugin mounts:

- ``/auth/*``      — login, logout, register, whoami, csrf, me/password
- ``/_admin/api/*`` — admin user/app management (gated by admin allowlist)
- ``/api/{app}/store/*`` — per-user data store
- middleware: PlatformAuthMiddleware, CSRFMiddleware, StoreInjectionMiddleware

When it's False the plugin is a no-op, so installing this package never
changes platform behavior unless the operator opts in.
"""

from enlace_auth.config import (
    AccessLevel,
    AuthConfig,
    OAuthProviderConfig,
    StoreBackendConfig,
)
from enlace_auth.plugin import EnlaceAuthConfigError, plugin, wire

__version__ = "0.0.1"

__all__ = [
    "AccessLevel",
    "AuthConfig",
    "EnlaceAuthConfigError",
    "OAuthProviderConfig",
    "StoreBackendConfig",
    "plugin",
    "wire",
]
