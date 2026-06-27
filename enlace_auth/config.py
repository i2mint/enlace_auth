"""Auth-side configuration models.

These were originally in ``enlace.base``. They have moved here because they
describe the auth subsystem's behavior, not the platform's composition. enlace
itself no longer imports anything from here; ``enlace_auth.plugin`` reads them
off ``PlatformConfig`` via ``getattr(config, "auth", None)`` and the loose
``stores`` mapping.

The TOML loader in ``enlace.base.PlatformConfig.from_toml`` accepts
``[auth.*]`` and ``[stores.*]`` tables and forwards them through the model;
we just deserialize them into typed objects here when the plugin runs.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

# "local" is a legacy alias for "public" — middleware treats it as public.
AccessLevel = Literal["public", "protected:shared", "protected:user", "local"]


class StoreBackendConfig(BaseModel):
    """Backend configuration for a MutableMapping-backed store."""

    backend: str = "file"
    path: str = "~/.enlace/platform_store"


class OAuthProviderConfig(BaseModel):
    """Configuration for a single OAuth2/OIDC provider."""

    client_id_env: str
    client_secret_env: str
    scopes: list[str] = Field(default_factory=list)
    authorize_url: Optional[str] = None
    token_url: Optional[str] = None
    userinfo_url: Optional[str] = None
    server_metadata_url: Optional[str] = None


class OAuthServerConfig(BaseModel):
    """OAuth 2.1 authorization-server settings (for MCP connectors).

    When ``enabled``, ``enlace_auth`` issues signed JWT access tokens that a
    Claude.ai custom connector validates — reusing the platform user store and
    session login. See :mod:`enlace_auth.auth.oauth_server`.
    """

    enabled: bool = False
    issuer: Optional[str] = Field(
        default=None,
        description=(
            "Token issuer + discovery origin (e.g. https://apps.thorwhalen.com). "
            "When unset, derived from each request's base URL."
        ),
    )
    key_dir: str = "~/.enlace/oauth_keys"
    access_token_ttl_seconds: int = 3600
    code_ttl_seconds: int = 120
    scopes_supported: list[str] = Field(default_factory=lambda: ["mcp:read"])
    require_consent: bool = True


class AuthConfig(BaseModel):
    """Platform-wide authentication configuration."""

    enabled: bool = False
    session_cookie_name: str = "enlace_session"
    session_max_age_seconds: int = 86400
    signing_key_env: str = "ENLACE_SIGNING_KEY"
    secure_cookies: bool = True
    stores: StoreBackendConfig = Field(default_factory=StoreBackendConfig)
    oauth: dict[str, OAuthProviderConfig] = Field(default_factory=dict)
    oauth_server: OAuthServerConfig = Field(default_factory=OAuthServerConfig)
    admin_emails_env: str = Field(
        default="ENLACE_ADMIN_EMAILS",
        description=(
            "Env var holding a comma-separated list of admin emails. Admins "
            "see the dashboard at /_admin and can manage users."
        ),
    )
    registration_open: bool = Field(
        default=False,
        description=(
            "Whether anyone can self-register via /auth/register or OAuth. "
            "When False (default), only emails listed in "
            "registration_allowlist_env (or admin_emails_env) can complete "
            "signup; everyone else gets 403. Existing users can always log "
            "in regardless of this setting."
        ),
    )
    registration_allowlist_env: str = Field(
        default="ENLACE_REGISTRATION_ALLOWLIST",
        description=(
            "Env var holding a comma-separated list of emails permitted to "
            "self-register (via /auth/register or OAuth callback) when "
            "registration_open is False. Admin emails are always allowed."
        ),
    )


def coerce_auth_config(raw: Any) -> AuthConfig:
    """Accept dict / AuthConfig / None and return an AuthConfig.

    Used by the plugin so it can read whatever ``PlatformConfig`` happens to
    hold without forcing enlace to know about ``AuthConfig`` itself.
    """
    if raw is None:
        return AuthConfig()
    if isinstance(raw, AuthConfig):
        return raw
    if isinstance(raw, BaseModel):
        return AuthConfig(**raw.model_dump())
    return AuthConfig(**raw)


def coerce_stores_map(raw: Any) -> dict[str, StoreBackendConfig]:
    """Accept the loose ``config.stores`` dict and yield typed configs."""
    if not raw:
        return {}
    out: dict[str, StoreBackendConfig] = {}
    for k, v in dict(raw).items():
        if isinstance(v, StoreBackendConfig):
            out[k] = v
        elif isinstance(v, BaseModel):
            out[k] = StoreBackendConfig(**v.model_dump())
        else:
            out[k] = StoreBackendConfig(**v)
    return out
