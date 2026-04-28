"""TOML parsing for [auth], [auth.stores], [auth.oauth.*], [stores.user_data].

After the auth split, ``PlatformConfig`` keeps these tables as untyped dicts.
``coerce_auth_config`` deserializes them into ``AuthConfig`` on demand.
"""

from pathlib import Path

from enlace.base import AppConfig, PlatformConfig
from enlace_auth.config import coerce_auth_config, coerce_stores_map


def test_auth_section_parsed(tmp_path: Path):
    toml = tmp_path / "platform.toml"
    toml.write_text(
        """
[auth]
enabled = true
session_cookie_name = "my_session"
session_max_age_seconds = 3600
signing_key_env = "MY_KEY"
secure_cookies = false

[auth.stores]
backend = "file"
path = "/tmp/platform_store"

[auth.oauth.google]
client_id_env = "GOOGLE_ID"
client_secret_env = "GOOGLE_SECRET"
scopes = ["openid", "email"]

[stores.user_data]
backend = "file"
path = "/tmp/user_data"
"""
    )
    config = PlatformConfig.from_toml(toml)
    auth = coerce_auth_config(config.auth)
    assert auth.enabled is True
    assert auth.session_cookie_name == "my_session"
    assert auth.session_max_age_seconds == 3600
    assert auth.signing_key_env == "MY_KEY"
    assert auth.secure_cookies is False
    assert auth.stores.path == "/tmp/platform_store"
    assert "google" in auth.oauth
    g = auth.oauth["google"]
    assert g.client_id_env == "GOOGLE_ID"
    assert g.scopes == ["openid", "email"]
    stores = coerce_stores_map(config.stores)
    assert "user_data" in stores
    assert stores["user_data"].path == "/tmp/user_data"


def test_auth_defaults_when_section_absent(tmp_path: Path):
    toml = tmp_path / "platform.toml"
    toml.write_text("")
    config = PlatformConfig.from_toml(toml)
    auth = coerce_auth_config(config.auth)
    assert auth.enabled is False
    assert auth.session_cookie_name == "enlace_session"
    assert config.stores == {}


def test_shared_password_env_parsed_in_app(tmp_path: Path):
    """An app's shared_password_env should round-trip through AppConfig."""
    app = AppConfig(
        name="secret_app",
        route_prefix="/api/secret_app",
        app_type="asgi_app",
        access="protected:shared",
        shared_password_env="SECRET_APP_PW",
    )
    assert app.shared_password_env == "SECRET_APP_PW"
    assert app.access == "protected:shared"
