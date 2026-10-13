"""A malformed OAuth allowlist config fails at load, never open (#39).

The config models used to ignore unknown keys, so a misspelled or misnested
``resource_allowlist`` table arrived as an empty one, and an empty allowlist meant
every connector open to every account. Each case below is a config shape that
used to load that way and must now be refused with a message naming the problem.
"""

import textwrap

import pytest
from enlace.base import PlatformConfig

from enlace_auth.config import AuthConfig, OAuthServerConfig, coerce_auth_config
from enlace_auth.resource_policy import parse_resource_allowlist

RES = "https://apps.example.com/api/x_mcp/mcp"


def _load_toml(tmp_path, body: str) -> AuthConfig:
    path = tmp_path / "platform.toml"
    path.write_text(textwrap.dedent(body))
    return coerce_auth_config(PlatformConfig.from_toml(path).auth)


# --- typos and misnesting: every one used to load as "no allowlist" -----------


@pytest.mark.parametrize(
    "body, named",
    [
        (  # misspelled table name
            f"""
            [auth.oauth_server]
            enabled = true
            [auth.oauth_server.resource_allowlists]
            "{RES}" = ["a@example.com"]
            """,
            "resource_allowlists",
        ),
        (  # nested under [auth] instead of [auth.oauth_server]
            f"""
            [auth.oauth_server]
            enabled = true
            [auth.resource_allowlist]
            "{RES}" = ["a@example.com"]
            """,
            "resource_allowlist",
        ),
        (  # the server table itself misspelled: it stays disabled, but say so
            f"""
            [auth.oauth-server]
            enabled = true
            [auth.oauth-server.resource_allowlist]
            "{RES}" = ["a@example.com"]
            """,
            "oauth-server",
        ),
        (  # a top-level table enlace drops: the server sees no allowlist at all
            f"""
            [auth.oauth_server]
            enabled = true
            [resource_allowlist]
            "{RES}" = ["a@example.com"]
            """,
            "allow_unlisted_resources",
        ),
    ],
)
def test_a_misplaced_allowlist_is_refused_at_load(tmp_path, body, named):
    with pytest.raises(ValueError, match=named):
        _load_toml(tmp_path, body)


def test_a_misspelled_setting_anywhere_in_auth_is_refused():
    for raw in (
        {"enabled": True, "registraton_open": True},
        {"stores": {"backend": "file", "pth": "/x"}},
        {
            "oauth": {
                "google": {
                    "client_id_env": "A",
                    "client_secret_env": "B",
                    "trust_unverified_emails": True,
                }
            }
        },
    ):
        with pytest.raises(ValueError, match="Extra inputs are not permitted"):
            coerce_auth_config(raw)


# --- the empty allowlist is an explicit choice, not a default -----------------


def test_an_enabled_server_with_no_allowlist_is_refused():
    with pytest.raises(ValueError, match="allow_unlisted_resources"):
        OAuthServerConfig(enabled=True)


def test_an_open_server_must_be_asked_for():
    cfg = OAuthServerConfig(enabled=True, allow_unlisted_resources=True)
    assert cfg.resource_allowlist == {}


def test_a_disabled_server_needs_no_allowlist():
    assert OAuthServerConfig().resource_allowlist == {}


def test_the_open_flag_beside_an_allowlist_is_a_contradiction():
    with pytest.raises(ValueError, match="conflicts"):
        OAuthServerConfig(
            enabled=True,
            allow_unlisted_resources=True,
            resource_allowlist={RES: ["a@example.com"]},
        )


# --- the shape of the allowlist itself ------------------------------------------


@pytest.mark.parametrize(
    "allowlist, named",
    [
        ({RES: "a@example.com"}, "valid list"),
        ({RES: {"emails": ["a@example.com"]}}, "valid list"),
        ({RES: ["*@example.com"]}, "pattern"),
        ({RES: ["all"]}, "not an email"),
        ({RES: ["a@example.com "]}, "not an email"),
        ({RES: [""]}, "not an email"),
        ({"x_mcp": ["a@example.com"]}, "not an absolute http"),
        ({"https://apps.example.com/": ["*"]}, "names an origin"),
        ({RES + "?x=1": ["*"]}, "query"),
        ({RES: ["*"], RES + "/": ["a@example.com"]}, "same resource"),
        ({RES: ["a@example.com", "*"]}, "stand alone"),
        # Non-canonical spellings: none can equal a connector's audience.
        ({"https://apps.example.com:443/api/x_mcp/mcp": ["*"]}, "default port"),
        ({"HTTPS://apps.example.com/api/x_mcp/mcp": ["*"]}, "scheme"),
        ({"https://Apps.Example.com/api/x_mcp/mcp": ["*"]}, "host"),
        ({"https://apps.example.com./api/x_mcp/mcp": ["*"]}, "trailing dot"),
        ({"https://apps.example.com//api/x_mcp/mcp": ["*"]}, "path segment"),
        ({"https://apps.example.com/api/../x_mcp/mcp": ["*"]}, "path segment"),
    ],
)
def test_a_malformed_allowlist_names_its_problem(allowlist, named):
    with pytest.raises(ValueError, match=named):
        OAuthServerConfig(enabled=True, resource_allowlist=allowlist)


def test_a_dotted_bare_key_is_refused(tmp_path):
    """Unquoted, a URL-ish key becomes nested tables; that must not load."""
    with pytest.raises(ValueError):
        _load_toml(
            tmp_path,
            """
            [auth.oauth_server]
            enabled = true
            [auth.oauth_server.resource_allowlist]
            apps.example.com = ["*"]
            """,
        )


def test_a_display_name_key_that_can_never_match_is_refused():
    with pytest.raises(ValueError, match="resource_display_names"):
        OAuthServerConfig(
            enabled=True,
            resource_allowlist={RES: ["*"]},
            resource_display_names={"x_mcp": "X"},
        )


def test_a_well_formed_allowlist_loads_normalized(tmp_path):
    auth = _load_toml(
        tmp_path,
        f"""
        [auth.oauth_server]
        enabled = true
        [auth.oauth_server.resource_allowlist]
        "{RES}/" = ["A@Example.com", "b@example.com"]
        """,
    )
    assert parse_resource_allowlist(auth.oauth_server.resource_allowlist) == {
        RES: frozenset({"a@example.com", "b@example.com"})
    }


def test_the_plugin_refuses_to_start_on_a_malformed_allowlist(tmp_path, monkeypatch):
    """The refusal happens where the platform loads, not at the first request."""
    from enlace import build_backend

    from enlace_auth import plugin as auth_plugin

    monkeypatch.setenv("ENLACE_SIGNING_KEY", "x" * 48)
    config = PlatformConfig(
        apps_dir=tmp_path,
        auth={
            "enabled": True,
            "stores": {"backend": "file", "path": str(tmp_path / "platform")},
            "oauth_server": {
                "enabled": True,
                "key_dir": str(tmp_path / "keys"),
                "resource_allowlists": {RES: ["a@example.com"]},
            },
        },
    )
    with pytest.raises(ValueError, match="resource_allowlists"):
        build_backend(config, plugins=[auth_plugin])


def test_the_open_flag_must_be_a_real_boolean():
    """``allow_unlisted_resources = "true"`` is a typo for a boolean, not an opt-in."""
    with pytest.raises(ValueError, match="boolean"):
        OAuthServerConfig(enabled=True, allow_unlisted_resources="true")
