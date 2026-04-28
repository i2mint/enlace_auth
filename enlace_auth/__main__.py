"""CLI for enlace_auth.

Operator helpers for the auth subsystem. These were originally part of the
``enlace`` CLI; they moved here when auth was extracted.

Usage::

    enlace-auth init
    enlace-auth generate-signing-key
    enlace-auth hash-password
    enlace-auth list-sessions [--json]
    enlace-auth revoke-session <session_id>
"""

from __future__ import annotations

import json as json_module
import secrets
import sys
from getpass import getpass
from pathlib import Path

import argh

from enlace.base import PlatformConfig

from enlace_auth.config import coerce_auth_config


def init():
    """Print a starter ``[auth]`` block for platform.toml.

    Copy the output into your ``platform.toml`` and edit the paths and env
    var names as needed.
    """
    print(
        "# Copy into your platform.toml and edit as needed.\n"
        "[auth]\n"
        "enabled = true\n"
        'session_cookie_name = "enlace_session"\n'
        "session_max_age_seconds = 86400\n"
        'signing_key_env = "ENLACE_SIGNING_KEY"\n'
        'admin_emails_env = "ENLACE_ADMIN_EMAILS"\n'
        "secure_cookies = true\n"
        "\n"
        "[auth.stores]\n"
        'backend = "file"\n'
        'path = "~/.enlace/platform_store"\n'
        "\n"
        "[stores.user_data]\n"
        'backend = "file"\n'
        'path = "~/.enlace/user_data"\n'
        "\n"
        "# Then in your launcher:\n"
        "#   from enlace import build_backend\n"
        "#   from enlace_auth import plugin as auth_plugin\n"
        "#   app = build_backend(config, plugins=[auth_plugin])\n"
        "# Or with the bundled factory: ENLACE_PLUGINS=enlace_auth:plugin\n"
    )


def generate_signing_key():
    """Print a URL-safe 32-byte signing key suitable for ENLACE_SIGNING_KEY."""
    print(secrets.token_urlsafe(32))


def hash_password():
    """Prompt for a password and print its argon2id hash.

    Use the output as the value of an app's ``shared_password_env`` variable.
    """
    from enlace_auth.auth.passwords import hash_password as _hash

    pw = getpass("Password: ")
    confirm = getpass("Confirm:  ")
    if pw != confirm:
        print("Passwords did not match.", file=sys.stderr)
        sys.exit(1)
    print(_hash(pw))


def _load_session_store(toml_path: Path = Path("platform.toml")):
    """Build a SessionStore pointing at the configured platform store."""
    from enlace_auth.auth import SessionStore
    from enlace_auth.stores import make_file_store_factory

    config = PlatformConfig.from_toml(toml_path)
    auth = coerce_auth_config(config.auth)
    factory = make_file_store_factory(auth.stores.path)
    return SessionStore(factory("sessions"))


def list_sessions(*, json: bool = False, toml: str = "platform.toml"):
    """List active sessions from the platform store.

    Args:
        json: Output as JSON.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    sessions = _load_session_store(Path(toml)).list_all()
    if json:
        print(
            json_module.dumps(
                [{"session_id": sid, **info} for sid, info in sessions], indent=2
            )
        )
        return
    if not sessions:
        print("No active sessions.")
        return
    for sid, info in sessions:
        user = info.get("user_id") or "?"
        email = info.get("email") or "-"
        created = info.get("created_at") or 0
        print(f"{sid}  user={user}  email={email}  created_at={created:.0f}")


def revoke_session(session_id: str, *, toml: str = "platform.toml"):
    """Delete a session by id.

    Args:
        session_id: The session id to revoke.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    ok = _load_session_store(Path(toml)).delete(session_id)
    if ok:
        print(f"Revoked {session_id}")
    else:
        print(f"No session named {session_id}", file=sys.stderr)
        sys.exit(1)


def main():
    argh.dispatch_commands(
        [
            init,
            generate_signing_key,
            hash_password,
            list_sessions,
            revoke_session,
        ]
    )


if __name__ == "__main__":
    main()
