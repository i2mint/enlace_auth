"""CLI for enlace_auth.

Operator helpers for the auth subsystem. These were originally part of the
``enlace`` CLI; they moved here when auth was extracted.

Usage::

    enlace-auth init
    enlace-auth generate-signing-key
    enlace-auth hash-password
    enlace-auth list-sessions [--json]
    enlace-auth revoke-session <session_id>
    enlace-auth list-users [--json]
    enlace-auth set-password <email>
    enlace-auth reset-link <email> [--base-url URL] [--hours N]
    enlace-auth grant <app_id> <email> [--expires YYYY-MM-DD] [--note ...]
    enlace-auth revoke-grant <app_id> <email>
    enlace-auth list-grants [--app NAME] [--json]
"""

from __future__ import annotations

import json as json_module
import secrets
import sys
from getpass import getpass
from pathlib import Path

import cw
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


def _load_user_store(toml_path: Path = Path("platform.toml")):
    """Open the platform's user store (email -> {password_hash, ...})."""
    from enlace_auth.stores import make_file_store_factory

    config = PlatformConfig.from_toml(toml_path)
    auth = coerce_auth_config(config.auth)
    factory = make_file_store_factory(auth.stores.path)
    return factory("users")


def _load_grant_store(toml_path: Path = Path("platform.toml")):
    """Open the platform's per-app runtime grants store."""
    import os

    from enlace_auth.auth.grants import GrantStore
    from enlace_auth.stores import make_file_store_factory

    config = PlatformConfig.from_toml(toml_path)
    auth = coerce_auth_config(config.auth)
    factory = make_file_store_factory(auth.stores.path)
    root = Path(os.path.expanduser(auth.stores.path)) / "grants"
    return GrantStore(factory("grants"), root=root)


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


def list_users(*, json: bool = False, toml: str = "platform.toml"):
    """List registered users from the platform store.

    Args:
        json: Output as JSON.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    store = _load_user_store(Path(toml))
    rows = []
    for email in list(store):
        try:
            rec = store[email]
        except KeyError:
            continue
        rows.append(
            {
                "email": email,
                "created_at": rec.get("created_at") if isinstance(rec, dict) else None,
                "has_password": (
                    isinstance(rec, dict) and bool(rec.get("password_hash"))
                ),
            }
        )
    if json:
        print(json_module.dumps(rows, indent=2))
        return
    if not rows:
        print("No users.")
        return
    for r in rows:
        created = r["created_at"] or 0
        flag = "ok" if r["has_password"] else "NO HASH"
        print(f"{r['email']}  created_at={created:.0f}  {flag}")


def set_password(email: str, *, toml: str = "platform.toml"):
    """Set (or reset) a user's password. Prompts twice for the new value.

    Args:
        email: Email of the user to update. Must already exist in the store.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    from enlace_auth.auth.passwords import hash_password as _hash

    store = _load_user_store(Path(toml))
    key = email.lower()
    try:
        record = store[key]
    except KeyError:
        print(f"No user {key!r} in store.", file=sys.stderr)
        sys.exit(1)
    if not isinstance(record, dict):
        print(f"Corrupt user record for {key!r}.", file=sys.stderr)
        sys.exit(1)

    pw = getpass("New password: ")
    confirm = getpass("Confirm:      ")
    if pw != confirm:
        print("Passwords did not match.", file=sys.stderr)
        sys.exit(1)
    if not pw:
        print("Empty password rejected.", file=sys.stderr)
        sys.exit(1)

    updated = dict(record)
    updated["password_hash"] = _hash(pw)
    store[key] = updated
    print(f"Password updated for {key}.")


def reset_link(
    email: str,
    *,
    base_url: str = None,
    hours: int = None,
    toml: str = "platform.toml",
):
    """Print a one-time link letting a user choose their own password.

    Prefer this to ``set-password``: the operator never invents, learns, or
    transmits someone else's credential — just a link that expires on first
    use. It is also the recovery path that works with no SMTP configured, since
    you deliver the link yourself.

    Args:
        email: Email of the user. Must already exist in the store.
        base_url: Public origin the link should point at (e.g.
            ``https://apps.example.com``). Defaults to the OAuth issuer in
            platform.toml — the origin the platform already declares as its
            public face — and falls back to ``https://{[platform] domain}``.
            Note those can differ (apps often live on a subdomain), so pass
            this explicitly if the printed link looks wrong.
        hours: How long the link stays usable (default: 72).
        toml: Path to platform.toml (default: ./platform.toml).
    """
    import os

    from enlace_auth.auth.reset_tokens import (
        DEFAULT_HANDOFF_TTL,
        mint_reset_token,
        reset_url,
    )

    config = PlatformConfig.from_toml(Path(toml))
    auth = coerce_auth_config(config.auth)
    key = os.environ.get(auth.signing_key_env, "").strip()
    if not key:
        print(
            f"No signing key: env var {auth.signing_key_env} is unset or empty.\n"
            "A link signed with a different key than the running platform uses "
            "would be rejected on arrival, so refusing to mint one.",
            file=sys.stderr,
        )
        sys.exit(1)

    store = _load_user_store(Path(toml))
    target = email.lower()
    try:
        record = store[target]
    except KeyError:
        print(f"No user {target!r} in store.", file=sys.stderr)
        sys.exit(1)
    if not isinstance(record, dict):
        print(f"Corrupt user record for {target!r}.", file=sys.stderr)
        sys.exit(1)

    ttl = DEFAULT_HANDOFF_TTL if hours is None else int(hours) * 3600
    issuer = getattr(getattr(auth, "oauth_server", None), "issuer", None)
    base = base_url or issuer or f"https://{config.domain or 'localhost'}"
    token = mint_reset_token(
        record=record, email=target, signing_key=key, ttl_seconds=ttl
    )
    # The link alone goes to stdout so it stays pipeable; the human note goes
    # to stderr. Flush first, or the two streams interleave out of order.
    print(reset_url(base, token), flush=True)
    print(
        f"\nFor {target}. Valid {ttl // 3600}h, once. Send it over; they pick "
        "their own password.",
        file=sys.stderr,
    )


def grant(
    app_id: str,
    email: str,
    *,
    expires: str = None,
    note: str = None,
    toml: str = "platform.toml",
):
    """Grant a user runtime access to a protected:user app (no redeploy).

    The grant is ADDITIVE on top of the app's app.toml allowed_users.

    Args:
        app_id: The app name (its directory / route name).
        email: Email of the user to grant access to.
        expires: Optional expiry — a date (YYYY-MM-DD, end of day UTC) or full
            ISO-8601 timestamp. Omit for a non-expiring grant.
        note: Optional free-text note stored with the grant.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    from enlace_auth.auth.grants import GrantError, parse_expires_at

    store = _load_grant_store(Path(toml))
    try:
        expires_at = parse_expires_at(expires)
        record = store.grant(
            app_id, email, expires_at=expires_at, granted_by="cli", note=note
        )
    except GrantError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    when = "never" if record["expires_at"] is None else f"{record['expires_at']:.0f}"
    print(f"Granted {record['email']} access to {record['app_id']} (expires={when}).")


def revoke_grant(app_id: str, email: str, *, toml: str = "platform.toml"):
    """Revoke a user's runtime grant for an app.

    Args:
        app_id: The app name.
        email: Email of the user whose grant to revoke.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    if _load_grant_store(Path(toml)).revoke(app_id, email):
        print(f"Revoked {email.lower()} from {app_id}.")
    else:
        print(f"No grant for {email.lower()} on {app_id}.", file=sys.stderr)
        sys.exit(1)


def list_grants(*, app: str = None, json: bool = False, toml: str = "platform.toml"):
    """List runtime grants, optionally filtered to a single app.

    Args:
        app: If given, only list grants for this app.
        json: Output as JSON.
        toml: Path to platform.toml (default: ./platform.toml).
    """
    import time

    store = _load_grant_store(Path(toml))
    grants = store.list_for_app(app) if app else store.list_all()
    if json:
        print(json_module.dumps(grants, indent=2))
        return
    if not grants:
        print(f"No grants for {app}." if app else "No grants.")
        return
    now = time.time()
    for g in sorted(
        grants, key=lambda r: (r.get("app_id") or "", r.get("email") or "")
    ):
        exp = g.get("expires_at")
        if exp is None:
            status = "never"
        elif exp > now:
            status = f"until {exp:.0f}"
        else:
            status = f"EXPIRED ({exp:.0f})"
        print(f"{g.get('app_id')}  {g.get('email')}  {status}")


def _load_refresh_store(toml_path: Path = Path("platform.toml")):
    """Open the OAuth refresh-token store for the configured platform."""
    from enlace_auth.stores import make_file_store_factory

    config = PlatformConfig.from_toml(toml_path)
    auth = coerce_auth_config(config.auth)
    factory = make_file_store_factory(auth.stores.path)
    return factory("oauth_refresh_tokens")


def list_connector_sessions(*, json: bool = False, toml: str = "platform.toml"):
    """List live MCP connector sessions (one row per refresh-token family).

    Answers the question that went unanswered for a day during the outage this
    was written after: *does this connector currently have a working session,
    and whose is it?* A connector's process being healthy says nothing about it.
    """
    import json as json_module

    store = _load_refresh_store(Path(toml))
    families: dict[str, dict] = {}
    for key in store:
        try:
            record = store[key]
        except KeyError:
            continue
        if not record or record.get("consumed_at") is not None:
            continue  # spent tokens are tombstones, not sessions
        families[record.get("family", key)] = {
            "family": record.get("family"),
            "email": record.get("email"),
            "resource": record.get("resource"),
            "client_id": record.get("client_id"),
            "issued_at": record.get("iat"),
            "expires_at": record.get("exp"),
            "family_expires_at": record.get("family_exp"),
        }
    rows = sorted(
        families.values(), key=lambda r: (r["resource"] or "", r["email"] or "")
    )
    if json:
        print(json_module.dumps(rows, indent=2, default=str))
        return
    if not rows:
        print("No live connector sessions.")
        return
    for row in rows:
        print(f"{row['resource']}  {row['email']}  family={row['family']}")


def revoke_connector_session(
    family: str = None, *, email: str = None, toml: str = "platform.toml"
):
    """Revoke connector sessions by refresh-token *family* or by *email*.

    The access tokens this server issues are self-contained JWTs with no
    denylist, so revoking here stops *renewal*: the session ends within one
    access-token lifetime rather than instantly. That is the only revocation
    path there is, which is the reason to keep access-token TTLs short.
    """
    if not family and not email:
        print("Give a family id or --email.")
        return
    store = _load_refresh_store(Path(toml))
    removed = 0
    for key in list(store):
        try:
            record = store[key]
        except KeyError:
            continue
        if not record:
            continue
        if (family and record.get("family") == family) or (
            email and (record.get("email") or "").lower() == email.lower()
        ):
            try:
                del store[key]
                removed += 1
            except KeyError:
                pass
    target = family or email
    print(f"Revoked {removed} refresh token(s) for {target}.")


#: The SSOT for the CLI surface: a verb that is not in this list does not exist.
COMMANDS = [
    init,
    generate_signing_key,
    hash_password,
    list_sessions,
    revoke_session,
    list_users,
    set_password,
    reset_link,
    grant,
    revoke_grant,
    list_grants,
    list_connector_sessions,
    revoke_connector_session,
]


def main():
    """Dispatch the ``enlace-auth`` command.

    ``cw.dispatch`` *returns* the exit code where ``argh`` exited by itself, so the
    ``SystemExit`` is load-bearing: without it every usage error would exit 0.

    The convention is cw's default (:data:`cw.ARGH`) on purpose.
    ``revoke_connector_session(family=None, *, ...)`` is a *defaulted positional*, which
    the default renders as the option ``--family``; ``cw.MODERN`` would turn it into the
    positional ``enlace-auth revoke-connector-session <family>``. That reinterpretation
    parses, runs, and revokes something else. See ``tests/test_cli_surface.py``.
    """
    raise SystemExit(cw.dispatch(COMMANDS))


if __name__ == "__main__":
    main()
