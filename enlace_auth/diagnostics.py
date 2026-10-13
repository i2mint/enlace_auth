"""Auth-specific doctor checks that plug into ``enlace.doctor.run_doctor``.

Usage::

    from enlace.doctor import run_doctor
    from enlace_auth.diagnostics import static_checks, http_checks

    report = run_doctor(
        config,
        base_url="http://localhost:8000",
        extra_static_checks=static_checks,
        extra_http_checks=http_checks,
    )

These checks were previously hard-wired into ``enlace.doctor`` itself; they
moved here when auth was extracted from enlace.
"""

from __future__ import annotations

import functools
import json
import os
from typing import Iterable, Optional

from enlace import doctor as _doctor
from enlace.base import PlatformConfig
from enlace.doctor import FAIL, PASS, SKIP, WARN, Check

from enlace_auth.config import coerce_auth_config


def _auth_config_error(config: PlatformConfig) -> str | None:
    """Why ``[auth]`` does not load, or ``None`` if it does."""
    try:
        coerce_auth_config(getattr(config, "auth", None))
    except ValueError as e:  # pydantic's ValidationError is a ValueError
        return str(e)
    return None


def check_auth_config(config: PlatformConfig) -> Iterable[Check]:
    """Report an ``[auth]`` table the plugin would refuse at startup.

    Unknown keys and a malformed or missing OAuth resource allowlist are errors
    (see :mod:`enlace_auth.resource_policy`), so this is the one check that says
    why; every other check skips a config that does not load.
    """
    if err := _auth_config_error(config):
        return [Check("auth_config", FAIL, f"[auth] does not load: {err}")]
    return [Check("auth_config", PASS, "[auth] loads")]


def _skip_if_auth_config_invalid(check):
    """Make *check* return nothing for a config ``check_auth_config`` reports."""

    @functools.wraps(check)
    def guarded(config, *args, **kwargs):
        if _auth_config_error(config):
            return []
        return check(config, *args, **kwargs)

    return guarded


def check_signing_key(config: PlatformConfig) -> Iterable[Check]:
    auth = coerce_auth_config(getattr(config, "auth", None))
    if not auth.enabled:
        return [Check("signing_key", SKIP, "auth.enabled=false")]
    raw = os.environ.get(auth.signing_key_env) or ""
    stripped = raw.strip()
    if not stripped:
        return [
            Check(
                "signing_key",
                FAIL,
                f"env var {auth.signing_key_env} is unset or empty",
            )
        ]
    if len(stripped) < 32:
        return [
            Check(
                "signing_key",
                FAIL,
                f"env var {auth.signing_key_env} too short ({len(stripped)} chars)",
            )
        ]
    return [
        Check(
            "signing_key",
            PASS,
            f"{auth.signing_key_env} set ({len(stripped)} chars)",
        )
    ]


def check_shared_passwords(config: PlatformConfig) -> Iterable[Check]:
    auth = coerce_auth_config(getattr(config, "auth", None))
    if not auth.enabled:
        return []
    out: list[Check] = []
    for app in config.apps:
        if app.access != "protected:shared":
            continue
        if not app.shared_password_env:
            out.append(
                Check(
                    f"shared_pw:{app.name}",
                    FAIL,
                    "access=protected:shared but no shared_password_env set",
                )
            )
            continue
        if not os.environ.get(app.shared_password_env):
            out.append(
                Check(
                    f"shared_pw:{app.name}",
                    FAIL,
                    f"env var {app.shared_password_env} is unset",
                )
            )
        else:
            out.append(
                Check(
                    f"shared_pw:{app.name}",
                    PASS,
                    f"{app.shared_password_env} set",
                )
            )
    return out


def check_oauth_importable(config: PlatformConfig) -> Iterable[Check]:
    auth = coerce_auth_config(getattr(config, "auth", None))
    if not auth.enabled or not auth.oauth:
        return []
    providers = ", ".join(sorted(auth.oauth))
    try:
        import authlib  # noqa: F401
    except ImportError:
        return [
            Check(
                "oauth_import",
                FAIL,
                f"oauth providers ({providers}) configured but authlib not "
                "installed. Install with `pip install enlace_auth[oauth]`.",
            )
        ]
    return [Check("oauth_import", PASS, f"authlib importable; providers: {providers}")]


def check_admin_accounts(config: PlatformConfig) -> Iterable[Check]:
    """Every configured admin address should already have an account.

    Self-registration cannot prove who owns an address, so an admin address
    with no account is one anyone could claim the moment registration admits it
    (open registration, or an allowlist that lists it), and that account would
    pass every ``@admins`` gate (i2mint/enlace_auth#35).
    """
    from enlace_auth.emails import normalize_email
    from enlace_auth.plugin import read_email_list
    from enlace_auth.stores import make_file_store_factory

    name = "admin_accounts"
    auth = coerce_auth_config(getattr(config, "auth", None))
    if not auth.enabled:
        return [Check(name, SKIP, "auth.enabled=false")]
    admins = read_email_list(auth.admin_emails_env)
    if not admins:
        return [Check(name, SKIP, f"{auth.admin_emails_env} lists no admins")]
    users = make_file_store_factory(auth.stores.path)("users")
    missing = [email for email in admins if email not in users]

    # Registration refuses admin addresses (#38), so an admin account recorded
    # as self-registered predates that fix and may belong to whoever got there
    # first. So may one an OAuth sign-in created while the address was not yet an
    # admin's, unless the provider itself vouched for the address. Accounts with
    # no ``created_via`` predate provenance: listed as unknown, not warned about,
    # since nothing short of recreating them would ever clear the warning.
    def _provenance(email) -> tuple[str, Optional[bool]]:
        """(how the account was made, whether that proves who owns the address).

        ``None`` means not recorded either way.
        """
        record = users[email]
        record = record if isinstance(record, dict) else {}
        via = record.get("created_via")
        if via is None:
            return "unknown (accounts this old predate created_via)", None
        if via == "register":
            return "self-registration", False
        if str(via).startswith("oauth:"):
            vouched = record.get("email_verified_by_provider")
            if vouched is True:
                return f"{via}, address verified by the provider", True
            if vouched is False:
                return f"{via}, address NOT verified by the provider", False
            return f"{via}, provider verification not recorded", False
        return str(via), True  # add-user: the operator made it

    def _spelling_hint(entry) -> str:
        """Why an admin entry may never match: written in a form no key takes."""
        try:
            key = normalize_email(entry)
        except ValueError:
            return (
                f" {entry!r} is not an address add-user or registration accepts, "
                "so only an OAuth sign-in could make its account."
            )
        if key != entry and key in users:
            return (
                f" {entry!r} has an account keyed {key!r} (add-user stores the "
                f"normalized form): write the admin entry as {key!r}."
            )
        return ""

    present = [e for e in admins if e not in missing]
    provenance = {e: _provenance(e) for e in present}
    doubtful = [e for e, (_, proven) in provenance.items() if proven is False]
    summary = "; ".join(f"{e}: {how}" for e, (how, _) in provenance.items())
    checks = []
    if doubtful:
        checks.append(
            Check(
                name,
                WARN,
                f"admin account(s) whose owner is not established: "
                f"{', '.join(doubtful)}. Confirm each is really the admin's "
                "(compare created_at with when the address became an admin), or "
                "delete it and recreate with `enlace-auth add-user`. "
                f"Provenance: {summary}",
            )
        )
    if missing:
        checks.append(
            Check(
                name,
                WARN,
                f"admin address(es) with no account: {', '.join(missing)}; the "
                "admin cannot sign in yet (registration refuses admin "
                "addresses). Create each with `enlace-auth add-user <email>`, "
                "or sign in once through an OAuth provider that verifies it."
                + "".join(_spelling_hint(e) for e in missing),
            )
        )
    if not checks:
        checks.append(
            Check(
                name,
                PASS,
                f"all {len(admins)} admin(s) have accounts. Provenance: {summary}",
            )
        )
    return checks


def check_csrf(
    config: PlatformConfig, base_url: str, timeout: float
) -> Iterable[Check]:
    """GET /auth/csrf must return JSON with a 'csrf' key.

    This is THE check that catches the i2mint/enlace#11 regression: when auth
    is silently disabled, the SPA catch-all returns ``<!doctype html>``
    instead of JSON.
    """
    auth = coerce_auth_config(getattr(config, "auth", None))
    if not auth.enabled:
        return [Check("http:/auth/csrf", SKIP, "auth.enabled=false")]
    url = f"{base_url.rstrip('/')}/auth/csrf"
    # Late-bind so monkeypatch on enlace.doctor._http_get is honored.
    status, headers, body, err = _doctor._http_get(url, timeout=timeout)
    if err:
        return [Check("http:/auth/csrf", FAIL, err)]
    ct = headers.get("content-type", "")
    if status != 200:
        snippet = (body or b"").decode("utf-8", errors="replace")[:120]
        return [
            Check(
                "http:/auth/csrf",
                FAIL,
                f"status={status} content-type={ct!r} body[:120]={snippet!r}",
                extra={"status": status, "content_type": ct},
            )
        ]
    if "application/json" not in ct.lower():
        snippet = (body or b"").decode("utf-8", errors="replace")[:120]
        return [
            Check(
                "http:/auth/csrf",
                FAIL,
                f"expected JSON, got content-type={ct!r}; "
                f"body[:120]={snippet!r} (auth silently disabled?)",
                extra={"status": status, "content_type": ct},
            )
        ]
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:
        return [Check("http:/auth/csrf", FAIL, f"body is not valid JSON: {e}")]
    if not isinstance(data, dict) or "csrf" not in data:
        keys = list(data) if isinstance(data, dict) else type(data).__name__
        return [
            Check(
                "http:/auth/csrf",
                FAIL,
                f"JSON response missing 'csrf' key: keys={keys}",
            )
        ]
    return [
        Check(
            "http:/auth/csrf",
            PASS,
            f"JSON with csrf token ({len(data['csrf'])} chars)",
        )
    ]


def check_connector_session_longevity(config: PlatformConfig) -> Iterable[Check]:
    """Can a connector survive its own access-token expiry unattended?

    THE check for the failure this exists to prevent: an authorization server
    that issues short access tokens and no refresh token strands every MCP
    connector the moment the first token expires. Nothing errors — the connector
    process stays healthy and the endpoint keeps answering — it just returns 401
    forever until a human re-runs the browser authorization. In production that
    read as "the connector has been down all day" and took a user complaint to
    surface, because expiry is logged at INFO on the connector, not here.
    """
    auth = coerce_auth_config(getattr(config, "auth", None))
    osc = getattr(auth, "oauth_server", None)
    if not auth.enabled or not getattr(osc, "enabled", False):
        return [Check("oauth_refresh", SKIP, "oauth_server not enabled")]

    access_ttl = getattr(osc, "access_token_ttl_seconds", 3600)
    refresh_ttl = getattr(osc, "refresh_token_ttl_seconds", 0)
    if refresh_ttl > 0:
        return [
            Check(
                "oauth_refresh",
                PASS,
                f"refresh grant enabled (access {access_ttl}s, "
                f"refresh {refresh_ttl}s) — connectors renew unattended",
            )
        ]
    hours = access_ttl / 3600.0
    return [
        Check(
            "oauth_refresh",
            FAIL,
            f"refresh_token_ttl_seconds=0 disables the refresh grant, so every "
            f"connector session dies {access_ttl}s (~{hours:.1f}h) after "
            f"authorization and only a human at a browser can restore it. "
            f"Set [auth.oauth_server] refresh_token_ttl_seconds > 0.",
        )
    ]


def check_oauth_server_advertises_refresh(
    config: PlatformConfig, base_url: str, timeout: float
) -> Iterable[Check]:
    """The live server must offer refresh_token in its discovery metadata.

    Static config can be right while the deployed build is an older release that
    has no refresh support at all — exactly the drift that caused the outage
    (config and code were fine locally; the installed wheel was what served
    requests). This asks the running server what it actually advertises.
    """
    auth = coerce_auth_config(getattr(config, "auth", None))
    osc = getattr(auth, "oauth_server", None)
    name = "http:/.well-known/oauth-authorization-server"
    if not auth.enabled or not getattr(osc, "enabled", False):
        return [Check(name, SKIP, "oauth_server not enabled")]
    url = f"{base_url.rstrip('/')}/.well-known/oauth-authorization-server"
    status, _headers, body, err = _doctor._http_get(url, timeout=timeout)
    if err:
        return [Check(name, FAIL, err)]
    if status != 200:
        return [Check(name, FAIL, f"expected 200, got {status}")]
    try:
        grants = json.loads(body or b"{}").get("grant_types_supported", [])
    except ValueError:
        return [Check(name, FAIL, "metadata is not valid JSON")]
    if "refresh_token" in grants:
        return [Check(name, PASS, f"grant_types_supported={grants}")]
    return [
        Check(
            name,
            FAIL,
            f"the RUNNING server advertises {grants} — no refresh_token grant, so "
            "connector sessions cannot renew and will strand on expiry. If config "
            "sets refresh_token_ttl_seconds > 0, the deployed enlace_auth build is "
            "older than the config: upgrade it and restart the backend.",
        )
    ]


# Convenience tuples for `extra_static_checks=` / `extra_http_checks=`.
static_checks = (
    check_auth_config,
    *map(
        _skip_if_auth_config_invalid,
        (
            check_signing_key,
            check_shared_passwords,
            check_oauth_importable,
            check_connector_session_longevity,
            check_admin_accounts,
        ),
    ),
)
http_checks = tuple(
    map(
        _skip_if_auth_config_invalid,
        (check_csrf, check_oauth_server_advertises_refresh),
    )
)
