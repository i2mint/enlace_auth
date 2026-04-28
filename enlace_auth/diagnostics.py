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

import json
import os
from typing import Iterable

from enlace import doctor as _doctor
from enlace.base import PlatformConfig
from enlace.doctor import FAIL, PASS, SKIP, Check

from enlace_auth.config import coerce_auth_config


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
    return [
        Check("oauth_import", PASS, f"authlib importable; providers: {providers}")
    ]


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


# Convenience tuples for `extra_static_checks=` / `extra_http_checks=`.
static_checks = (
    check_signing_key,
    check_shared_passwords,
    check_oauth_importable,
)
http_checks = (check_csrf,)
