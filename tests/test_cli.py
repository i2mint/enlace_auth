"""Tests for the enlace-auth CLI's user-store commands.

The CLI's session/sign-key helpers are exercised indirectly elsewhere; here
we focus on ``set_password`` and ``list_users`` because they mutate / read
the user store and are the easiest way to lock yourself out if they regress.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from enlace_auth.__main__ import (
    _load_grant_store,
    _load_user_store,
    grant,
    list_grants,
    list_users,
    revoke_grant,
    set_password,
)
from enlace_auth.auth.passwords import hash_password, verify_password


def _make_platform_toml(tmp_path: Path) -> Path:
    """Write a minimal platform.toml + apps dir that PlatformConfig will accept."""
    apps_dir = tmp_path / "apps"
    apps_dir.mkdir()
    ping = apps_dir / "ping"
    ping.mkdir()
    (ping / "server.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    toml = tmp_path / "platform.toml"
    toml.write_text(textwrap.dedent(f"""
            [platform]
            apps_dir = "{apps_dir}"

            [auth]
            enabled = true
            signing_key_env = "ENLACE_SIGNING_KEY"

            [auth.stores]
            backend = "file"
            path = "{tmp_path / "platform_store"}"
            """).strip())
    return toml


def test_set_password_updates_hash(tmp_path, monkeypatch, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_user_store(toml)
    store["thor@example.com"] = {
        "password_hash": hash_password("old-secret"),
        "created_at": 0,
    }

    inputs = iter(["fresh-secret", "fresh-secret"])
    monkeypatch.setattr("enlace_auth.__main__.getpass", lambda _: next(inputs))

    set_password("thor@example.com", toml=str(toml))
    out = capsys.readouterr().out
    assert "Password updated" in out

    record = _load_user_store(toml)["thor@example.com"]
    assert verify_password(record["password_hash"], "fresh-secret")
    assert not verify_password(record["password_hash"], "old-secret")


def test_set_password_rejects_mismatched_confirm(tmp_path, monkeypatch):
    toml = _make_platform_toml(tmp_path)
    store = _load_user_store(toml)
    store["thor@example.com"] = {
        "password_hash": hash_password("old-secret"),
        "created_at": 0,
    }

    inputs = iter(["new-one", "different"])
    monkeypatch.setattr("enlace_auth.__main__.getpass", lambda _: next(inputs))

    with pytest.raises(SystemExit) as exc:
        set_password("thor@example.com", toml=str(toml))
    assert exc.value.code == 1
    # Hash must still verify the old password — nothing was written.
    record = _load_user_store(toml)["thor@example.com"]
    assert verify_password(record["password_hash"], "old-secret")


def test_set_password_unknown_user_exits_with_error(tmp_path, monkeypatch):
    toml = _make_platform_toml(tmp_path)
    monkeypatch.setattr("enlace_auth.__main__.getpass", lambda _: "any")
    with pytest.raises(SystemExit) as exc:
        set_password("ghost@example.com", toml=str(toml))
    assert exc.value.code == 1


def test_list_users_json_output(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_user_store(toml)
    store["a@example.com"] = {"password_hash": "x", "created_at": 1700000000}
    store["b@example.com"] = {"password_hash": "y", "created_at": 1700000100}

    list_users(json=True, toml=str(toml))
    payload = json.loads(capsys.readouterr().out)
    emails = {r["email"] for r in payload}
    assert emails == {"a@example.com", "b@example.com"}
    assert all(r["has_password"] for r in payload)


# --------------------------------------------------------------------------
# grant / revoke-grant / list-grants
# --------------------------------------------------------------------------


def test_grant_and_list_and_revoke(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)

    grant("vault", "carl@example.com", toml=str(toml))
    assert "Granted carl@example.com" in capsys.readouterr().out

    # Persisted to the grants store and active.
    assert _load_grant_store(toml).active_emails_for_app("vault") == {
        "carl@example.com"
    }

    list_grants(json=True, toml=str(toml))
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["app_id"] == "vault"
    assert payload[0]["email"] == "carl@example.com"
    assert payload[0]["expires_at"] is None
    assert payload[0]["granted_by"] == "cli"

    revoke_grant("vault", "carl@example.com", toml=str(toml))
    assert "Revoked carl@example.com" in capsys.readouterr().out
    assert _load_grant_store(toml).active_emails_for_app("vault") == set()


def test_grant_with_date_expiry(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    grant("vault", "dora@example.com", expires="2099-12-31", toml=str(toml))
    capsys.readouterr()
    rec = _load_grant_store(toml).get("vault", "dora@example.com")
    assert rec["expires_at"] is not None  # end-of-day UTC epoch


def test_grant_past_expiry_exits_error(tmp_path):
    toml = _make_platform_toml(tmp_path)
    with pytest.raises(SystemExit) as exc:
        grant("vault", "e@example.com", expires="2000-01-01", toml=str(toml))
    assert exc.value.code == 1


def test_revoke_unknown_grant_exits_error(tmp_path):
    toml = _make_platform_toml(tmp_path)
    with pytest.raises(SystemExit) as exc:
        revoke_grant("vault", "ghost@example.com", toml=str(toml))
    assert exc.value.code == 1


# ---------------------------------------------------------------------- #
# Connector sessions
#
# "Does this connector have a live session, and whose?" — the question that
# went unanswered for a day, because a healthy process answers it wrongly.
# ---------------------------------------------------------------------- #

from enlace_auth.__main__ import (  # noqa: E402
    _load_refresh_store,
    list_connector_sessions,
    revoke_connector_session,
)

RESOURCE = "https://apps.example.com/api/demo_mcp/mcp"


def _seed_family(store, *, family, email, consumed=False, resource=RESOURCE):
    store[f"hash-{family}-{'spent' if consumed else 'live'}"] = {
        "family": family,
        "client_id": "client-1",
        "resource": resource,
        "scope": "mcp:read",
        "email": email,
        "iat": 1,
        "exp": 9999999999,
        "family_exp": 9999999999,
        "consumed_at": 123 if consumed else None,
        "successor": None,
    }


def test_list_connector_sessions_shows_live_families(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_refresh_store(toml)
    _seed_family(store, family="f1", email="alice@example.com")
    _seed_family(store, family="f2", email="bob@example.com", consumed=True)

    list_connector_sessions(toml=str(toml))
    out = capsys.readouterr().out
    assert "alice@example.com" in out
    assert "bob@example.com" not in out, "a spent token is a tombstone, not a session"


def test_list_connector_sessions_reports_emptiness_plainly(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    _load_refresh_store(toml)
    list_connector_sessions(toml=str(toml))
    assert "No live connector sessions" in capsys.readouterr().out


def test_revoke_by_family(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_refresh_store(toml)
    _seed_family(store, family="f1", email="alice@example.com")
    _seed_family(store, family="f2", email="bob@example.com")

    revoke_connector_session("f1", toml=str(toml))
    assert "Revoked 1" in capsys.readouterr().out
    remaining = {store[k]["family"] for k in store}
    assert remaining == {"f2"}


def test_revoke_by_email_is_case_insensitive(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_refresh_store(toml)
    _seed_family(store, family="f1", email="Alice@Example.com")
    _seed_family(store, family="f2", email="bob@example.com", consumed=True)
    _seed_family(store, family="f3", email="alice@example.com", resource="other")

    revoke_connector_session(email="ALICE@example.com", toml=str(toml))
    assert "Revoked 2" in capsys.readouterr().out
    assert {store[k]["family"] for k in store} == {"f2"}


def test_revoke_requires_a_target(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_refresh_store(toml)
    _seed_family(store, family="f1", email="alice@example.com")
    revoke_connector_session(toml=str(toml))
    assert "Give a family id" in capsys.readouterr().out
    assert len(list(store)) == 1, "a targetless revoke must not delete anything"


def test_list_connector_sessions_json(tmp_path, capsys):
    toml = _make_platform_toml(tmp_path)
    store = _load_refresh_store(toml)
    _seed_family(store, family="f1", email="alice@example.com")
    list_connector_sessions(json=True, toml=str(toml))
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["email"] == "alice@example.com"
    assert rows[0]["resource"] == RESOURCE
