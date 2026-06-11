"""GrantStore semantics + expiry parsing.

Exercises the runtime per-app grants store over both a dict backend (no root)
and a file backend (with a root for per-app directory scans), plus the
``parse_expires_at`` date/ISO coercion rules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from enlace_auth.auth.grants import (
    GrantError,
    GrantStore,
    _is_active,
    parse_expires_at,
)
from enlace_auth.stores.backends import make_file_store_factory

DAY = 86400


def _file_store(tmp_path) -> GrantStore:
    factory = make_file_store_factory(str(tmp_path))
    return GrantStore(factory("grants"), root=Path(tmp_path) / "grants")


# --------------------------------------------------------------------------
# grant / get / revoke
# --------------------------------------------------------------------------


def test_grant_get_revoke_roundtrip_dict():
    store = GrantStore({})
    rec = store.grant("vault", "Alice@Example.com", granted_by="boss@x")
    assert rec["app_id"] == "vault"
    assert rec["email"] == "alice@example.com"  # normalized lowercase
    assert rec["expires_at"] is None
    assert store.get("vault", "alice@example.com") is not None
    # Lookup is case-insensitive on the email.
    assert store.get("vault", "ALICE@example.com") is not None
    assert store.revoke("vault", "alice@example.com") is True
    assert store.get("vault", "alice@example.com") is None
    assert store.revoke("vault", "alice@example.com") is False


def test_grant_upsert_replaces():
    store = GrantStore({})
    store.grant("vault", "a@x.com", note="first")
    store.grant("vault", "a@x.com", note="second")
    assert len(store.list_for_app("vault")) == 1
    assert store.get("vault", "a@x.com")["note"] == "second"


def test_invalid_email_rejected():
    store = GrantStore({})
    with pytest.raises(GrantError):
        store.grant("vault", "not-an-email")
    with pytest.raises(GrantError):
        store.grant("vault", "a/b@x.com")  # path-hostile
    with pytest.raises(GrantError):
        store.grant("vault", "a..b@x.com")  # traversal-ish


def test_invalid_app_id_rejected():
    store = GrantStore({})
    with pytest.raises(GrantError):
        store.grant("a/b", "a@x.com")
    with pytest.raises(GrantError):
        store.grant("..", "a@x.com")


# --------------------------------------------------------------------------
# active filtering / expiry
# --------------------------------------------------------------------------


def test_active_emails_filters_expired():
    store = GrantStore({})
    now = 1_000_000.0
    store.grant("vault", "never@x.com", expires_at=None, now=now)
    store.grant("vault", "future@x.com", expires_at=now + DAY, now=now)
    store.grant("vault", "past@x.com", expires_at=now - DAY, now=now)
    active = store.active_emails_for_app("vault", now=now)
    assert active == {"never@x.com", "future@x.com"}


def test_is_active_helper():
    now = 100.0
    assert _is_active({"expires_at": None}, now) is True
    assert _is_active({"expires_at": now + 1}, now) is True
    assert _is_active({"expires_at": now - 1}, now) is False
    assert _is_active({"expires_at": now}, now) is False  # boundary: not after now


def test_per_app_isolation():
    store = GrantStore({})
    store.grant("vault", "a@x.com")
    store.grant("library", "b@x.com")
    assert store.active_emails_for_app("vault") == {"a@x.com"}
    assert store.active_emails_for_app("library") == {"b@x.com"}
    assert {g["email"] for g in store.list_all()} == {"a@x.com", "b@x.com"}


# --------------------------------------------------------------------------
# file backend: per-app dir scan + persistence
# --------------------------------------------------------------------------


def test_file_backend_per_app_scan_and_persist(tmp_path):
    store = _file_store(tmp_path)
    store.grant("vault", "a@x.com", expires_at=None)
    store.grant("vault", "b@x.com", expires_at=None)
    store.grant("library", "c@x.com", expires_at=None)

    # Per-app listing reads only that app's subdir.
    assert {g["email"] for g in store.list_for_app("vault")} == {"a@x.com", "b@x.com"}
    assert store.active_emails_for_app("library") == {"c@x.com"}

    # Rebuild over the same path — grants persist (the whole point: survive restarts).
    store2 = _file_store(tmp_path)
    assert store2.active_emails_for_app("vault") == {"a@x.com", "b@x.com"}
    assert store2.revoke("vault", "a@x.com") is True
    assert store2.active_emails_for_app("vault") == {"b@x.com"}


def test_file_backend_unknown_app_is_empty(tmp_path):
    store = _file_store(tmp_path)
    assert store.list_for_app("nope") == []
    assert store.active_emails_for_app("nope") == set()


# --------------------------------------------------------------------------
# parse_expires_at
# --------------------------------------------------------------------------


def test_parse_expires_none_and_empty():
    assert parse_expires_at(None) is None
    assert parse_expires_at("") is None
    assert parse_expires_at("   ") is None


def test_parse_expires_bare_date_is_end_of_day_utc():
    now = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    ts = parse_expires_at("2026-06-15", now=now)
    expected = datetime(2026, 6, 15, 23, 59, 59, tzinfo=timezone.utc).timestamp()
    assert ts == expected


def test_parse_expires_iso_with_z():
    now = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    ts = parse_expires_at("2026-06-15T12:00:00Z", now=now)
    assert ts == datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def test_parse_expires_naive_iso_assumed_utc():
    now = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    ts = parse_expires_at("2026-06-15T12:00:00", now=now)
    assert ts == datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def test_parse_expires_epoch_passthrough():
    now = 1000.0
    assert parse_expires_at(5000, now=now) == 5000.0
    assert parse_expires_at(5000.5, now=now) == 5000.5


def test_parse_expires_past_rejected():
    now = datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp()
    with pytest.raises(GrantError):
        parse_expires_at("2020-01-01", now=now)


def test_parse_expires_unparseable_rejected():
    with pytest.raises(GrantError):
        parse_expires_at("not-a-date")
    with pytest.raises(GrantError):
        parse_expires_at(True)  # bool guarded out
