"""Runtime per-app access grants, with optional UTC expiry.

A *grant* gives a specific user (by email) access to a specific ``protected:user``
app at runtime, **without a redeploy**. Grants are ADDITIVE on top of the static
``allowed_users`` declared in an app's ``app.toml``: the effective allow-set for
an app is ``config allowed_users ∪ {active grants}``. A grant is *active* when its
``expires_at`` is ``None`` (never expires) or lies in the future (UTC).

Storage mirrors :class:`enlace_auth.auth.sessions.SessionStore`: a thin adapter
over a ``MutableMapping`` whose keys are ``"{app_id}/{email}"`` and whose values
are JSON grant records::

    {
        "app_id": str,
        "email": str,              # normalized to lowercase
        "expires_at": float | None,  # epoch seconds, UTC; None = never
        "granted_at": float,       # epoch seconds, UTC
        "granted_by": str | None,  # admin email who created it
        "note": str | None,
    }

The composite key groups grants per app on disk (``grants/{app_id}/{email}``), so
the hot path — :meth:`GrantStore.active_emails_for_app`, consulted by the auth
middleware on every ``protected:user`` request — lists a single app's
subdirectory rather than scanning every grant for every app.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator, MutableMapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Conservative email shape check. We only need to reject path-hostile input
# (slashes, traversal, whitespace, control chars) before it becomes a store key;
# the admin API uses pydantic ``EmailStr`` for real RFC validation upstream.
_EMAIL_RE = re.compile(r"^[^\s/\\@]+@[^\s/\\@]+\.[^\s/\\@]+$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class GrantError(ValueError):
    """Raised when a grant argument is invalid (bad email/app_id, past expiry)."""


def _normalize_email(email: str) -> str:
    e = (email or "").strip().lower()
    if ".." in e or not _EMAIL_RE.match(e):
        raise GrantError(f"Invalid email for grant: {email!r}")
    return e


def _validate_app_id(app_id: str) -> str:
    a = (app_id or "").strip()
    if not a or "/" in a or "\\" in a or ".." in a:
        raise GrantError(f"Invalid app_id for grant: {app_id!r}")
    return a


def parse_expires_at(value, *, now: Optional[float] = None) -> Optional[float]:
    """Coerce a user-supplied expiry into epoch seconds (UTC), or ``None``.

    Accepts:

    - ``None`` / empty string → ``None`` (never expires).
    - a number → treated as epoch seconds, returned as a float.
    - ``"YYYY-MM-DD"`` → **end of that day UTC** (``23:59:59``), so the grant is
      valid through the whole named day (least-surprising "expires on this date").
    - a full ISO-8601 timestamp (``...THH:MM[:SS][±TZ|Z]``) → that instant. A
      trailing ``Z`` is honored (Python 3.10's ``fromisoformat`` can't) and a
      naive timestamp is assumed to be UTC.

    Raises :class:`GrantError` for unparseable input or an already-past expiry.
    """
    if value is None:
        return None
    if isinstance(value, bool):  # guard: bool is an int subclass
        raise GrantError(f"Invalid expiry value: {value!r}")
    if isinstance(value, (int, float)):
        ts = float(value)
    else:
        s = str(value).strip()
        if not s:
            return None
        ts = _parse_datetime_string(s)
    now = time.time() if now is None else now
    if ts <= now:
        raise GrantError("Expiry is in the past; choose a future date.")
    return ts


def _parse_datetime_string(s: str) -> float:
    if _DATE_RE.match(s):
        # Bare date → end-of-day UTC.
        try:
            d = datetime.strptime(s, "%Y-%m-%d")
        except ValueError as e:
            raise GrantError(f"Unparseable expiry date: {s!r}") from e
        d = d.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
        return d.timestamp()
    # Full ISO 8601. Normalize a trailing Z for 3.10 compatibility.
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError as e:
        raise GrantError(f"Unparseable expiry timestamp: {s!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _is_active(record: dict, now: float) -> bool:
    exp = record.get("expires_at")
    return exp is None or (isinstance(exp, (int, float)) and exp > now)


class GrantStore:
    """Thin adapter over a ``MutableMapping`` that speaks grant semantics.

    Args:
        backend: the per-name store (e.g. ``factory("grants")``).
        root: the resolved filesystem directory backing ``backend``
            (``.../grants``). Used ONLY for efficient per-app listing
            (``root/{app_id}/*``). All reads/writes go through ``backend`` so the
            storage codec stays in one place. When ``None`` (e.g. a dict backend
            in tests), listing falls back to filtering the backend's keys.
    """

    def __init__(self, backend: MutableMapping, *, root: Optional[Path] = None):
        self._store = backend
        self._root = Path(root) if root is not None else None

    @staticmethod
    def _key(app_id: str, email: str) -> str:
        return f"{app_id}/{email}"

    def grant(
        self,
        app_id: str,
        email: str,
        *,
        expires_at: Optional[float] = None,
        granted_by: Optional[str] = None,
        note: Optional[str] = None,
        now: Optional[float] = None,
    ) -> dict:
        """Create or replace a grant. ``expires_at`` is epoch seconds UTC or None.

        Use :func:`parse_expires_at` to turn a date/ISO string into ``expires_at``
        before calling this.
        """
        app_id = _validate_app_id(app_id)
        email = _normalize_email(email)
        record = {
            "app_id": app_id,
            "email": email,
            "expires_at": expires_at,
            "granted_at": time.time() if now is None else now,
            "granted_by": granted_by or None,
            "note": note or None,
        }
        self._store[self._key(app_id, email)] = record
        return record

    def get(self, app_id: str, email: str) -> Optional[dict]:
        try:
            value = self._store[
                self._key(_validate_app_id(app_id), _normalize_email(email))
            ]
        except (KeyError, GrantError):
            return None
        return value if isinstance(value, dict) else None

    def revoke(self, app_id: str, email: str) -> bool:
        try:
            del self._store[
                self._key(_validate_app_id(app_id), _normalize_email(email))
            ]
            return True
        except (KeyError, GrantError):
            return False

    def list_for_app(self, app_id: str) -> list[dict]:
        app_id = _validate_app_id(app_id)
        out: list[dict] = []
        for email in self._emails_on_disk(app_id):
            try:
                rec = self._store[self._key(app_id, email)]
            except KeyError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
        return out

    def list_all(self) -> list[dict]:
        """All grant records across all apps. Admin-only / infrequent."""
        out: list[dict] = []
        for key in list(self._store):
            try:
                rec = self._store[key]
            except KeyError:
                continue
            if isinstance(rec, dict) and "email" in rec:
                out.append(rec)
        return out

    def active_emails_for_app(
        self, app_id: str, *, now: Optional[float] = None
    ) -> set[str]:
        """The set of currently-active granted emails for ``app_id`` (hot path)."""
        now = time.time() if now is None else now
        return {
            rec["email"]
            for rec in self.list_for_app(app_id)
            if _is_active(rec, now) and rec.get("email")
        }

    def _emails_on_disk(self, app_id: str) -> Iterator[str]:
        """Yield the email leaf-names of grants for ``app_id``.

        Prefers a targeted directory scan (``root/{app_id}/*``); falls back to
        filtering the backend's full key listing when no ``root`` is set.
        """
        if self._root is not None:
            app_dir = self._root / app_id
            if not app_dir.is_dir():
                return
            for child in app_dir.iterdir():
                if child.is_file() and not child.name.endswith(".tmp"):
                    yield child.name
            return
        prefix = f"{app_id}/"
        for key in list(self._store):
            if key.startswith(prefix):
                yield key[len(prefix) :]
