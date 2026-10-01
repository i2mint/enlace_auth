"""Owner-granted data shares: let named users at one user's per-user data in one app.

Grants (:mod:`enlace_auth.auth.grants`) answer *may this user open this app?* A
**share** answers a different question: *may this user act on that user's data in
this app?* A share is ``(app_id, owner, grantee)`` plus an access level, and the
per-user store (:mod:`enlace_auth.stores.middleware`) honours it when a request
names an owner with ``?owner=``. The design, and why it is shaped this way, is
``misc/docs/decisions/0001-owner-granted-data-shares.md``.

Storage mirrors :class:`~enlace_auth.auth.grants.GrantStore`: a thin adapter over a
``MutableMapping`` whose keys are ``"{app_id}/{owner}/{grantee}"`` and whose values
are JSON records::

    {
        "app_id": str,
        "owner": str,              # normalized email
        "grantee": str,            # normalized email
        "access": "rw" | "ro",     # "ro" = read-only (GET)
        "label": str | None,       # how the grantee sees this space
        "granted_at": float,       # epoch seconds, UTC
        "granted_by": str | None,  # who created it (the owner, or an admin)
        "expires_at": float | None,  # epoch seconds, UTC; None = never
    }

Two rules the store enforces, so no caller can forget them:

- **A share names existing accounts only** (when ``account_exists`` is given). A
  share to an address nobody holds would be claimed by whoever registers it next.
- **A share dies with either account**: :meth:`ShareStore.remove_account` deletes
  every share an email is part of, and account deletion calls it.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Callable, Optional

from enlace_auth.auth.grants import (
    GrantError,
    _is_active,
    _normalize_email,
    _validate_app_id,
)

#: The access levels a share may carry: read-write, or read-only (GET).
ACCESS_LEVELS = ("rw", "ro")


#: The longest ``label`` a share may carry (the grantee sees it as the space's name).
MAX_LABEL = 80


class ShareError(ValueError):
    """An invalid share. ``code`` says which: ``"no_account"`` or ``"invalid"``."""

    def __init__(self, message: str, *, code: str = "invalid"):
        super().__init__(message)
        self.code = code


def _email(value: str) -> str:
    try:
        return _normalize_email(value)
    except GrantError as e:
        raise ShareError(str(e).replace("grant", "share")) from None


def _app(value: str) -> str:
    try:
        return _validate_app_id(value)
    except GrantError as e:
        raise ShareError(str(e).replace("grant", "share")) from None


class ShareStore:
    """Share semantics over a ``MutableMapping``.

    Args:
        backend: the per-name store (e.g. ``factory("shares")``).
        root: the filesystem directory backing ``backend``, used only to list one
            app's shares without scanning every key (as ``GrantStore`` does).
            ``None`` (a dict backend in tests) falls back to filtering all keys.
        account_exists: ``email -> bool``. When given, :meth:`share` refuses an
            owner or grantee with no account. ``None`` skips the check (tests).
    """

    def __init__(
        self,
        backend: MutableMapping,
        *,
        root: Optional[Path] = None,
        account_exists: Optional[Callable[[str], bool]] = None,
    ):
        self._store = backend
        self._root = Path(root) if root is not None else None
        self._account_exists = account_exists

    @staticmethod
    def _key(app_id: str, owner: str, grantee: str) -> str:
        return f"{app_id}/{owner}/{grantee}"

    def share(
        self,
        app_id: str,
        owner: str,
        grantee: str,
        *,
        access: str = "rw",
        label: Optional[str] = None,
        expires_at: Optional[float] = None,
        granted_by: Optional[str] = None,
        now: Optional[float] = None,
    ) -> dict:
        """Create or replace the share ``owner`` → ``grantee`` in ``app_id``.

        ``expires_at`` is epoch seconds UTC or ``None``; turn a date string into it
        with :func:`enlace_auth.auth.grants.parse_expires_at` first.
        """
        app_id, owner, grantee = _app(app_id), _email(owner), _email(grantee)
        if owner == grantee:
            raise ShareError("An owner cannot share with themselves.")
        if access not in ACCESS_LEVELS:
            raise ShareError(f"access must be one of {ACCESS_LEVELS}, not {access!r}")
        if self._account_exists is not None:
            missing = [e for e in (owner, grantee) if not self._account_exists(e)]
            if missing:
                raise ShareError(
                    f"No account for {', '.join(missing)}; "
                    "a share names existing accounts only.",
                    code="no_account",
                )
        label = (label or "").strip() or None
        if label is not None and len(label) > MAX_LABEL:
            raise ShareError(f"label is longer than {MAX_LABEL} characters")
        record = {
            "app_id": app_id,
            "owner": owner,
            "grantee": grantee,
            "access": access,
            "label": label,
            "granted_at": time.time() if now is None else now,
            "granted_by": granted_by or None,
            "expires_at": expires_at,
        }
        self._store[self._key(app_id, owner, grantee)] = record
        return record

    def get(self, app_id: str, owner: str, grantee: str) -> Optional[dict]:
        try:
            value = self._store[self._key(_app(app_id), _email(owner), _email(grantee))]
        except (KeyError, ShareError):
            return None
        return value if isinstance(value, dict) else None

    def revoke(self, app_id: str, owner: str, grantee: str) -> bool:
        try:
            del self._store[self._key(_app(app_id), _email(owner), _email(grantee))]
            return True
        except (KeyError, ShareError):
            return False

    def access(
        self, app_id: str, owner: str, grantee: str, *, now: Optional[float] = None
    ) -> Optional[str]:
        """``"rw"``, ``"ro"`` or ``None``: what ``grantee`` may do with the data."""
        record = self.get(app_id, owner, grantee)
        now = time.time() if now is None else now
        if record is None or not _is_active(record, now):
            return None
        return record.get("access") if record.get("access") in ACCESS_LEVELS else None

    def granted(
        self, app_id: str, owner: str, *, now: Optional[float] = None
    ) -> list[dict]:
        """Every share ``owner`` made in ``app_id``, each with ``"active"``."""
        app_id, owner = _app(app_id), _email(owner)
        now = time.time() if now is None else now
        return [
            {**rec, "active": _is_active(rec, now)}
            for rec in self._records(app_id)
            if rec.get("owner") == owner
        ]

    def received(
        self, app_id: str, grantee: str, *, now: Optional[float] = None
    ) -> list[dict]:
        """The **active** shares made to ``grantee`` in ``app_id``."""
        app_id, grantee = _app(app_id), _email(grantee)
        now = time.time() if now is None else now
        return [
            rec
            for rec in self._records(app_id)
            if rec.get("grantee") == grantee and _is_active(rec, now)
        ]

    def list_all(self) -> list[dict]:
        """Every share in every app. Admin-only, infrequent."""
        out = []
        for key in list(self._store):
            try:
                rec = self._store[key]
            except KeyError:
                continue
            if isinstance(rec, dict) and "grantee" in rec:
                out.append(rec)
        return out

    def remove_account(self, email: str) -> int:
        """Delete every share ``email`` is part of, either side. Returns how many."""
        try:
            email = _email(email)
        except ShareError:
            return 0
        gone = 0
        for rec in self.list_all():
            if email in (rec.get("owner"), rec.get("grantee")):
                gone += self.revoke(rec["app_id"], rec["owner"], rec["grantee"])
        return gone

    def _records(self, app_id: str) -> Iterator[dict]:
        for key in self._keys_for_app(app_id):
            try:
                rec = self._store[key]
            except KeyError:
                continue
            if isinstance(rec, dict):
                yield rec

    def _keys_for_app(self, app_id: str) -> Iterator[str]:
        """The ``{app_id}/{owner}/{grantee}`` keys of one app (a directory scan)."""
        if self._root is not None:
            app_dir = self._root / app_id
            if not app_dir.is_dir():
                return
            for owner_dir in app_dir.iterdir():
                if not owner_dir.is_dir():
                    continue
                for child in owner_dir.iterdir():
                    if child.is_file() and not child.name.endswith(".tmp"):
                        yield f"{app_id}/{owner_dir.name}/{child.name}"
            return
        prefix = f"{app_id}/"
        for key in list(self._store):
            if isinstance(key, str) and key.startswith(prefix):
                yield key
