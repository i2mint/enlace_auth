"""Who may create an account, from which app.

A :class:`SignupPolicy` answers two questions: ``allows(email, app)`` (may this
address create an account when it signs up from *app*) and ``mode(app)`` (which
of ``closed``, ``allowlist``, ``invite`` or ``open`` applies, for the page copy).
It decides account *creation* only. Whether an account may open an app stays
with ``enlace.access.is_user_allowed``.

An admin address is refused under every mode: a self-service sign-up must never
be the way an admin account comes into being (i2mint/enlace_auth#35, #38).

Invitations are a ``MutableMapping`` keyed by the normalized address, whose
value is ``{"apps": [...], "invited_by": ..., "created_at": ...}``; ``"*"`` in
``apps`` invites to every app. An allowlisted address counts as invited.

>>> p = SignupPolicy(
...     default="closed",
...     apps={"game": "open", "beta": "invite"},
...     invites={"a@x.io": {"apps": ["beta"]}},
...     admin_emails=("boss@x.io",),
... )
>>> p.allows("anyone@x.io", "game"), p.allows("anyone@x.io", None)
(True, False)
>>> p.allows("a@x.io", "beta"), p.allows("b@x.io", "beta")
(True, False)
>>> p.allows("boss@x.io", "game")
False
"""

from __future__ import annotations

import time
from collections.abc import Iterable, Mapping, MutableMapping
from typing import Optional

from enlace_auth.emails import account_spellings, normalize_email

SIGNUP_MODES = ("closed", "allowlist", "invite", "open")
ALL_APPS = "*"


def _normal(email: str) -> str:
    """The spelling sign-up keys an address under (punycode domain as Unicode)."""
    try:
        return normalize_email(email)
    except ValueError:
        return email.strip().lower()


class SignupPolicy:
    """The per-app sign-up policy of ``[auth.signup]``. See the module docstring."""

    def __init__(
        self,
        *,
        default: str = "closed",
        apps: Optional[Mapping[str, str]] = None,
        allowlist: Iterable[str] = (),
        invites: Optional[MutableMapping] = None,
        admin_emails: Iterable[str] = (),
    ):
        for mode in (default, *(apps or {}).values()):
            if mode not in SIGNUP_MODES:
                raise ValueError(f"unknown sign-up mode {mode!r}; use {SIGNUP_MODES}")
        self.default = default
        self.apps = dict(apps or {})
        # Both spellings of the entry's one mailbox (punycode and Unicode
        # domain): sign-up proves the address by a mailed code (and OAuth by
        # the provider), so the other spelling is the same, proven mailbox.
        self.allowlist = frozenset(
            s
            for e in allowlist
            if e.strip()
            for s in account_spellings(e.strip().lower())
        )
        self.invites = {} if invites is None else invites
        self._admins = frozenset(s for e in admin_emails for s in account_spellings(e))

    def mode(self, app: Optional[str]) -> str:
        """The mode that applies to a sign-up from *app* (``None``: the default)."""
        return self.apps.get(app, self.default) if app else self.default

    def is_invited(self, email: str, app: Optional[str]) -> bool:
        """True when *email* holds an invitation for *app*, or is allowlisted."""
        if email.strip().lower() in self.allowlist:
            return True
        e = _normal(email)
        if e in self.allowlist:
            return True
        try:
            record = self.invites.get(e)
        except Exception:  # noqa: BLE001 - a damaged record invites nobody
            return False
        if not isinstance(record, dict):
            return False
        apps = record.get("apps") or []
        return ALL_APPS in apps or (app is not None and app in apps)

    def allows(self, email: str, app: Optional[str]) -> bool:
        """May *email* create an account by signing up from *app*?"""
        e = _normal(email)
        if e in self._admins or email.strip().lower() in self._admins:
            return False
        mode = self.mode(app)
        if mode == "open":
            return True
        if mode == "allowlist":
            return email.strip().lower() in self.allowlist
        if mode == "invite":
            return self.is_invited(e, app)
        return False

    def is_admin(self, email: str) -> bool:
        """True for an admin address, in either spelling."""
        return _normal(email) in self._admins or email.strip().lower() in self._admins

    def on_created(self, email: str) -> None:
        """Called once an account for *email* exists: its invitation is used up."""
        consume_invite(self.invites, email)

    def __call__(self, email: str, app: Optional[str] = None) -> bool:
        """Alias of :meth:`allows`, so a policy is also a ``can_register``."""
        return self.allows(email, app)


def app_from_next(next_url: str, known_apps: Iterable[str]) -> Optional[str]:
    """The app a ``next`` path belongs to (``/<app>/...`` or ``/api/<app>/...``).

    >>> app_from_next("/api/game/state?x=1", {"game"})
    'game'
    >>> app_from_next("/nope/", {"game"}) is None
    True
    """
    parts = [p for p in (next_url or "").split("?", 1)[0].split("/") if p]
    if len(parts) >= 2 and parts[0] == "api":
        parts = parts[1:]
    return parts[0] if parts and parts[0] in set(known_apps) else None


def invite(
    invites: MutableMapping,
    email: str,
    *,
    apps: Iterable[str] = (ALL_APPS,),
    invited_by: Optional[str] = None,
    now: Optional[float] = None,
) -> dict:
    """Invite *email* to sign up from *apps* (merged with any earlier invitation)."""
    e = _normal(email)
    try:
        earlier = invites.get(e)
    except Exception:  # noqa: BLE001 - replace a damaged record
        earlier = None
    merged = set(earlier.get("apps") or []) if isinstance(earlier, dict) else set()
    merged.update(apps)
    record = {
        "apps": sorted(merged),
        "invited_by": invited_by,
        "created_at": time.time() if now is None else now,
    }
    invites[e] = record
    return record


def consume_invite(invites: MutableMapping, email: str) -> None:
    """Drop *email*'s invitation once its account exists (a missing one is fine)."""
    try:
        del invites[_normal(email)]
    except Exception:  # noqa: BLE001 - absent, raced or unreadable: nothing to do
        pass
