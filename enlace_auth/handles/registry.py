"""The handle registry: which account holds which handle, kept unique under a lock.

Two mappings, each a plain ``MutableMapping`` (a ``dict`` in tests, the platform's
file store in production):

- ``handles``: uniqueness key -> ``{"handle", "account", "at", "released_at"}``. A
  live entry has ``released_at`` ``None``. A released one keeps a public name out
  of reach for *quarantine_seconds*: after a rename it still points at its old
  account (who may take it back, and whose old links resolve to the new name);
  after an account deletion its ``account`` is ``None`` (the email is erased).
- ``owners``: account -> ``{"handle", "chosen", "at", "changed_at"}``. ``chosen``
  is ``False`` for a default the account has not confirmed yet: a frontend shows
  its "choose your username" step while it is ``False``, and nobody else sees it.

``owners`` is the authority on an account's handle; a ``handles`` entry counts only
while its account's ``owners`` record points back at it. So a write interrupted
between the two mappings leaves a stale entry that reads as free, never two owners.

Uniqueness: every write runs under *lock* (a context manager). The default is a
process-local ``threading.Lock``; the platform passes :func:`file_lock`, which holds
across worker processes on one host. A store with a conditional write (S3
``If-None-Match``, a database unique index) is the replacement for a multi-host
deployment.

>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True, clock=lambda: 0.0)
>>> reg.ensure("ann.lee@example.com")
{'handle': 'ann.lee', 'chosen': False}
>>> reg.ensure("annlee@example.org")["handle"]   # ann.lee and annlee are one name
'annlee1'
>>> reg.claim("annlee@example.org", "Ann_Music")
{'handle': 'ann_music', 'chosen': True}
>>> reg.account_of("@annmusic")
'annlee@example.org'
>>> reg.handle_of("ann.lee@example.com") is None   # an unconfirmed default is private
True
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from collections.abc import Callable, Iterable, Iterator, MutableMapping
from pathlib import Path
from typing import ContextManager, Optional

from enlace_auth.handles.core import (
    DEFAULT_POLICY,
    HandlePolicy,
    base_from_email,
    candidates,
    handle_problem,
    normalize,
    suggestions,
    uniqueness_key,
)

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

__all__ = ["HandleError", "HandleRegistry", "file_lock", "make_handle_registry"]

DAY = 86400.0


class HandleError(ValueError):
    """A handle could not be set. *code* says why, *message* says it to a person.

    Codes: ``invalid``, ``reserved``, ``taken``, ``cooldown``, ``no-account``.
    """

    def __init__(self, code: str, message: str, *, suggestions: list = ()):
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestions = list(suggestions)


def file_lock(path) -> Callable[[], ContextManager]:
    """A lock factory over ``flock`` on *path*: exclusive across processes on a host.

    Each call returns a fresh context manager. Without ``fcntl`` (Windows) it falls
    back to a process-local lock.
    """
    path = Path(os.path.expanduser(str(path)))
    local = threading.Lock()

    @contextlib.contextmanager
    def hold():
        with local:  # flock is per open file; threads in one process share it
            if fcntl is None:  # pragma: no cover
                yield
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)  # releases the flock

    return hold


def _thread_lock() -> Callable[[], ContextManager]:
    lock = threading.Lock()
    return lambda: lock


class HandleRegistry:
    """Handles of accounts: assign defaults, claim, rename, release, look up.

    A default handle (made from the email) is *private and soft* until its account
    confirms or changes it: lookups by others do not see it, the availability check
    reports its name as free, and if someone claims that name the default moves to
    the next free one. A handle made from an email gives part of the address away,
    so it is published only by its owner's own action (GDPR Art. 25(2); see
    ``misc/docs/research/general/usernames.md``).

    :param handles: uniqueness key -> handle entry (see the module docstring)
    :param owners: account -> its handle record
    :param policy: the rules (:class:`~enlace_auth.handles.core.HandlePolicy`)
    :param lock: a zero-argument factory of a context manager held around writes
    :param account_exists: whether an account exists; a default is assigned only
        to one that does, so a lookup cannot create handles for arbitrary strings
    :param quarantine_seconds: how long a released handle stays out of others' reach
    :param rename_cooldown_seconds: the least time between two chosen renames (the
        first choice, from an unconfirmed default, is free)
    :param clock: the time, in epoch seconds
    """

    def __init__(
        self,
        handles: MutableMapping,
        owners: MutableMapping,
        *,
        policy: HandlePolicy = DEFAULT_POLICY,
        lock: Optional[Callable[[], ContextManager]] = None,
        account_exists: Callable[[str], bool] = lambda account: False,
        quarantine_seconds: float = 90 * DAY,
        rename_cooldown_seconds: float = 30 * DAY,
        clock: Callable[[], float] = time.time,
    ):
        self.handles = handles
        self.owners = owners
        self.policy = policy
        self._lock = lock or _thread_lock()
        self._account_exists = account_exists
        self.quarantine_seconds = quarantine_seconds
        self.rename_cooldown_seconds = rename_cooldown_seconds
        self._clock = clock

    # ------------------------------------------------------------------ reads

    def _owner_record(self, account: Optional[str]) -> Optional[dict]:
        if not account:
            return None
        try:
            record = self.owners[account]
        except KeyError:
            return None
        return record if isinstance(record, dict) and record.get("handle") else None

    def _entry(self, key: str) -> Optional[dict]:
        try:
            entry = self.handles[key]
        except KeyError:
            return None
        return entry if isinstance(entry, dict) else None

    def _live_owner(self, key: str, *, chosen_only: bool = False) -> Optional[str]:
        """The account that holds *key* now (only a confirmed one if *chosen_only*)."""
        entry = self._entry(key)
        if not entry or entry.get("released_at") is not None:
            return None
        account = entry.get("account")
        record = self._owner_record(account)
        if not record or uniqueness_key(record["handle"]) != key:
            return None  # stale: its account moved on (an interrupted write)
        if chosen_only and not record.get("chosen"):
            return None
        return account

    def _holder(self, key: str, now: float, *, soft_too: bool) -> Optional[str]:
        """Who keeps *key* from others: an owner, or a last owner in quarantine.

        An unconfirmed default counts only with *soft_too*. Returns the account,
        ``""`` for a deleted account's quarantined name, or ``None`` when free.
        """
        live = self._live_owner(key, chosen_only=not soft_too)
        if live:
            return live
        entry = self._entry(key)
        if not entry or entry.get("released_at") is None:
            return None
        if now - float(entry["released_at"]) >= self.quarantine_seconds:
            return None
        return entry.get("account") or ""

    def record_of(self, account: str) -> Optional[dict]:
        """``{"handle", "chosen"}`` of *account*, or ``None`` (nothing assigned).

        For the account itself (its own default included); others use
        :meth:`handle_of`.
        """
        record = self._owner_record(account)
        if record is None:
            return None
        return {"handle": record["handle"], "chosen": bool(record.get("chosen"))}

    def handle_of(self, account: str) -> Optional[str]:
        """The public handle of *account*: ``None`` until it has confirmed one."""
        record = self.record_of(account)
        return record["handle"] if record and record["chosen"] else None

    def handles_of(self, accounts: Iterable[str]) -> dict:
        """``{account: handle}`` for each of *accounts* with a public handle."""
        out = {}
        for account in dict.fromkeys(accounts):
            handle = self.handle_of(account)
            if handle:
                out[account] = handle
        return out

    def account_of(self, handle: str) -> Optional[str]:
        """The account holding *handle* publicly (any spelling of it), or ``None``."""
        return self._live_owner(uniqueness_key(handle), chosen_only=True)

    def resolve(self, handle: str) -> Optional[dict]:
        """``{"handle": current}`` for *handle*, following a recent rename.

        A name its account renamed away from, still in quarantine, resolves to that
        account's current handle with ``"renamed_from"``; a deleted account's
        name, an unconfirmed default, or an unknown one resolves to ``None``.

        >>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
        >>> _ = reg.claim("a@example.com", "first")
        >>> _ = reg.claim("a@example.com", "second", force=True)
        >>> reg.resolve("FIRST")
        {'handle': 'second', 'renamed_from': 'first'}
        """
        key = uniqueness_key(handle)
        live = self._live_owner(key, chosen_only=True)
        if live:
            return {"handle": self._owner_record(live)["handle"]}
        entry = self._entry(key)
        if (
            entry
            and entry.get("released_at") is not None
            and self._clock() - float(entry["released_at"]) < self.quarantine_seconds
        ):
            current = self.handle_of(entry.get("account") or "")
            if current:
                return {"handle": current, "renamed_from": entry["handle"]}
        return None

    def is_free(self, handle: str, *, account: Optional[str] = None) -> bool:
        """Whether *handle* could be claimed by *account* (by anyone, if ``None``)."""
        holder = self._holder(uniqueness_key(handle), self._clock(), soft_too=False)
        return holder is None or (account is not None and holder == account)

    def check(self, wanted: str, *, account: Optional[str] = None) -> dict:
        """What a "choose your username" field shows while the person types.

        ``{"handle", "available", "problem", "code", "suggestions"}``: *handle* is
        the normalised form (show it as the preview), *problem* a sentence or
        ``None``, *code* one of :class:`HandleError`'s codes or ``None``.

        >>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
        >>> _ = reg.claim("thorwhalen@example.com", "thorwhalen")
        >>> reg.check("Thor.Whalen")["suggestions"]
        ['thor.whalen1', 'thor.whalen2', 'thor.whalen3']
        """
        handle = normalize(wanted)
        problem = handle_problem(handle, policy=self.policy)
        code = None
        if problem:
            code = "reserved" if problem.endswith("reserved.") else "invalid"
        elif not self.is_free(handle, account=account):
            problem, code = "This name is taken.", "taken"
        return {
            "handle": handle,
            "available": problem is None,
            "problem": problem,
            "code": code,
            "suggestions": (
                self._suggest(handle, account) if code in ("taken", "reserved") else []
            ),
        }

    def _suggest(self, handle: str, account: Optional[str]) -> list:
        return suggestions(
            handle, lambda h: self.is_free(h, account=account), policy=self.policy
        )

    def __iter__(self) -> Iterator[tuple]:
        """``(account, handle, chosen)`` for each account with a handle."""
        for account in list(self.owners):
            record = self.record_of(account)
            if record:
                yield account, record["handle"], record["chosen"]

    # ----------------------------------------------------------------- writes

    def _write(self, account: str, handle: str, *, chosen: bool, now: float) -> dict:
        """Point *handle* at *account* and release its previous one. Under the lock."""
        key = uniqueness_key(handle)
        previous = self._owner_record(account)
        self.handles[key] = {
            "handle": handle,
            "account": account,
            "at": now,
            "released_at": None,
        }
        changed = previous is None or previous["handle"] != handle
        self.owners[account] = {
            "handle": handle,
            "chosen": chosen,
            "at": previous.get("at", now) if previous else now,
            "changed_at": now if changed else previous.get("changed_at", now),
        }
        if previous and uniqueness_key(previous["handle"]) != key:
            old_key = uniqueness_key(previous["handle"])
            old = self._entry(old_key)
            if old and old.get("account") == account:  # not if another took it
                if previous.get("chosen"):  # a public name: held, and redirects
                    self.handles[old_key] = {**old, "at": now, "released_at": now}
                else:  # a private default was never seen: just let it go
                    with contextlib.suppress(KeyError):
                        del self.handles[old_key]
        return {"handle": handle, "chosen": chosen}

    def _assign_default(self, account: str, now: float) -> dict:
        """Give *account* its first free default. Under the lock."""
        base = base_from_email(account, policy=self.policy)
        for handle in candidates(base, policy=self.policy):
            if self._holder(uniqueness_key(handle), now, soft_too=True) is None:
                return self._write(account, handle, chosen=False, now=now)
        raise AssertionError("candidates() is infinite")  # pragma: no cover

    def ensure(self, account: str, *, missing_ok: bool = False) -> Optional[dict]:
        """The handle record of *account*, assigning the default if it has none.

        The default is the email's local part, then ``1``, ``2`` ... until a free one
        (:func:`~enlace_auth.handles.core.candidates`), unconfirmed (``chosen``
        ``False``, so private and soft). An account that does not exist gets
        nothing: ``None`` with *missing_ok*, else :class:`HandleError` ``no-account``.
        """
        record = self.record_of(account)
        if record:
            return record
        if not self._account_exists(account):
            if missing_ok:
                return None
            raise HandleError("no-account", "There is no such account.")
        with self._lock():
            return self.record_of(account) or self._assign_default(
                account, self._clock()
            )

    def claim(self, account: str, wanted: str, *, force: bool = False) -> dict:
        """Give *account* the handle *wanted* (also: confirm the one it has).

        Claiming the handle the account already has marks it chosen. A first
        choice (from an unconfirmed default) is free; a later rename waits
        *rename_cooldown_seconds* after the last change. Another account's
        unconfirmed default does not block a claim: that default moves on to its
        next free name. *force* (an admin) skips the reserved list, the cooldown
        and others' quarantine, never a confirmed owner. Raises
        :class:`HandleError`.
        """
        if not self._account_exists(account) and self.record_of(account) is None:
            raise HandleError("no-account", "There is no such account.")
        handle = normalize(wanted)
        problem = handle_problem(handle, policy=self.policy)
        if problem and not (force and problem.endswith("reserved.")):
            code = "reserved" if problem.endswith("reserved.") else "invalid"
            raise HandleError(code, problem)
        with self._lock():
            now = self._clock()
            current = self._owner_record(account)
            key = uniqueness_key(handle)
            if current and uniqueness_key(current["handle"]) == key:
                # the same name (perhaps re-spelled): a confirmation, never a rename
                return self._write(account, handle, chosen=True, now=now)
            holder = self._holder(key, now, soft_too=False)
            if holder is not None and holder != account:
                if not (force and self._live_owner(key, chosen_only=True) is None):
                    raise HandleError(
                        "taken",
                        "This name is taken.",
                        suggestions=self._suggest(handle, account),
                    )
            if current and current.get("chosen") and not force:
                wait = (
                    float(current.get("changed_at", 0))
                    + self.rename_cooldown_seconds
                    - now
                )
                if wait > 0:
                    days = max(1, int(-(-wait // DAY)))
                    raise HandleError(
                        "cooldown",
                        "You changed your username recently. "
                        f"You can change it again in {days} day{'s' * (days > 1)}.",
                    )
            bumped = self._live_owner(key)  # an unconfirmed default of another
            record = self._write(account, handle, chosen=True, now=now)
            if bumped and bumped != account:
                self._assign_default(bumped, now)
            return record

    def release_account(self, account: str) -> int:
        """Forget *account*'s handle (the account is being deleted); return 1 or 0.

        A confirmed name stays out of others' reach for *quarantine_seconds*, with
        no account attached (the email is erased with the account), and then is
        free; an unconfirmed default, never public, is freed at once.
        """
        with self._lock():
            record = self._owner_record(account)
            now = self._clock()
            for key in list(self.handles):
                entry = self._entry(key)
                if entry and entry.get("account") == account:
                    self.handles[key] = {**entry, "account": None}
            if record is not None:
                key = uniqueness_key(record["handle"])
                if record.get("chosen"):
                    self.handles[key] = {
                        "handle": record["handle"],
                        "account": None,
                        "at": now,
                        "released_at": now,
                    }
                else:
                    with contextlib.suppress(KeyError):
                        del self.handles[key]
            with contextlib.suppress(KeyError):
                del self.owners[account]
            return int(record is not None)

    def sweep(self) -> int:
        """Remove released entries whose quarantine is over; return how many."""
        now, gone = self._clock(), 0
        with self._lock():
            for key in list(self.handles):
                entry = self._entry(key)
                if (
                    entry
                    and entry.get("released_at") is not None
                    and now - float(entry["released_at"]) >= self.quarantine_seconds
                ):
                    with contextlib.suppress(KeyError):
                        del self.handles[key]
                        gone += 1
        return gone


def make_handle_registry(
    handles_cfg,
    *,
    store_factory: Callable[[str], MutableMapping],
    store_root,
    account_exists: Callable[[str], bool],
    groups: Iterable[str] = (),
) -> HandleRegistry:
    """The platform's registry, from ``[auth.handles]`` (a ``HandlesConfig``).

    The two mappings are the platform store's ``handles`` and ``handle_owners``, and
    the lock is a ``flock`` on ``<store_root>/handles.lock``, so the gunicorn
    workers of one host agree. The names of *groups* (``[auth.groups]``) are
    reserved too, so no account can be called ``@family``.
    """
    from dataclasses import replace

    policy = replace(
        DEFAULT_POLICY,
        min_length=handles_cfg.min_length,
        max_length=handles_cfg.max_length,
    ).with_reserved([*handles_cfg.reserved, *groups])
    return HandleRegistry(
        store_factory("handles"),
        store_factory("handle_owners"),
        policy=policy,
        lock=file_lock(Path(os.path.expanduser(str(store_root))) / "handles.lock"),
        account_exists=account_exists,
        quarantine_seconds=handles_cfg.quarantine_days * DAY,
        rename_cooldown_seconds=handles_cfg.rename_cooldown_days * DAY,
    )
