"""The handle registry: which account holds which handle, kept unique under a lock.

Two mappings, each a plain ``MutableMapping`` (a ``dict`` in tests, the platform's
file store in production):

- ``handles``: uniqueness key -> ``{"handle", "account", "at", "released_at"}``,
  public names only. A live entry has ``released_at`` ``None``. A released one keeps
  the name out of reach for *quarantine_seconds*: after a rename it still names its
  old account (who may take it back, and whose old links resolve to the new name);
  after an account deletion its ``account`` is ``None`` (the email is erased).
- ``owners``: account -> ``{"handle", "chosen", "at", "changed_at", "previous"}``.
  ``chosen`` is ``False`` for a private default the account has not confirmed: a
  frontend shows its "choose your username" step, and nobody else can see it.

A name is public only while both halves agree: a live ``handles`` entry naming the
account, and the account's chosen record naming that key. Writes are ordered so
that an interrupted one leaves at most one half, which every read ignores: never
two owners, never a name freed before its quarantine.

Uniqueness: every write runs under *lock* (a context manager). The default is a
process-local ``threading.Lock``; the platform passes :func:`file_lock`, which holds
across worker processes on one host. A store with a conditional write (S3
``If-None-Match``, a database unique index) is the replacement for a multi-host
deployment.

>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True, clock=lambda: 0.0)
>>> reg.ensure("ann.lee@example.com")
{'handle': 'ann.lee', 'chosen': False}
>>> reg.ensure("annlee@example.org")["handle"]   # private defaults do not collide
'annlee'
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
    is_well_formed,
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

    Codes: ``invalid``, ``reserved``, ``taken``, ``cooldown``, ``no-account``,
    ``exhausted``.
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

    A default handle (made from the email) is *private* until its account confirms
    or changes it: it lives only in the account's own ``owners`` record, never in
    ``handles``. So lookups, the availability check, timings and other accounts'
    defaults are all unaffected by it, two accounts may hold the same private
    default, and confirming one is an ordinary claim that can find the name taken.
    A handle made from an email gives part of the address away, so it is published
    only by its owner's own action (GDPR Art. 25(2); see
    ``misc/docs/research/general/usernames.md``).

    :param handles: uniqueness key -> public name entry (see the module docstring)
    :param owners: account -> its handle record
    :param policy: the rules (:class:`~enlace_auth.handles.core.HandlePolicy`)
    :param lock: a zero-argument factory of a context manager held around writes
    :param account_exists: whether an account exists; checked under the lock, so
        nothing is written for an account deleted meanwhile
    :param quarantine_seconds: how long a released public name stays out of others'
        reach (a renamed one redirects meanwhile)
    :param rename_cooldown_seconds: the least time between two public names (the
        first choice is free)
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

    def _live_owner(self, key: str) -> Optional[str]:
        """The account that holds *key* publicly now, checked both ways, or ``None``.

        The entry must be live and name the account, AND the account's record must
        be chosen and name the same key. Either half alone is a write that was
        interrupted, and counts for nothing.
        """
        entry = self._entry(key)
        if not entry or entry.get("released_at") is not None:
            return None
        account = entry.get("account")
        record = self._owner_record(account)
        if not record or not record.get("chosen"):
            return None
        if uniqueness_key(record["handle"]) != key:
            return None
        return account

    def _holder(self, key: str, now: float) -> Optional[str]:
        """Who keeps *key* from others: its public owner, or its last owner while
        the name is in quarantine (``""`` for a deleted account); ``None`` if free."""
        live = self._live_owner(key)
        if live:
            return live
        entry = self._entry(key)
        if not entry or entry.get("released_at") is None:
            return None  # free, or a stale half-write
        if now - float(entry["released_at"]) >= self.quarantine_seconds:
            return None
        return entry.get("account") or ""

    def _is_public(self, account: str, record: Optional[dict]) -> bool:
        return bool(
            record
            and record.get("chosen")
            and self._live_owner(uniqueness_key(record["handle"])) == account
        )

    def record_of(self, account: str) -> Optional[dict]:
        """``{"handle", "chosen"}`` of *account*, for the account itself.

        ``chosen`` is true only while the name is really published (so a write
        interrupted half-way shows as not chosen, and the account confirms again).
        """
        record = self._owner_record(account)
        if record is None:
            return None
        return {"handle": record["handle"], "chosen": self._is_public(account, record)}

    def handle_of(self, account: str) -> Optional[str]:
        """The public handle of *account*: ``None`` until it has confirmed one."""
        record = self._owner_record(account)
        return record["handle"] if self._is_public(account, record) else None

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
        if not is_well_formed(handle):
            return None
        return self._live_owner(uniqueness_key(handle))

    def resolve(self, handle: str) -> Optional[dict]:
        """``{"handle": current}`` for *handle*, following a recent rename.

        A name its account renamed away from, still in quarantine, resolves to that
        account's current handle with ``"renamed_from"``; a deleted account's name,
        a private default, or an unknown one resolves to ``None``.

        >>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
        >>> _ = reg.claim("a@example.com", "first")
        >>> _ = reg.claim("a@example.com", "second", force=True)
        >>> reg.resolve("FIRST")
        {'handle': 'second', 'renamed_from': 'first'}
        """
        if not is_well_formed(handle):
            return None
        key = uniqueness_key(handle)
        live = self._live_owner(key)
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
        holder = self._holder(uniqueness_key(handle), self._clock())
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

    def _default_for(self, account: str, now: float) -> str:
        """The first default for *account* not held publicly. Private defaults of
        other accounts are ignored on purpose: avoiding them would tell this account
        that some other email's local part folds to that name."""
        base = base_from_email(account, policy=self.policy)
        tries = self.policy.max_sequential + 1 + self.policy.random_tries
        for handle in candidates(base, policy=self.policy, tries=tries):
            if self._holder(uniqueness_key(handle), now) is None:
                return handle
        raise HandleError("exhausted", "Could not find a free username; try another.")

    def ensure(self, account: str, *, missing_ok: bool = False) -> Optional[dict]:
        """The handle record of *account*, giving it a private default if needed.

        The default is the email's local part, then ``1``, ``2`` ... until a name no
        one holds publicly (:func:`~enlace_auth.handles.core.candidates`). A private
        default that someone has since published is replaced by the next one. An
        account that does not exist gets nothing: ``None`` with *missing_ok*, else
        :class:`HandleError` ``no-account``.
        """
        record = self.record_of(account)
        if record and (
            record["chosen"] or self.is_free(record["handle"], account=account)
        ):
            return record
        with self._lock():
            if not self._account_exists(account):  # under the lock: not mid-deletion
                if missing_ok:
                    return None
                raise HandleError("no-account", "There is no such account.")
            now = self._clock()
            record = self._owner_record(account)
            if record and (
                self._is_public(account, record)
                or self._holder(uniqueness_key(record["handle"]), now)
                in (None, account)
            ):
                return self.record_of(account)
            previous = list(record.get("previous", [])) if record else []
            handle = self._default_for(account, now)
            self.owners[account] = {
                "handle": handle,
                "chosen": False,
                "at": record.get("at", now) if record else now,
                "changed_at": record.get("changed_at") if record else None,
                "previous": previous,
            }
            return {"handle": handle, "chosen": False}

    def claim(self, account: str, wanted: str, *, force: bool = False) -> dict:
        """Publish *wanted* as *account*'s handle (also: confirm its default).

        The first public name is free; changing it waits
        *rename_cooldown_seconds* after the last change, and the old name stays
        with the account for the quarantine (it redirects). *force* (an admin)
        skips the reserved list, the cooldown and a quarantine, never a public
        owner. Raises :class:`HandleError`; a ``taken`` one carries suggestions.
        """
        handle = normalize(wanted)
        problem = handle_problem(handle, policy=self.policy)
        if problem and not (force and problem.endswith("reserved.")):
            code = "reserved" if problem.endswith("reserved.") else "invalid"
            raise HandleError(code, problem)
        key = uniqueness_key(handle)
        with self._lock():
            if not self._account_exists(account):  # under the lock: not mid-deletion
                raise HandleError("no-account", "There is no such account.")
            now = self._clock()
            current = self._owner_record(account)
            public = self._is_public(account, current)
            live = self._live_owner(key)
            holder = self._holder(key, now)
            taken = (
                live not in (None, account)
                or holder not in (None, account)
                and not force
            )
            if not taken:
                if public and live != account and not force:
                    wait = (
                        float(current.get("changed_at") or 0)
                        + self.rename_cooldown_seconds
                        - now
                    )
                    if wait > 0:
                        days = max(1, int(-(-wait // DAY)))
                        raise HandleError(
                            "cooldown",
                            "You changed your username recently. "
                            f"You can change it again in {days} "
                            f"day{'s' * (days > 1)}.",
                        )
                return self._publish(account, handle, current, public, now)
        # computed outside the lock: up to a few hundred lookups
        raise HandleError(
            "taken", "This name is taken.", suggestions=self._suggest(handle, account)
        )

    def _publish(
        self, account: str, handle: str, current: Optional[dict], public: bool, now
    ) -> dict:
        """Write a public name. Under the lock; the order bounds a crash's harm.

        1. the new entry (alone, it is a stale half-write: reads ignore it);
        2. the old public name into quarantine, still the account's (alone, the
           account looks unconfirmed and confirms again; the name is never freed
           early);
        3. the account's record (now both halves agree).
        """
        key = uniqueness_key(handle)
        self.handles[key] = {
            "handle": handle,
            "account": account,
            "at": now,
            "released_at": None,
        }
        previous = list(current.get("previous", [])) if current else []
        old_key = uniqueness_key(current["handle"]) if current else None
        old = self._entry(old_key) if old_key and old_key != key else None
        if old and old.get("account") == account:
            # the old public name (or one a crash left quarantined) stays the
            # account's for the quarantine, and is remembered to release it
            if old.get("released_at") is None:
                self.handles[old_key] = {**old, "at": now, "released_at": now}
            previous = [k for k in previous if k != old_key] + [old_key]
        for dropped in previous[:-_MAX_PREVIOUS]:  # forgotten: erase the account
            entry = self._entry(dropped)
            if entry and entry.get("account") == account:
                self.handles[dropped] = {**entry, "account": None}
        previous = previous[-_MAX_PREVIOUS:]
        same = public and old_key == key
        self.owners[account] = {
            "handle": handle,
            "chosen": True,
            "at": current.get("at", now) if current else now,
            "changed_at": current.get("changed_at") if same else now,
            "previous": previous,
        }
        return {"handle": handle, "chosen": True}

    def release_account(self, account: str) -> int:
        """Forget *account*'s handles (the account is being deleted); return 1 or 0.

        Its public name, and the names it renamed away from, stay out of others'
        reach for the quarantine with no account attached (the email is erased);
        then they are free. Only entries that name this account are touched, and
        the record goes last, so an interrupted release never frees a name early.
        """
        with self._lock():
            record = self._owner_record(account)
            now = self._clock()
            keys = list(record.get("previous", [])) if record else []
            if record:
                keys.append(uniqueness_key(record["handle"]))
            for key in keys:
                entry = self._entry(key)
                if entry and entry.get("account") == account:
                    released = entry.get("released_at")
                    self.handles[key] = {
                        **entry,
                        "account": None,
                        "released_at": now if released is None else released,
                    }
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


#: how many earlier public names an account's record remembers (to release them)
_MAX_PREVIOUS = 20


def make_handle_registry(
    handles_cfg,
    *,
    store_factory: Callable[[str], MutableMapping],
    store_root,
    account_exists: Callable[[str], bool],
    groups: Iterable[str] = (),
    lock: Optional[Callable[[], ContextManager]] = None,
) -> HandleRegistry:
    """The platform's registry, from ``[auth.handles]`` (a ``HandlesConfig``).

    The two mappings are the platform store's ``handles`` and ``handle_owners``, and
    the lock is a ``flock`` on ``<store_root>/handles.lock``, so the gunicorn
    workers of one host agree (pass *lock* for stores shared across hosts). The
    names of *groups* (``[auth.groups]``) are reserved too, so no account can be
    called ``@family``.
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
        lock=lock
        or file_lock(Path(os.path.expanduser(str(store_root))) / "handles.lock"),
        account_exists=account_exists,
        quarantine_seconds=handles_cfg.quarantine_days * DAY,
        rename_cooldown_seconds=handles_cfg.rename_cooldown_days * DAY,
    )
