"""A sliding-window rate limiter over any ``MutableMapping``.

Host-free on purpose: this module imports nothing from ``enlace_auth``, so it can
move to a metering package unchanged (extraction candidate:
i2mint/enlace_metering#9, a rolling-window call-count policy).

A limiter is a callable ``allow(key, *, limit, window) -> bool``. It records the
hit and answers whether it stays within *limit* hits per *window* seconds. The
store maps a hashed key to the list of hit times, so a plain ``dict`` serves one
process and a file-backed mapping serves several worker processes sharing one
disk. With a file store the read-modify-write is not atomic, so concurrent hits
can each see the same count: the limit is approximate by a few hits, which is
what a rate limit needs, and is why a hard cap (an attempt counter) must not be
built from this alone.

>>> now = [0.0]
>>> allow = SlidingWindowLimiter({}, clock=lambda: now[0])
>>> [allow("ip:1", limit=2, window=60) for _ in range(3)]
[True, True, False]
>>> now[0] = 61.0
>>> allow("ip:1", limit=2, window=60)
True
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, MutableMapping
from typing import Optional, Protocol


class RateLimiter(Protocol):
    """Records one hit on *key*; True while it is within the limit."""

    def __call__(self, key: str, *, limit: int, window: float) -> bool:
        """Record a hit and say whether it is allowed."""
        ...


def _store_key(key: str) -> str:
    # Keys hold addresses and IPs; hashing keeps them out of file names and
    # gives every key the same safe shape.
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class SlidingWindowLimiter:
    """Allow at most *limit* hits per *window* seconds for each key.

    A refused hit is still recorded, so a client that keeps hammering stays
    refused instead of getting one more through every time an old hit ages out.
    Every *sweep_every* hits, up to *sweep_limit* keys whose newest hit is older
    than the longest window seen are deleted, so one-off keys do not pile up.
    A damaged entry counts as empty rather than raising.
    """

    def __init__(
        self,
        store: Optional[MutableMapping] = None,
        *,
        clock: Callable[[], float] = time.time,
        sweep_every: int = 200,
        sweep_limit: int = 500,
        max_hits_kept: int = 1000,
    ):
        self.store = {} if store is None else store
        self._clock = clock
        self._sweep_every = sweep_every
        self._sweep_limit = sweep_limit
        self._max_hits_kept = max_hits_kept
        self._hits_since_sweep = 0
        self._longest_window = 0.0

    def _read(self, skey: str) -> list[float]:
        try:
            hits = self.store[skey]
        except Exception:  # noqa: BLE001 - absent or damaged: start afresh
            return []
        if not isinstance(hits, list):
            return []
        return [h for h in hits if isinstance(h, (int, float))]

    def __call__(self, key: str, *, limit: int, window: float) -> bool:
        """Record a hit on *key*; True while it is within *limit* per *window*."""
        now = self._clock()
        self._longest_window = max(self._longest_window, float(window))
        skey = _store_key(key)
        recent = [h for h in self._read(skey) if now - h < window]
        allowed = len(recent) < limit
        recent.append(now)
        try:
            self.store[skey] = recent[-self._max_hits_kept :]
        except Exception:  # noqa: BLE001 - an unwritable store must not 500
            pass
        self._maybe_sweep(now)
        return allowed

    def _maybe_sweep(self, now: float) -> None:
        self._hits_since_sweep += 1
        if self._hits_since_sweep < self._sweep_every:
            return
        self._hits_since_sweep = 0
        horizon = self._longest_window
        for i, skey in enumerate(list(self.store)):
            if i >= self._sweep_limit:
                break
            hits = self._read(skey)
            if not hits or now - max(hits) >= horizon:
                try:
                    del self.store[skey]
                except Exception:  # noqa: BLE001 - raced or damaged: skip it
                    pass
