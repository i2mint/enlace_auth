# enlace_auth.ratelimit

A sliding-window rate limiter over any `MutableMapping`.

Host-free on purpose: this module imports nothing from `enlace_auth`, so it can
move unchanged (extraction candidate: i2mint/enlace#111, a limiter of
`enlace.ratelimit` over a `MutableMapping`, whose `RedisLimiter` is then
the shared replacement). enlace’s own in-memory limiters count per worker
process; the limits here must hold across workers, hence a store.

A limiter is a callable `allow(key, *, limit, window) -> bool`. It records the
hit and answers whether it stays within *limit* hits per *window* seconds. The
store maps a hashed key to the list of hit times, so a plain `dict` serves one
process and a file-backed mapping serves several worker processes sharing one
disk. With a file store the read-modify-write is not atomic, so concurrent hits
can each see the same count: the limit is approximate by a few hits, which is
what a rate limit needs, and is why a hard cap (an attempt counter) must not be
built from this alone.

```pycon
>>> now = [0.0]
>>> allow = SlidingWindowLimiter({}, clock=lambda: now[0])
>>> [allow("ip:1", limit=2, window=60) for _ in range(3)]
[True, True, False]
>>> now[0] = 61.0
>>> allow("ip:1", limit=2, window=60)
True
```

### Classes

| [`RateLimiter`](#enlace_auth.ratelimit.RateLimiter)(\*args, \*\*kwargs)           | Records one hit on *key*; True while it is within the limit.   |
|--------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| [`SlidingWindowLimiter`](#enlace_auth.ratelimit.SlidingWindowLimiter)([store, clock, ...]) | Allow at most *limit* hits per *window* seconds for each key.  |

### *class* enlace_auth.ratelimit.RateLimiter(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

Records one hit on *key*; True while it is within the limit.

### *class* enlace_auth.ratelimit.SlidingWindowLimiter(store=None, \*, clock=<built-in function time>, sweep_every=200, sweep_limit=500, max_hits_kept=1000)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Allow at most *limit* hits per *window* seconds for each key.

A refused hit is still recorded, so a client that keeps hammering stays
refused instead of getting one more through every time an old hit ages out.
Every *sweep_every* hits, up to *sweep_limit* keys whose newest hit is older
than the longest window seen are deleted, so one-off keys do not pile up.
A damaged entry counts as empty rather than raising.
