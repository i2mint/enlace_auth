# enlace_auth.signup.codes

One-time codes mailed for sign-in, sign-up and account deletion.

A pending code is stored as an HMAC, never in clear, in a `MutableMapping`
keyed by a hash of `(purpose, address, nonce)`. The *nonce* names the browser
that asked (an HttpOnly cookie the sign-up router sets), so a code can be spent
only from that browser: someone else cannot finish a sign-up they did not start
(which would let them choose the password of a victim’s account), nor sign a
victim’s browser into their own account by sending them a link. It also means a
stranger asking for codes for an address replaces only their own pending code,
never its owner’s.

A code is spent by the first check that matches it, expires after *ttl*
seconds, and is destroyed after *max_attempts* wrong guesses. Wrong guesses are
counted under their own key, so a late write of the counter (from another worker
process) can never bring a spent code back; under such races the counter can
undercount, so callers also rate-limit the check.

The emailed link carries the same code in a signed token (`link_token()`)
put in the URL *fragment*, which browsers never send to the server, so the code
does not land in access logs, and the page it opens spends it only by a POST.

```pycon
>>> now = [0.0]
>>> codes = PendingCodes({}, signing_key="k" * 32, clock=lambda: now[0])
>>> code = codes.issue("a@x.io", data={"next": "/game/"})
>>> codes.check("a@x.io", "000000" if code != "000000" else "111111")
>>> codes.check("a@x.io", code)
{'next': '/game/'}
>>> codes.check("a@x.io", code) is None  # spent
True
```

### Functions

| [`normalize_code`](#enlace_auth.signup.codes.normalize_code)(code)   | Digits only, so `"123 456"` and `"123-456"` are the code `"123456"`.   |
|-------------------------------------------------------------------------|------------------------------------------------------------------------|

### Classes

| [`PendingCodes`](#enlace_auth.signup.codes.PendingCodes)(store, \*, signing_key[, ttl, ...])   | Issue and check one-time codes.   |
|-----------------------------------------------------------------------------------------------------|-----------------------------------|

### *class* enlace_auth.signup.codes.PendingCodes(store, \*, signing_key, ttl=600, max_attempts=3, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Issue and check one-time codes. See the module docstring.

#### check(email, code, , purpose='signin', nonce='')

Spend *code* for *email* and *nonce*; return its data, else `None`.

`None` covers every failure alike (no pending code, another browser’s,
expired, wrong, too many attempts, already spent).

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)]

#### discard(email, , purpose='signin', nonce='')

Forget any pending code for *email* and *nonce*.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

#### issue(email, , purpose='signin', nonce='', data=None)

Store a fresh code for *email* and *nonce* (replacing theirs); return it.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### link_token(email, code, , purpose='signin')

A signed token carrying *email* and *code*, for the emailed link.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### open_link_token(token)

`(email, code, purpose)` from a valid, unexpired token, else `None`.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`tuple`](https://docs.python.org/3/builtins/stdtypes.html#tuple)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str), [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]]

### enlace_auth.signup.codes.normalize_code(code)

Digits only, so `"123 456"` and `"123-456"` are the code `"123456"`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
