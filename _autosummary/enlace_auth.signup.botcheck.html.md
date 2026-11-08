# enlace_auth.signup.botcheck

A cheap check that a sign-up form was sent by a person.

[`TimedHoneypot`](#enlace_auth.signup.botcheck.TimedHoneypot) combines a honeypot field (`website`, hidden from
people, filled in by naive bots) with a signed time-to-submit challenge: the
form carries a token minted when it was rendered, and a submission sent sooner
than *min_seconds* after it, or with no valid token, fails. The page script
waits out the remainder before sending, so a person never sees the delay.

It is a seam: anything with `challenge() -> str` and `verify(fields) -> bool`
replaces it, such as a self-hosted proof-of-work challenge (ALTCHA) or
Cloudflare Turnstile. A failed check is answered exactly like a passed one, and
no mail is sent, so a bot learns nothing.

```pycon
>>> now = [100.0]
>>> check = TimedHoneypot("k" * 32, min_seconds=2, clock=lambda: now[0])
>>> token = check.challenge()
>>> check.verify({"challenge": token})
False
>>> now[0] = 103.0
>>> check.verify({"challenge": token})
True
>>> check.verify({"challenge": token, "website": "x"})
False
```

### Classes

| [`BotCheck`](#enlace_auth.signup.botcheck.BotCheck)(\*args, \*\*kwargs)                       | Mints a challenge for a form and checks the submitted fields.   |
|-----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| [`TimedHoneypot`](#enlace_auth.signup.botcheck.TimedHoneypot)(signing_key, \*[, min_seconds, ...]) | Honeypot field plus a signed time-to-submit token.              |

### *class* enlace_auth.signup.botcheck.BotCheck(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

Mints a challenge for a form and checks the submitted fields.

#### challenge()

A token the form sends back.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### verify(fields)

True when the submission looks like a person’s.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)

### *class* enlace_auth.signup.botcheck.TimedHoneypot(signing_key, \*, min_seconds=2.0, max_seconds=3600, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Honeypot field plus a signed time-to-submit token. See the module docstring.

#### challenge(, issued_at=None)

A token recording when the form was rendered (*issued_at*: now).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### verify(fields)

True when the honeypot is empty and the token is old enough, not stale.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)
