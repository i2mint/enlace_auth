# enlace_auth.auth.step_up

Step-up proofs and step-up requests, independent of how the person confirmed.

A **proof** says “this account confirmed this action, for this audience, by this
method, just now”. It is a signed token, valid for `ttl` seconds and spendable
once. Today the passkey ceremony mints them (`method="passkey"`); a TOTP or an
emailed code could mint them beside it without changing a redeeming backend
(i2mint/enlace_auth#95).

An **audience** names who may redeem a proof (an app, a connector backend). A
proof minted for one audience never redeems at another, and a proof minted with
no audience never redeems at a backend that names one, so a backend that states
its audience accepts only proofs made for it.

A **request** is how a backend asks for a confirmation without letting any page
choose the words the proof is for. The backend signs `{email, action, audience,
return_url}` with its audience key ([`audience_key()`](#enlace_auth.auth.step_up.audience_key), which the operator
gives it: `enlace-auth step-up-key AUDIENCE`) and posts it to
`/auth/passkeys/step-up/request`; the platform answers with a request id, and
the browser opens the platform’s own confirmation page for it, which shows the
action and the audience. The proof binds the backend’s action and audience, and
is minted once per request. A request id is signed, not encrypted: its email and
action can be read from it (and from the confirmation URL, so from access logs
and browser history); never put a secret in an action.

What the person SEES is guaranteed only when the platform’s pages are on an
origin no app shares: on one origin, an app’s script can run the same calls as
the confirmation page, or script that page, so it can still show other words
while the person taps. Serve apps on their own hosts (`[auth] cookie_domain`)
and keep `/auth` on the parent, with passkey `origins` naming only it.

```pycon
>>> proofs = StepUpProofs("k" * 32, clock=lambda: 1000)
>>> act, who = "app: delete 7", "ann@x.io"
>>> minted = proofs.mint(who, act, method="passkey", audience="app")
>>> proofs.redeem(minted["proof"], act, email=who, audience="app")["method"]
'passkey'
>>> proofs.redeem(minted["proof"], act, email=who, audience="app")
Traceback (most recent call last):
  ...
enlace_auth.auth.step_up.StepUpError: This step-up proof was already used.
```

### Module Attributes

| [`MAX_ACTION_LEN`](#enlace_auth.auth.step_up.MAX_ACTION_LEN)   | Longest action description a step-up accepts (it is shown to the user).   |
|-------------------------------------------------------------------|---------------------------------------------------------------------------|
| [`MAX_AUDIENCE_LEN`](#enlace_auth.auth.step_up.MAX_AUDIENCE_LEN) | Longest audience name.                                                    |

### Functions

| [`audience_key`](#enlace_auth.auth.step_up.audience_key)(signing_key, audience)   | The secret a backend proves it speaks for *audience* with.               |
|----------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`challenge_binding`](#enlace_auth.auth.step_up.challenge_binding)(action, audience)   | The text a step-up challenge commits to: the action, and its audience.   |
| [`clean_action`](#enlace_auth.auth.step_up.clean_action)(action)                  | The action text of a step-up, checked: 1..300 printable characters.      |
| [`clean_audience`](#enlace_auth.auth.step_up.clean_audience)(audience)              | An audience name (letters, digits, `._-`, at most 64), or None for none. |
| [`same_account`](#enlace_auth.auth.step_up.same_account)(a, b)                    | Whether two written addresses name one account (either IDN spelling).    |

### Classes

| [`StepUpProofs`](#enlace_auth.auth.step_up.StepUpProofs)(signing_key, \*[, claim_once, ...])   | Mint and redeem step-up proofs; sign and read step-up requests.   |
|-----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|

### Exceptions

| [`StepUpError`](#enlace_auth.auth.step_up.StepUpError)   | A step-up proof or request is refused; the message is safe to show.   |
|----------------------------------------------------------------|-----------------------------------------------------------------------|

### enlace_auth.auth.step_up.MAX_ACTION_LEN *= 300*

Longest action description a step-up accepts (it is shown to the user).

### enlace_auth.auth.step_up.MAX_AUDIENCE_LEN *= 64*

Longest audience name.

### *exception* enlace_auth.auth.step_up.StepUpError

Bases: [`ValueError`](https://docs.python.org/3/builtins/exceptions.html#ValueError)

A step-up proof or request is refused; the message is safe to show.

### *class* enlace_auth.auth.step_up.StepUpProofs(signing_key, \*, claim_once=None, ttl=120, request_ttl=300, clock=<built-in function time>)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Mint and redeem step-up proofs; sign and read step-up requests.

* **Parameters:**
  * **signing_key** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the platform’s HMAC key.
  * **claim_once** ([`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`bool`](https://docs.python.org/3/builtins/functions.html#bool)]]) – `claim(key) -> bool`, True the first time; spends proofs
    (default: in-process, right for one worker and tests).
  * **ttl** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – how long a proof is valid, in seconds.
  * **request_ttl** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – how long a step-up request is valid, in seconds.
  * **clock** ([`Callable`](https://docs.python.org/3/library/collections.abc.html#collections.abc.Callable)[[], [`float`](https://docs.python.org/3/builtins/functions.html#float)]) – `() -> epoch seconds`.

#### create_request(, email, action, audience, key, return_url=None)

A signed step-up request, for a backend holding *audience*’s key.

The request id carries the action, so the confirmation page shows what
the backend wrote and nothing a page chose.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

#### mint(email, action, , method, audience=None, ref=None)

A proof that *email* confirmed *action* by *method*.

*ref* is the method’s own reference (a passkey’s key), returned on
redemption so the method can check it still stands.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### read_request(request_id)

`{email, action, audience, return_url}` of a valid, unexpired request.

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### redeem(proof, action, , email, audience=None, methods=None, still_valid=None)

Spend *proof* for *action* by *email*; return what it proves.

`{email, action, audience, verified_at, method, ref}`. Refused (raises
[`StepUpError`](#enlace_auth.auth.step_up.StepUpError)): a forged, expired or spent proof; another action,
account or audience (a proof with an audience redeems only where that
audience is named, and one without only where none is); a method outside
*methods*; or what *still_valid(payload)* objects to (a removed passkey).

* **Return type:**
  [`dict`](https://docs.python.org/3/builtins/stdtypes.html#dict)

#### spend_request(request_id)

Mark a request confirmed; a second confirmation of it is refused.

One request, one proof: a backend that acts once per redeemed proof must
not be handed two for one request.

* **Return type:**
  [`None`](https://docs.python.org/3/builtins/constants.html#None)

### enlace_auth.auth.step_up.audience_key(signing_key, audience)

The secret a backend proves it speaks for *audience* with.

Derived from the platform’s signing key, so nothing is stored; rotating the
signing key rotates every audience key.

```pycon
>>> len(audience_key("k" * 32, "my_app"))
64
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.step_up.challenge_binding(action, audience)

The text a step-up challenge commits to: the action, and its audience.

The NUL cannot occur in a clean action or audience, so the pair is unambiguous,
and an audience-less binding is the action alone (as before #95).

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.step_up.clean_action(action)

The action text of a step-up, checked: 1..300 printable characters.

```pycon
>>> clean_action("  start job: repo, title ")
'start job: repo, title'
```

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.step_up.clean_audience(audience)

An audience name (letters, digits, `._-`, at most 64), or None for none.

```pycon
>>> clean_audience("my_app"), clean_audience(None), clean_audience("")
('my_app', None, None)
```

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]

### enlace_auth.auth.step_up.same_account(a, b)

Whether two written addresses name one account (either IDN spelling).

```pycon
>>> same_account("Ann@XN--BCHER-KVA.example", "ann@bücher.example")
True
>>> same_account("ann@x.io", "bob@x.io")
False
```

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)
