# enlace_auth.auth.email

Outbound email for enlace_auth — used by the password-recovery flow.

Email is deliberately a thin, injectable seam. `make_auth_router` takes an
`EmailSender` callable; the platform wires a real one (SMTP) when configured
and otherwise falls back to the console sender, which *logs* the message
instead of sending it. That fallback means:

- local development needs no SMTP account — the reset link shows up in the log;
- a misconfigured production box degrades to “operator can recover the link
  from `journalctl`” instead of a hard failure.

A sender is `send(*, to: str, subject: str, body: str) -> None`. Senders
never raise into the request path: delivery failures are logged, because the
password-reset endpoint must return the same response whether or not the
address exists (so it can’t be used to enumerate accounts).

### Functions

| [`make_console_sender`](#enlace_auth.auth.email.make_console_sender)()                             | Return a sender that logs the email instead of delivering it.   |
|----------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| [`make_smtp_sender`](#enlace_auth.auth.email.make_smtp_sender)(\*, host[, port, username, ...]) | Return a sender that delivers via SMTP.                         |

### Classes

| [`EmailSender`](#enlace_auth.auth.email.EmailSender)(\*args, \*\*kwargs)   | Callable that delivers one plain-text email.   |
|------------------------------------------------------------------------------------|------------------------------------------------|

### *class* enlace_auth.auth.email.EmailSender(\*args, \*\*kwargs)

Bases: [`Protocol`](https://docs.python.org/3/library/typing.html#typing.Protocol)

Callable that delivers one plain-text email. Must not raise.

### enlace_auth.auth.email.make_console_sender()

Return a sender that logs the email instead of delivering it.

The default when no SMTP config is present. The full body — including any
reset link — is logged at WARNING so it stands out in `journalctl`.

* **Return type:**
  [`EmailSender`](#enlace_auth.auth.email.EmailSender)

### enlace_auth.auth.email.make_smtp_sender(, host, port=587, username=None, password=None, from_addr, use_tls=True, timeout=15.0)

Return a sender that delivers via SMTP.

* **Parameters:**
  * **host** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – SMTP server hostname.
  * **port** ([`int`](https://docs.python.org/3/builtins/functions.html#int)) – SMTP port (587 for STARTTLS, 465 for implicit TLS, 25 plain).
  * **password** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)) – SMTP auth credentials; omit for an open relay.
  * **from_addr** ([`str`](https://docs.python.org/3/builtins/stdtypes.html#str)) – the envelope/`From` address.
  * **use_tls** ([`bool`](https://docs.python.org/3/builtins/functions.html#bool)) – STARTTLS after connecting (ignored when `port == 465`,
    which uses implicit TLS).
  * **timeout** ([`float`](https://docs.python.org/3/builtins/functions.html#float)) – socket timeout in seconds.
* **Return type:**
  [`EmailSender`](#enlace_auth.auth.email.EmailSender)

Delivery errors are caught and logged — the caller’s flow continues so
account existence never leaks through a differing response.
