"""Outbound email for enlace_auth — used by the password-recovery flow.

Email is deliberately a thin, injectable seam. ``make_auth_router`` takes an
``EmailSender`` callable; the platform wires a real one (SMTP) when configured
and otherwise falls back to the console sender, which *logs* the message
instead of sending it. That fallback means:

- local development needs no SMTP account — the reset link shows up in the log;
- a misconfigured production box degrades to "operator can recover the link
  from ``journalctl``" instead of a hard failure.

A sender is ``send(*, to: str, subject: str, body: str) -> None``. Senders
never raise into the request path: delivery failures are logged, because the
password-reset endpoint must return the same response whether or not the
address exists (so it can't be used to enumerate accounts).
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Protocol

_logger = logging.getLogger("enlace_auth.email")


class EmailSender(Protocol):
    """Callable that delivers one plain-text email. Must not raise."""

    def __call__(self, *, to: str, subject: str, body: str) -> None:
        """Deliver (or log) the message."""
        ...


def make_console_sender() -> EmailSender:
    """Return a sender that logs the email instead of delivering it.

    The default when no SMTP config is present. The full body — including any
    reset link — is logged at WARNING so it stands out in ``journalctl``.
    """

    def send(*, to: str, subject: str, body: str) -> None:
        _logger.warning(
            "EMAIL NOT SENT (no SMTP configured) — logging instead.\n"
            "  to:      %s\n"
            "  subject: %s\n"
            "  body:\n%s",
            to,
            subject,
            _indent(body),
        )

    return send


def make_smtp_sender(
    *,
    host: str,
    port: int = 587,
    username: str | None = None,
    password: str | None = None,
    from_addr: str,
    use_tls: bool = True,
    timeout: float = 15.0,
) -> EmailSender:
    """Return a sender that delivers via SMTP.

    Args:
        host: SMTP server hostname.
        port: SMTP port (587 for STARTTLS, 465 for implicit TLS, 25 plain).
        username / password: SMTP auth credentials; omit for an open relay.
        from_addr: the envelope/``From`` address.
        use_tls: STARTTLS after connecting (ignored when ``port == 465``,
            which uses implicit TLS).
        timeout: socket timeout in seconds.

    Delivery errors are caught and logged — the caller's flow continues so
    account existence never leaks through a differing response.
    """

    def send(*, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=timeout) as s:
                    _login_and_send(s, username, password, msg)
            else:
                with smtplib.SMTP(host, port, timeout=timeout) as s:
                    if use_tls:
                        s.starttls()
                    _login_and_send(s, username, password, msg)
            _logger.info("Sent email to %s (subject: %s)", to, subject)
        except Exception as exc:  # noqa: BLE001 — never surface into the request
            _logger.error(
                "Failed to send email to %s via %s:%s — %r", to, host, port, exc
            )

    return send


def _login_and_send(
    server: smtplib.SMTP, username: str | None, password: str | None, msg: EmailMessage
) -> None:
    """Authenticate (if creds given) and send ``msg`` on an open connection."""
    if username and password:
        server.login(username, password)
    server.send_message(msg)


def _indent(text: str, prefix: str = "    ") -> str:
    """Indent every line of ``text`` for readable multi-line log output."""
    return "\n".join(prefix + line for line in text.splitlines())
