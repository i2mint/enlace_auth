"""Sign an account up the way a person does: register, read the mailed code, verify.

``/auth/register`` creates nothing until the address proves it gets mail
(i2mint/enlace_auth#81), so a test that needs a self-registered, signed-in
account goes through :func:`sign_up`. With no SMTP configured the platform's
sender logs the mail; the code is read from that log record. The bot check's
time-to-submit is met with a challenge dated a minute back, minted with the
test's signing key.
"""

from __future__ import annotations

import logging
import os
import re
import time

from enlace_auth.emails import normalize_email
from enlace_auth.signup.botcheck import TimedHoneypot


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def challenge(signing_key: str | None = None) -> str:
    """A bot-check token old enough to pass."""
    key = signing_key or os.environ["ENLACE_SIGNING_KEY"]
    return TimedHoneypot(key).challenge(issued_at=time.time() - 60)


def _csrf(client) -> dict:
    return {"X-CSRF-Token": client.get("/auth/csrf").json()["csrf"]}


def mailed_code(client, path: str, body: dict, *, csrf: dict | None = None):
    """POST *body* to *path*; return ``(response, code or None)`` from the mail."""
    handler = _Capture()
    logger = logging.getLogger("enlace_auth.email")
    logger.addHandler(handler)
    try:
        r = client.post(path, json=body, headers=csrf or _csrf(client))
    finally:
        logger.removeHandler(handler)
    try:
        to = normalize_email(body.get("email", ""))
    except ValueError:
        to = body.get("email", "")
    codes = [
        m.group(1)
        for msg in handler.messages
        if to in msg
        for m in [re.search(r"subject:\s*(\d{6})\b", msg)]
        if m
    ]
    return r, (codes[-1] if codes else None)


def sign_up(
    client, email: str, password: str | None = None, *, csrf: dict | None = None
):
    """Create *email* through the verify-first flow and sign in.

    Returns the verify response (200 when an account was signed in), or the
    register/start response when no code was mailed (a refused address).
    """
    body = {"email": email, "challenge": challenge()}
    path = "/auth/email/start"
    if password is not None:
        body["password"] = password
        path = "/auth/register"
    r, code = mailed_code(client, path, body, csrf=csrf)
    if r.status_code != 202 or code is None:
        return r
    return client.post(
        "/auth/email/verify",
        json={"email": email, "code": code},
        headers=csrf or _csrf(client),
    )
