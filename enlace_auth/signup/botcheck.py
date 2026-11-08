"""A cheap check that a sign-up form was sent by a person.

:class:`TimedHoneypot` combines a honeypot field (``website``, hidden from
people, filled in by naive bots) with a signed time-to-submit challenge: the
form carries a token minted when it was rendered, and a submission sent sooner
than *min_seconds* after it, or with no valid token, fails. The page script
waits out the remainder before sending, so a person never sees the delay.

It is a seam: anything with ``challenge() -> str`` and ``verify(fields) -> bool``
replaces it, such as a self-hosted proof-of-work challenge (ALTCHA) or
Cloudflare Turnstile. A failed check is answered exactly like a passed one, and
no mail is sent, so a bot learns nothing.

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
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from enlace_auth.auth.cookies import sign_cookie, verify_cookie

_SALT = "signup-challenge"
HONEYPOT_FIELD = "website"


class BotCheck(Protocol):
    """Mints a challenge for a form and checks the submitted fields."""

    def challenge(self) -> str:
        """A token the form sends back."""
        ...

    def verify(self, fields: Mapping[str, Any]) -> bool:
        """True when the submission looks like a person's."""
        ...


class TimedHoneypot:
    """Honeypot field plus a signed time-to-submit token. See the module docstring."""

    def __init__(
        self,
        signing_key: str,
        *,
        min_seconds: float = 2.0,
        max_seconds: int = 3600,
        clock: Callable[[], float] = time.time,
    ):
        self._signing_key = signing_key
        self.min_seconds = min_seconds
        self.max_seconds = max_seconds
        self._clock = clock

    def challenge(self, *, issued_at: float | None = None) -> str:
        """A token recording when the form was rendered (*issued_at*: now)."""
        at = self._clock() if issued_at is None else issued_at
        return sign_cookie(repr(at), self._signing_key, salt=_SALT)

    def verify(self, fields: Mapping[str, Any]) -> bool:
        """True when the honeypot is empty and the token is old enough, not stale."""
        if str(fields.get(HONEYPOT_FIELD) or "").strip():
            return False
        raw = verify_cookie(
            str(fields.get("challenge") or ""), self._signing_key, salt=_SALT
        )
        try:
            issued = float(raw)
        except (TypeError, ValueError):
            return False
        age = self._clock() - issued
        return self.min_seconds <= age <= self.max_seconds
