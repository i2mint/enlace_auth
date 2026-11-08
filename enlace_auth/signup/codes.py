"""One-time codes mailed for sign-in, sign-up and account deletion.

A pending code is stored as an HMAC, never in clear, in a ``MutableMapping``
keyed by a hash of ``(purpose, address)``, so one address has at most one
pending code per purpose and a new one replaces the old. A code is spent by the
first check that matches it, expires after *ttl* seconds, and is destroyed after
*max_attempts* wrong guesses. Under concurrent checks against a file store the
attempt counter can undercount, so callers also rate-limit the check per address.

The emailed link carries the same code in a signed token (:meth:`link_token`)
put in the URL *fragment*, which browsers never send to the server, so the code
does not land in access logs, and the page it opens spends it only by a POST.

>>> now = [0.0]
>>> codes = PendingCodes({}, signing_key="k" * 32, clock=lambda: now[0])
>>> code = codes.issue("a@x.io", data={"next": "/game/"})
>>> codes.check("a@x.io", "000000" if code != "000000" else "111111")
>>> codes.check("a@x.io", code)
{'next': '/game/'}
>>> codes.check("a@x.io", code) is None  # spent
True
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, MutableMapping
from typing import Any, Optional

from enlace_auth.auth.cookies import sign_cookie, verify_cookie

CODE_DIGITS = 6
_LINK_SALT = "email-code-link"


def _key(purpose: str, email: str) -> str:
    return hashlib.sha256(f"{purpose}\0{email}".encode()).hexdigest()


def normalize_code(code: Any) -> str:
    """Digits only, so ``"123 456"`` and ``"123-456"`` are the code ``"123456"``."""
    return "".join(c for c in str(code or "") if c.isdigit())


class PendingCodes:
    """Issue and check one-time codes. See the module docstring."""

    def __init__(
        self,
        store: MutableMapping,
        *,
        signing_key: str,
        ttl: int = 600,
        max_attempts: int = 5,
        clock: Callable[[], float] = time.time,
    ):
        self.store = store
        self._signing_key = signing_key
        self.ttl = ttl
        self.max_attempts = max_attempts
        self._clock = clock

    def _mac(self, purpose: str, email: str, code: str) -> str:
        msg = f"{purpose}\0{email}\0{code}".encode()
        return hmac.new(self._signing_key.encode(), msg, hashlib.sha256).hexdigest()

    def issue(
        self, email: str, *, purpose: str = "signin", data: Optional[dict] = None
    ) -> str:
        """Store a fresh code for *email* (replacing any pending one); return it."""
        code = f"{secrets.randbelow(10**CODE_DIGITS):0{CODE_DIGITS}d}"
        self.store[_key(purpose, email)] = {
            "mac": self._mac(purpose, email, code),
            "expires": self._clock() + self.ttl,
            "attempts": 0,
            "data": dict(data or {}),
        }
        return code

    def check(
        self, email: str, code: Any, *, purpose: str = "signin"
    ) -> Optional[dict]:
        """Spend *code* for *email*; return the data issued with it, else ``None``.

        ``None`` covers every failure alike (no pending code, expired, wrong,
        too many attempts, already spent), so a caller cannot tell them apart.
        """
        key = _key(purpose, email)
        try:
            record = self.store[key]
        except KeyError:
            return None
        if not isinstance(record, dict) or not isinstance(record.get("mac"), str):
            self._drop(key)
            return None
        if self._clock() >= float(record.get("expires") or 0):
            self._drop(key)
            return None
        given = normalize_code(code)
        if len(given) == CODE_DIGITS and hmac.compare_digest(
            record["mac"], self._mac(purpose, email, given)
        ):
            # Spent by whoever deletes it: a concurrent check that loses the
            # race gets None, so a code signs in once.
            try:
                del self.store[key]
            except KeyError:
                return None
            data = record.get("data")
            return dict(data) if isinstance(data, dict) else {}
        attempts = int(record.get("attempts") or 0) + 1
        if attempts >= self.max_attempts:
            self._drop(key)
        else:
            try:
                self.store[key] = {**record, "attempts": attempts}
            except Exception:  # noqa: BLE001 - an unwritable store: fail closed below
                self._drop(key)
        return None

    def discard(self, email: str, *, purpose: str = "signin") -> None:
        """Forget any pending code for *email*."""
        self._drop(_key(purpose, email))

    def _drop(self, key: str) -> None:
        try:
            del self.store[key]
        except Exception:  # noqa: BLE001 - absent or raced
            pass

    # ----- the emailed link -------------------------------------------------

    def link_token(self, email: str, code: str, *, purpose: str = "signin") -> str:
        """A signed token carrying *email* and *code*, for the emailed link."""
        payload = json.dumps({"e": email, "c": code, "p": purpose})
        return sign_cookie(payload, self._signing_key, salt=_LINK_SALT)

    def open_link_token(self, token: str) -> Optional[tuple[str, str, str]]:
        """``(email, code, purpose)`` from a valid, unexpired token, else ``None``."""
        raw = verify_cookie(
            token or "", self._signing_key, max_age=self.ttl, salt=_LINK_SALT
        )
        if not raw:
            return None
        try:
            payload = json.loads(raw)
            return str(payload["e"]), str(payload["c"]), str(payload["p"])
        except (ValueError, KeyError, TypeError):
            return None
