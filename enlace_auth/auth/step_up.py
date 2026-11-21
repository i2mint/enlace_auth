"""Step-up proofs and step-up requests, independent of how the person confirmed.

A **proof** says "this account confirmed this action, for this audience, by this
method, just now". It is a signed token, valid for ``ttl`` seconds and spendable
once. Today the passkey ceremony mints them (``method="passkey"``); a TOTP or an
emailed code could mint them beside it without changing a redeeming backend
(i2mint/enlace_auth#95).

An **audience** names who may redeem a proof (an app, a connector backend). A
proof minted for one audience never redeems at another, and a proof minted with
no audience never redeems at a backend that names one, so a backend that states
its audience accepts only proofs made for it.

A **request** is how a backend asks for a confirmation without letting any page
choose the words the person sees. The backend signs ``{email, action, audience,
return_url}`` with its audience key (:func:`audience_key`, which the operator
gives it: ``enlace-auth step-up-key AUDIENCE``) and posts it to
``/auth/passkeys/step-up/request``; the platform answers with a request id, and
the browser opens the platform's own confirmation page for it, which shows the
action and the audience and mints the proof. A page script never names the text.

>>> proofs = StepUpProofs("k" * 32, clock=lambda: 1000)
>>> act, who = "app: delete 7", "ann@x.io"
>>> minted = proofs.mint(who, act, method="passkey", audience="app")
>>> proofs.redeem(minted["proof"], act, email=who, audience="app")["method"]
'passkey'
>>> proofs.redeem(minted["proof"], act, email=who, audience="app")
Traceback (most recent call last):
  ...
enlace_auth.auth.step_up.StepUpError: This step-up proof was already used.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import Callable, Iterable
from typing import Any, Optional

#: Longest action description a step-up accepts (it is shown to the user).
MAX_ACTION_LEN = 300
#: Longest audience name.
MAX_AUDIENCE_LEN = 64
_PROOF_SALT = "enlace-passkey-step-up"  # kept: proofs minted before #95 still read
_REQUEST_SALT = "enlace-step-up-request"


class StepUpError(ValueError):
    """A step-up proof or request is refused; the message is safe to show."""


def clean_action(action: Any) -> str:
    """The action text of a step-up, checked: 1..300 printable characters.

    >>> clean_action("  start job: repo, title ")
    'start job: repo, title'
    """
    text = action.strip() if isinstance(action, str) else ""
    if not text or len(text) > MAX_ACTION_LEN or not text.isprintable():
        raise StepUpError(
            f"An action is one line of at most {MAX_ACTION_LEN} printable characters."
        )
    return text


def clean_audience(audience: Any) -> Optional[str]:
    """An audience name (letters, digits, ``._-``, at most 64), or None for none.

    >>> clean_audience("my_app"), clean_audience(None), clean_audience("")
    ('my_app', None, None)
    """
    if audience is None or audience == "":
        return None
    if (
        not isinstance(audience, str)
        or len(audience) > MAX_AUDIENCE_LEN
        or not all(c.isascii() and (c.isalnum() or c in "._-") for c in audience)
    ):
        raise StepUpError(
            "An audience is a name of letters, digits, '.', '_' or '-' "
            f"(at most {MAX_AUDIENCE_LEN})."
        )
    return audience


def audience_key(signing_key: str, audience: str) -> str:
    """The secret a backend proves it speaks for *audience* with.

    Derived from the platform's signing key, so nothing is stored; rotating the
    signing key rotates every audience key.

    >>> len(audience_key("k" * 32, "my_app"))
    64
    """
    audience = clean_audience(audience)
    if audience is None:
        raise StepUpError("An audience key needs an audience.")
    return hmac.new(
        signing_key.encode("utf-8"),
        b"enlace-step-up-audience|" + audience.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def challenge_binding(action: str, audience: Optional[str]) -> str:
    """The text a step-up challenge commits to: the action, and its audience.

    The NUL cannot occur in a clean action or audience, so the pair is unambiguous,
    and an audience-less binding is the action alone (as before #95).
    """
    return action if audience is None else f"{audience}\x00{action}"


class StepUpProofs:
    """Mint and redeem step-up proofs; sign and read step-up requests.

    Args:
        signing_key: the platform's HMAC key.
        claim_once: ``claim(key) -> bool``, True the first time; spends proofs
            (default: in-process, right for one worker and tests).
        ttl: how long a proof is valid, in seconds.
        request_ttl: how long a step-up request is valid, in seconds.
        clock: ``() -> epoch seconds``.
    """

    def __init__(
        self,
        signing_key: str,
        *,
        claim_once: Optional[Callable[[str], bool]] = None,
        ttl: int = 120,
        request_ttl: int = 300,
        clock: Callable[[], float] = time.time,
    ):
        self._signing_key = signing_key
        self._key = signing_key.encode("utf-8")
        if claim_once is None:
            from enlace_auth.passkeys.core import memory_claim

            claim_once = memory_claim(keep_seconds=max(ttl, request_ttl) * 2)
        self._claim = claim_once
        self.ttl = ttl
        self.request_ttl = request_ttl
        self._clock = clock

    def _serializer(self, salt: str):
        from itsdangerous import URLSafeSerializer

        return URLSafeSerializer(self._key, salt=salt)

    def _load(self, token: Any, salt: str, what: str) -> dict:
        from itsdangerous import BadSignature

        if not isinstance(token, str) or len(token) > 4096:
            raise StepUpError(f"Not a step-up {what}.")
        try:
            payload = self._serializer(salt).loads(token)
        except BadSignature:
            raise StepUpError(f"Not a step-up {what}.") from None
        if not isinstance(payload, dict):
            raise StepUpError(f"Not a step-up {what}.")
        return payload

    # ----- proofs -----------------------------------------------------------

    def mint(
        self,
        email: str,
        action: Any,
        *,
        method: str,
        audience: Optional[str] = None,
        ref: Optional[str] = None,
    ) -> dict:
        """A proof that *email* confirmed *action* by *method*.

        *ref* is the method's own reference (a passkey's key), returned on
        redemption so the method can check it still stands.
        """
        action = clean_action(action)
        audience = clean_audience(audience)
        payload = {
            "e": email,
            "a": action,
            "m": method,
            "j": secrets.token_urlsafe(16),
            "t": self._clock(),
        }
        if ref is not None:
            payload["k"] = ref
        if audience is not None:
            payload["u"] = audience
        out = {
            "proof": self._serializer(_PROOF_SALT).dumps(payload),
            "action": action,
            "expires_in": self.ttl,
        }
        if audience is not None:
            out["audience"] = audience
        return out

    def redeem(
        self,
        proof: Any,
        action: Any,
        *,
        email: Any,
        audience: Optional[str] = None,
        methods: Optional[Iterable[str]] = None,
        still_valid: Optional[Callable[[dict], Optional[str]]] = None,
    ) -> dict:
        """Spend *proof* for *action* by *email*; return what it proves.

        ``{email, action, audience, verified_at, method, ref}``. Refused (raises
        :class:`StepUpError`): a forged, expired or spent proof; another action,
        account or audience (a proof with an audience redeems only where that
        audience is named, and one without only where none is); a method outside
        *methods*; or what *still_valid(payload)* objects to (a removed passkey).
        """
        action = clean_action(action)
        audience = clean_audience(audience)
        payload = self._load(proof, _PROOF_SALT, "proof")
        at = payload.get("t")
        fresh = isinstance(at, (int, float)) and 0 <= self._clock() - at <= self.ttl
        if not fresh:
            raise StepUpError("This step-up proof has expired.")
        if not hmac.compare_digest(str(payload.get("a", "")), action):
            raise StepUpError("This step-up proof is for another action.")
        if not isinstance(email, str) or not hmac.compare_digest(
            str(payload.get("e", "")).lower(), email.strip().lower()
        ):
            raise StepUpError("This step-up proof is for another account.")
        if (payload.get("u") or None) != audience:
            raise StepUpError("This step-up proof is for another audience.")
        method = payload.get("m") or "passkey"  # minted before #95: passkey only
        if methods is not None and method not in set(methods):
            raise StepUpError(f"This step-up was confirmed by {method}, refused here.")
        if still_valid is not None and (problem := still_valid(payload)):
            raise StepUpError(problem)
        jti = str(payload.get("j"))
        if not self._claim(hashlib.sha256(b"proof|" + jti.encode()).hexdigest()):
            raise StepUpError("This step-up proof was already used.")
        return {
            "email": payload["e"],
            "action": action,
            "audience": audience,
            "verified_at": at,
            "method": method,
            "ref": payload.get("k"),
        }

    # ----- requests ---------------------------------------------------------

    def create_request(
        self,
        *,
        email: str,
        action: Any,
        audience: Any,
        key: str,
        return_url: Optional[str] = None,
    ) -> str:
        """A signed step-up request, for a backend holding *audience*'s key.

        The request id carries the action, so the confirmation page shows what
        the backend wrote and nothing a page chose.
        """
        audience = clean_audience(audience)
        if audience is None:
            raise StepUpError("A step-up request names its audience.")
        if not isinstance(key, str) or not hmac.compare_digest(
            key, audience_key(self._signing_key, audience)
        ):
            raise StepUpError("Not this audience's key.")
        if not isinstance(email, str) or "@" not in email:
            raise StepUpError("A step-up request names the account that confirms.")
        payload = {
            "e": email.strip().lower(),
            "a": clean_action(action),
            "u": audience,
            "t": self._clock(),
            "n": secrets.token_urlsafe(8),
        }
        if return_url:
            payload["r"] = str(return_url)
        return self._serializer(_REQUEST_SALT).dumps(payload)

    def read_request(self, request_id: Any) -> dict:
        """``{email, action, audience, return_url}`` of a valid, unexpired request."""
        payload = self._load(request_id, _REQUEST_SALT, "request")
        at = payload.get("t")
        if not isinstance(at, (int, float)) or not (
            0 <= self._clock() - at <= self.request_ttl
        ):
            raise StepUpError("This confirmation request has expired.")
        try:
            return {
                "email": str(payload["e"]),
                "action": clean_action(payload["a"]),
                "audience": clean_audience(payload["u"]),
                "return_url": payload.get("r"),
            }
        except KeyError:
            raise StepUpError("Not a step-up request.") from None
