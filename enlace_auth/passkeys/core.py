"""Passkey ceremonies, the step-up proof, and the passkey-required policy.

No web framework here: :class:`PasskeyService` takes and returns JSON-ready
values, so the HTTP router, the CLI and a test drive the same code. The WebAuthn
checks themselves are py_webauthn's (BSD-3-Clause, a dependency), imported on
first use so a platform that never turns passkeys on never loads it.

Three ceremonies, one challenge format. A challenge is 40 bytes:
``nonce(16) | expiry(8) | mac(16)``, the mac an HMAC of the purpose, the account
and (for a step-up) the action, under the platform's signing key. Nothing is
stored when a challenge is issued (the sign-in page asks for one on every view);
the answer carries it back inside ``clientDataJSON``, the server recomputes the
mac from what it expects, and spends the challenge once through *claim_once*.
So a step-up challenge commits to the action: an answer signed for one action
cannot be presented for another.

A verified step-up returns a **proof**: a signed token, valid for
``proof_ttl`` seconds, that names the account, the action and (for a step-up a
backend requested) the audience. An app or a connector backend redeems it once
(:meth:`PasskeyService.redeem`), stating the action it is about to perform; a
proof for another action or audience, an expired one or a spent one is refused.
Proofs and requests are method-agnostic (:mod:`enlace_auth.auth.step_up`); the
passkey is one method that mints them.

Records. A credential is stored under ``sha256(credential id)`` (hex, a safe
file name) as ``{email, credential_id, public_key, user_handle, name,
created_at, device_type, backed_up, transports}``. Its use (``sign_count``,
``last_used_at``) is kept in a second mapping, so a sign-in that races a removal
writes an orphan usage record, never a resurrected credential. The WebAuthn user
handle is ``HMAC(signing key, email)``: opaque, stable, and kept on each
credential so a sign-in compares against what was registered.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable, Iterable, MutableMapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from enlace_auth.auth.step_up import (  # noqa: E402 - re-exported
    MAX_ACTION_LEN,
    StepUpError,
    StepUpProofs,
    challenge_binding,
)

#: Longest name a passkey may be given.
MAX_NAME_LEN = 60
_CHALLENGE_LEN = 40
_PURPOSES = ("register", "login", "step-up")


class PasskeyError(ValueError):
    """A passkey request that cannot be honoured; the message is safe to show."""


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    """Unpadded base64url, the encoding WebAuthn JSON uses.

    >>> b64url(b"\\xfb\\xff")
    '-_8'
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    """Inverse of :func:`b64url`; raises :class:`PasskeyError` on garbage.

    >>> unb64url("-_8")
    b'\\xfb\\xff'
    """
    if not isinstance(text, str) or len(text) > 8192:
        raise PasskeyError("Malformed passkey response.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise PasskeyError("Malformed passkey response.") from None


def passkey_key(credential_id: bytes) -> str:
    """The store key (and public id) of a credential: sha256 of its raw id, hex."""
    return hashlib.sha256(credential_id).hexdigest()


def clean_action(action: Any) -> str:
    """The action text of a step-up, checked: 1..300 printable characters.

    >>> clean_action("  start job: repo, title ")
    'start job: repo, title'
    >>> clean_action("two\\nlines")  # doctest: +ELLIPSIS
    Traceback (most recent call last):
      ...
    enlace_auth.passkeys.core.PasskeyError: An action is one line of at most 300 ...
    """
    from enlace_auth.auth import step_up

    try:
        return step_up.clean_action(action)
    except StepUpError as e:
        raise PasskeyError(str(e)) from None


def clean_name(name: Any) -> str:
    """A passkey's display name: printable, at most 60 characters, never empty.

    >>> clean_name(""), clean_name("  Touch ID on the Mac ")
    ('Passkey', 'Touch ID on the Mac')
    """
    text = name.strip() if isinstance(name, str) else ""
    text = "".join(c for c in text if c.isprintable())[:MAX_NAME_LEN].strip()
    return text or "Passkey"


def memory_claim(*, keep_seconds: float = 3600.0) -> Callable[[str], bool]:
    """``claim(key) -> bool``: True the first time a key is claimed, then False.

    In-process only: right for one worker and for tests. A platform running
    several worker processes injects a cross-process claim instead (the plugin
    uses the same ``O_EXCL`` file claim as the OAuth server). Claims older than
    *keep_seconds* are forgotten, which is safe because every claimed thing
    (a challenge, a proof) expires well before.

    >>> claim = memory_claim()
    >>> claim("a"), claim("a"), claim("b")
    (True, False, True)
    """
    held: dict[str, float] = {}

    def claim(key: str) -> bool:
        now = time.monotonic()
        for k in [k for k, at in held.items() if now - at > keep_seconds]:
            del held[k]
        if key in held:
            return False
        held[key] = now
        return True

    return claim


@dataclass(frozen=True)
class RelyingParty:
    """Who the passkeys belong to: the RP ID, its display name, accepted origins.

    The RP ID is a host name every accepted origin is on or under, so one
    passkey covers every app served from those origins.

    >>> rp = RelyingParty("example.com", "Example", ("https://apps.example.com",))
    >>> RelyingParty("example.com", "x", ("https://evil.com",))
    Traceback (most recent call last):
      ...
    ValueError: origin 'https://evil.com' is not on 'example.com' or a subdomain of it
    """

    id: str
    name: str
    origins: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.id or "/" in self.id or ":" in self.id:
            raise ValueError(f"rp_id {self.id!r} must be a bare host name")
        if not self.origins:
            raise ValueError("a relying party needs at least one origin")
        for origin in self.origins:
            parts = urlsplit(origin)
            host = (parts.hostname or "").lower()
            secure = parts.scheme == "https" or (
                parts.scheme == "http" and host in ("localhost", "127.0.0.1")
            )
            if not secure or parts.path not in ("", "/") or parts.query:
                raise ValueError(
                    f"origin {origin!r} must be https://host (http only on localhost)"
                )
            if host != self.id and not host.endswith("." + self.id):
                raise ValueError(
                    f"origin {origin!r} is not on {self.id!r} or a subdomain of it"
                )

    @classmethod
    def for_origin(cls, origin: str, *, rp_id: Optional[str] = None, name=None):
        """The relying party of one origin (RP ID: its host, unless given).

        >>> RelyingParty.for_origin("https://apps.example.com/").id
        'apps.example.com'
        """
        origin = origin.rstrip("/")
        host = urlsplit(origin).hostname or ""
        return cls(rp_id or host, name or rp_id or host, (origin,))


# --------------------------------------------------------------------------
# the service
# --------------------------------------------------------------------------


def _webauthn():
    """py_webauthn, imported on first use."""
    import webauthn  # noqa: F401  (raises ImportError without the extra)

    return webauthn


class PasskeyService:
    """Register, sign in, step up, redeem and remove passkeys.

    Args:
        credentials: credential records, ``sha256(id) hex -> dict``.
        signing_key: the platform's HMAC key (challenges, proofs, user handles).
        usage: ``sha256(id) hex -> {sign_count, last_used_at}`` (default: a dict).
        claim_once: ``claim(sha256 hex) -> bool``, True once per key; spends
            challenges and proofs (default: :func:`memory_claim`).
        challenge_ttl / proof_ttl / request_ttl: lifetimes in seconds (a
            backend's step-up request must outlive a sign-in on the way).
        clock: ``() -> epoch seconds``; tests pass a fake.
    """

    def __init__(
        self,
        credentials: MutableMapping,
        *,
        signing_key: str,
        usage: Optional[MutableMapping] = None,
        claim_once: Optional[Callable[[str], bool]] = None,
        challenge_ttl: int = 300,
        proof_ttl: int = 120,
        request_ttl: int = 900,
        clock: Callable[[], float] = time.time,
    ):
        self.credentials = credentials
        self.usage = {} if usage is None else usage
        self._key = signing_key.encode("utf-8")
        self._claim = claim_once or memory_claim(
            keep_seconds=max(challenge_ttl, proof_ttl) * 2
        )
        self.challenge_ttl = challenge_ttl
        self.proof_ttl = proof_ttl
        self._clock = clock
        #: Proofs and requests, shared with any other step-up method.
        self.proofs = StepUpProofs(
            signing_key,
            claim_once=self._claim,
            ttl=proof_ttl,
            # Long enough to sign in first (a password, then an emailed code).
            request_ttl=request_ttl,
            clock=lambda: self._clock(),
        )

    # ----- records --------------------------------------------------------

    def user_handle(self, email: str) -> bytes:
        """The WebAuthn user handle of an account: opaque, stable, 32 bytes."""
        return hmac.new(
            self._key, b"enlace-passkey-user|" + email.encode("utf-8"), hashlib.sha256
        ).digest()

    def records(
        self, email: Optional[str] = None, *, rp_id: Optional[str] = None
    ) -> list[tuple[str, dict]]:
        """``(key, record)`` of every readable credential (of *email*, if given).

        With *rp_id*, only the credentials made for that relying party: a passkey
        made for another RP ID can no longer sign in, so it must not count.
        A damaged record is skipped, never raised: the store is hand-editable.
        """
        out = []
        for key in list(self.credentials):
            try:
                record = self.credentials[key]
            except KeyError:
                continue
            if not isinstance(record, dict) or not isinstance(record.get("email"), str):
                continue
            if rp_id is not None and record.get("rp_id", rp_id) != rp_id:
                continue
            if email is None or record["email"] == email:
                out.append((key, record))
        return out

    def count(self, email: str, *, rp_id: Optional[str] = None) -> int:
        """How many passkeys *email* has (for *rp_id*, if given)."""
        return len(self.records(email, rp_id=rp_id))

    def synced(self, email: str, *, rp_id: Optional[str] = None) -> bool:
        """Whether one of *email*'s passkeys is synced (backed up by its provider).

        A synced passkey lives on every device of its keychain (iCloud Keychain,
        Google Password Manager), so losing one device does not lose it.
        """
        return any(r.get("backed_up") for _, r in self.records(email, rp_id=rp_id))

    def describe(self, key: str, record: dict) -> dict:
        """The public view of one passkey (no key material)."""
        try:
            used = self.usage.get(key)
        except Exception:  # noqa: BLE001 - a listing must not fail on bookkeeping
            used = None
        used = used if isinstance(used, dict) else {}
        return {
            "id": key,
            "name": record.get("name") or "Passkey",
            "created_at": record.get("created_at"),
            "last_used_at": used.get("last_used_at"),
            "synced": bool(record.get("backed_up")),
            "device_type": record.get("device_type"),
        }

    def list(self, email: str) -> list[dict]:
        """The passkeys of *email*, oldest first."""
        views = [self.describe(k, r) for k, r in self.records(email)]

        def _when(view):
            at = view.get("created_at")
            return at if isinstance(at, (int, float)) else 0

        return sorted(views, key=_when)

    def remove(self, email: str, key: str) -> Optional[dict]:
        """Remove the passkey *key* of *email*; return its view, or None."""
        try:
            record = self.credentials[key]
        except KeyError:
            return None
        if not isinstance(record, dict) or record.get("email") != email:
            return None
        view = self.describe(key, record)
        try:
            del self.credentials[key]
        except KeyError:
            return None  # removed meanwhile by someone else
        self._forget_usage(key)
        return view

    def remove_account(self, email: str) -> int:
        """Remove every passkey of *email*; return how many went."""
        removed = 0
        for key, _ in self.records(email):
            if self.remove(email, key) is not None:
                removed += 1
        return removed

    def _forget_usage(self, key: str) -> None:
        try:
            del self.usage[key]
        except KeyError:
            pass

    # ----- challenges -----------------------------------------------------

    def _mac(self, purpose: str, binding: bytes, body: bytes) -> bytes:
        msg = b"|".join([b"enlace-passkey", purpose.encode(), body, binding])
        return hmac.new(self._key, msg, hashlib.sha256).digest()[:16]

    @staticmethod
    def _binding(email: str = "", action: str = "") -> bytes:
        return email.encode("utf-8") + b"\x00" + action.encode("utf-8")

    def _challenge(self, purpose: str, binding: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        expires = int(self._clock() + self.challenge_ttl).to_bytes(8, "big")
        body = nonce + expires
        return body + self._mac(purpose, binding, body)

    def _challenge_of(self, credential: dict) -> bytes:
        """The challenge an answer was signed over, read from its clientDataJSON."""
        response = credential.get("response")
        if not isinstance(response, dict):
            raise PasskeyError("Malformed passkey response.")
        try:
            client_data = json.loads(unb64url(response.get("clientDataJSON", "")))
            return unb64url(client_data["challenge"])
        except (ValueError, KeyError, TypeError):
            raise PasskeyError("Malformed passkey response.") from None

    def _check_challenge(self, challenge: bytes, purpose: str, binding: bytes):
        """Raise unless *challenge* is ours, for this purpose and binding, unexpired."""
        if len(challenge) != _CHALLENGE_LEN:
            raise PasskeyError("This passkey request is not valid. Try again.")
        body, mac = challenge[:24], challenge[24:]
        if not hmac.compare_digest(mac, self._mac(purpose, binding, body)):
            raise PasskeyError("This passkey request is not valid. Try again.")
        if int.from_bytes(body[16:24], "big") < self._clock():
            raise PasskeyError("This passkey request has expired. Try again.")

    def _spend(self, challenge: bytes) -> None:
        if not self._claim(hashlib.sha256(b"challenge|" + challenge).hexdigest()):
            raise PasskeyError("This passkey request was already used. Try again.")

    def _timeout_ms(self) -> int:
        return self.challenge_ttl * 1000

    @staticmethod
    def _as_json(options) -> dict:
        return json.loads(_webauthn().options_to_json(options))

    def _descriptors(self, email: str):
        from webauthn.helpers.structs import PublicKeyCredentialDescriptor

        out = []
        for _, record in self.records(email):
            try:
                out.append(
                    PublicKeyCredentialDescriptor(
                        id=unb64url(record["credential_id"]),
                        transports=_transports(record.get("transports")),
                    )
                )
            except (PasskeyError, KeyError):
                continue
        return out

    # ----- registration ---------------------------------------------------

    def registration_options(self, email: str, rp: RelyingParty) -> dict:
        """``PublicKeyCredentialCreationOptionsJSON`` for adding a passkey to *email*.

        A discoverable credential with user verification (a passkey proper),
        excluding the account's existing ones so a device is not enrolled twice.
        """
        wa = _webauthn()
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria,
            ResidentKeyRequirement,
            UserVerificationRequirement,
        )

        options = wa.generate_registration_options(
            rp_id=rp.id,
            rp_name=rp.name,
            user_name=email,
            user_id=self.user_handle(email),
            user_display_name=email,
            challenge=self._challenge("register", self._binding(email)),
            timeout=self._timeout_ms(),
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=self._descriptors(email),
        )
        return self._as_json(options)

    def register(
        self, email: str, credential: Any, rp: RelyingParty, *, name: Any = ""
    ) -> dict:
        """Verify a registration answer and store the passkey; return its view."""
        wa = _webauthn()
        credential = _as_dict(credential)
        challenge = self._challenge_of(credential)
        self._check_challenge(challenge, "register", self._binding(email))
        try:
            verified = wa.verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=rp.id,
                expected_origin=list(rp.origins),
                require_user_verification=True,
            )
        except Exception as e:  # noqa: BLE001 - every library failure is a refusal
            raise PasskeyError(f"The passkey could not be verified ({e}).") from None
        self._spend(challenge)
        key = passkey_key(verified.credential_id)
        if key in self.credentials:
            raise PasskeyError("This passkey is already registered.")
        now = self._clock()
        device_type = verified.credential_device_type
        response = credential.get("response") or {}
        record = {
            "email": email,
            "rp_id": rp.id,
            "credential_id": b64url(verified.credential_id),
            "public_key": b64url(verified.credential_public_key),
            "user_handle": b64url(self.user_handle(email)),
            "name": clean_name(name),
            "created_at": now,
            "device_type": getattr(device_type, "value", device_type),
            "backed_up": bool(verified.credential_backed_up),
            "transports": [
                t for t in (response.get("transports") or []) if isinstance(t, str)
            ][:8],
            "aaguid": verified.aaguid,
        }
        self.credentials[key] = record
        self.usage[key] = {"sign_count": verified.sign_count, "last_used_at": None}
        return self.describe(key, record)

    # ----- assertions (sign-in and step-up) --------------------------------

    def login_options(self, rp: RelyingParty) -> dict:
        """``PublicKeyCredentialRequestOptionsJSON`` for a sign-in by any passkey.

        No ``allowCredentials``: the authenticator offers the account's passkey
        (and the browser can show it in the email field's autofill).
        """
        wa = _webauthn()
        from webauthn.helpers.structs import UserVerificationRequirement

        options = wa.generate_authentication_options(
            rp_id=rp.id,
            challenge=self._challenge("login", self._binding()),
            timeout=self._timeout_ms(),
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return self._as_json(options)

    def step_up_options(
        self,
        email: str,
        action: Any,
        rp: RelyingParty,
        *,
        audience: Optional[str] = None,
    ) -> dict:
        """Request options for confirming *action* with one of *email*'s passkeys.

        The challenge commits to the action and the audience. Raises
        :class:`PasskeyError` when the account has no passkey.
        """
        wa = _webauthn()
        from webauthn.helpers.structs import UserVerificationRequirement

        action = clean_action(action)
        allowed = self._descriptors(email)
        if not allowed:
            raise PasskeyError("This account has no passkey yet.")
        bound = challenge_binding(action, audience)
        options = wa.generate_authentication_options(
            rp_id=rp.id,
            challenge=self._challenge("step-up", self._binding(email, bound)),
            timeout=self._timeout_ms(),
            allow_credentials=allowed,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        out = {**self._as_json(options), "action": action}
        if audience is not None:
            out["audience"] = audience
        return out

    def _assert(
        self,
        credential: Any,
        rp: RelyingParty,
        *,
        purpose: str,
        email: Optional[str] = None,
        action: str = "",
    ) -> tuple[str, dict]:
        """Verify an assertion; return ``(key, record)`` of the passkey used."""
        wa = _webauthn()
        credential = _as_dict(credential)
        challenge = self._challenge_of(credential)
        key = passkey_key(unb64url(credential.get("rawId") or credential.get("id")))
        try:
            record = self.credentials[key]
        except KeyError:
            raise PasskeyError("This passkey is not registered here.") from None
        if not isinstance(record, dict) or not isinstance(record.get("email"), str):
            raise PasskeyError("This passkey is not registered here.")
        if email is not None and record["email"] != email:
            raise PasskeyError("This passkey belongs to another account.")
        binding = self._binding(record["email"] if purpose != "login" else "", action)
        self._check_challenge(challenge, purpose, binding)
        returned_handle = (credential.get("response") or {}).get("userHandle")
        if returned_handle or purpose == "login":
            if not returned_handle or not hmac.compare_digest(
                str(returned_handle), str(record.get("user_handle") or "")
            ):
                raise PasskeyError("This passkey belongs to another account.")
        try:
            used = self.usage.get(key)
        except Exception:  # noqa: BLE001
            used = None
        sign_count = used.get("sign_count", 0) if isinstance(used, dict) else 0
        try:
            verified = wa.verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=rp.id,
                expected_origin=list(rp.origins),
                credential_public_key=unb64url(record["public_key"]),
                credential_current_sign_count=int(sign_count or 0),
                require_user_verification=True,
            )
        except Exception as e:  # noqa: BLE001 - every library failure is a refusal
            raise PasskeyError(f"The passkey could not be verified ({e}).") from None
        self._spend(challenge)
        try:
            self.usage[key] = {
                "sign_count": verified.new_sign_count,
                "last_used_at": self._clock(),
            }
        except Exception:  # noqa: BLE001 - bookkeeping must never block a sign-in
            pass
        return key, record

    def login(self, credential: Any, rp: RelyingParty) -> str:
        """Verify a sign-in assertion; return the account it signs in."""
        _, record = self._assert(credential, rp, purpose="login")
        return record["email"]

    def step_up(
        self,
        email: str,
        action: Any,
        credential: Any,
        rp: RelyingParty,
        *,
        audience: Optional[str] = None,
    ) -> dict:
        """Verify a step-up for *action*; return ``{proof, action, expires_in}``.

        With *audience* (a step-up a backend requested), the challenge must have
        committed to it and the proof redeems only where it is named.
        """
        action = clean_action(action)
        key, _ = self._assert(
            credential,
            rp,
            purpose="step-up",
            email=email,
            action=challenge_binding(action, audience),
        )
        try:
            return self.proofs.mint(
                email, action, method="passkey", audience=audience, ref=key
            )
        except StepUpError as e:
            raise PasskeyError(str(e)) from None

    def _passkey_still_there(self, payload: dict) -> Optional[str]:
        """Why a passkey proof no longer stands (its passkey was removed), or None."""
        if (payload.get("m") or "passkey") != "passkey":
            return None
        key = payload.get("k")
        try:
            record = self.credentials[key] if isinstance(key, str) else None
        except KeyError:
            record = None
        if not isinstance(record, dict) or record.get("email") != payload.get("e"):
            return "The passkey behind this proof was removed."
        return None

    def redeem(
        self,
        proof: Any,
        action: Any,
        *,
        email: Any,
        audience: Optional[str] = None,
        methods: Optional[Iterable[str]] = None,
    ) -> dict:
        """Spend a step-up proof for *action* by *email*; return what it proves.

        ``{email, action, audience, verified_at, method, passkey}``. Raises
        :class:`PasskeyError` for a forged, expired, spent, other-action,
        other-account or other-audience proof, one confirmed by a method outside
        *methods*, or one whose passkey has since been removed. The caller names
        the account it expects, so "someone confirmed" can never pass for "the
        owner confirmed".
        """
        try:
            proven = self.proofs.redeem(
                proof,
                action,
                email=email,
                audience=audience,
                methods=methods,
                still_valid=self._passkey_still_there,
            )
        except StepUpError as e:
            raise PasskeyError(str(e)) from None
        ref = proven.pop("ref", None)
        if proven["method"] == "passkey":
            record = self.credentials.get(ref) if isinstance(ref, str) else None
            name = record.get("name") if isinstance(record, dict) else None
            proven["passkey"] = name or "Passkey"
        return proven


def _as_dict(credential: Any) -> dict:
    if isinstance(credential, str):
        try:
            credential = json.loads(credential)
        except ValueError:
            raise PasskeyError("Malformed passkey response.") from None
    if not isinstance(credential, dict):
        raise PasskeyError("Malformed passkey response.")
    return credential


def _transports(values: Any):
    from webauthn.helpers.structs import AuthenticatorTransport

    known = {t.value: t for t in AuthenticatorTransport}
    picked = [known[v] for v in (values or []) if isinstance(v, str) and v in known]
    return picked or None


# --------------------------------------------------------------------------
# the policy
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PasskeyPolicy:
    """Which accounts must sign in with a passkey.

    *required* holds account keys (lower-case, every spelling already listed).
    The rule applies to an account once it has *enforce_from* passkeys, or one
    synced passkey (*synced*: it is on every device of its keychain); below
    that it may still sign in by its other methods, so it can enrol (a lockout
    guard: one lost device must not lock an account out).

    >>> p = PasskeyPolicy(frozenset({"a@x.io"}), count=lambda e: 2, enforce_from=2)
    >>> p.refusal("a@x.io", "password") is not None, p.refusal("a@x.io", "passkey")
    (True, None)
    >>> one = PasskeyPolicy(frozenset({"a@x.io"}), count=lambda e: 1)
    >>> one.refusal("a@x.io", "password")  # below enforce_from: not yet
    >>> p.refusal("b@x.io", "password")
    """

    required: frozenset
    count: Callable[[str], int]
    enforce_from: int = 2
    synced: Callable[[str], bool] = lambda _email: False

    def requires(self, email: str) -> bool:
        return bool(email) and email.lower() in self.required

    def enforced(self, email: str) -> bool:
        """True when *email* is required to use a passkey right now."""
        if not self.requires(email):
            return False
        try:
            n = self.count(email)
            return n >= self.enforce_from or (n >= 1 and bool(self.synced(email)))
        except Exception:  # noqa: BLE001 - an unreadable store fails closed
            return True

    def refusal(self, email: str, method: str) -> Optional[str]:
        """``None`` to admit a sign-in by *method*, else the reason to refuse."""
        if method == "passkey" or not self.enforced(email):
            return None
        return "This account signs in with a passkey."


def required_accounts(entries: Iterable[str]) -> frozenset:
    """Lower-cased account keys from already-expanded entries.

    >>> sorted(required_accounts(["A@x.io", "b@x.io", ""]))
    ['a@x.io', 'b@x.io']
    """
    return frozenset(e.lower() for e in entries if isinstance(e, str) and e)


__all__: Sequence[str] = [
    "MAX_ACTION_LEN",
    "PasskeyError",
    "PasskeyPolicy",
    "PasskeyService",
    "RelyingParty",
    "b64url",
    "clean_action",
    "clean_name",
    "memory_claim",
    "passkey_key",
    "required_accounts",
    "unb64url",
]
