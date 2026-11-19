"""``/auth/passkeys/*``: add, list and remove passkeys; sign in; step up; redeem.

Endpoints (every POST and DELETE is CSRF-checked like the rest of ``/auth``,
except ``step-up/redeem``, see below):

- ``GET    /auth/passkeys``                   the account's passkeys and policy
- ``POST   /auth/passkeys/register/options``  creation options (fresh sign-in needed)
- ``POST   /auth/passkeys/register/verify``   ``{credential, name}``: stores the passkey
- ``DELETE /auth/passkeys/{id}``              removes one (fresh sign-in needed)
- ``POST   /auth/passkeys/login/options``     request options for a sign-in by passkey
- ``POST   /auth/passkeys/login/verify``      ``{credential, next?}``: opens a session
- ``POST   /auth/passkeys/step-up/options``   ``{action}``: options bound to the action
- ``POST   /auth/passkeys/step-up/verify``    ``{action, credential}``: ``{proof, ...}``
- ``POST   /auth/passkeys/step-up/redeem``    ``{proof, action}``: spends the proof
- ``GET    /auth/passkeys/passkeys.js``       the browser helper, ``enlacePasskeys``

Adding or removing a passkey needs a session opened within ``fresh_seconds``:
a stolen session cookie should not be enough to plant a passkey or delete the
owner's. The refusal then carries an ``X-Enlace-Reauth: 1`` header so a page
can offer to sign in again. Both mail the account a notice; a removal also ends
the account's other sessions and connector refresh families
(``on_credentials_changed``).

``step-up/redeem`` is called by a backend, not a browser: no cookie
authenticates it, the proof in the body is the credential, so it is exempt from
the CSRF double-submit (the plugin lists it). It answers what the proof proves
(``{email, action, verified_at, passkey}``), once.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from importlib.resources import files
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from pydantic import BaseModel

from enlace_auth.auth.accounts import DISABLED_DETAIL, is_disabled, open_session
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.pages import safe_next
from enlace_auth.passkeys.core import (
    PasskeyError,
    PasskeyPolicy,
    PasskeyService,
    RelyingParty,
)
from enlace_auth.passkeys.texts import t

#: The redeem endpoint, which the plugin exempts from the CSRF check.
REDEEM_PATH = "/auth/passkeys/step-up/redeem"
#: Set on a 403 that a fresh sign-in would turn into a success.
REAUTH_HEADER = "X-Enlace-Reauth"


class _RegisterBody(BaseModel):
    credential: dict
    name: str = ""


class _LoginBody(BaseModel):
    credential: dict
    next: Optional[str] = None


class _ActionBody(BaseModel):
    action: str


class _StepUpBody(BaseModel):
    action: str
    credential: dict


class _RedeemBody(BaseModel):
    proof: str
    action: str


def make_passkey_router(
    *,
    service: PasskeyService,
    session_store,
    user_store,
    signing_key: str,
    relying_party: Callable[[Request], RelyingParty],
    policy: Optional[PasskeyPolicy] = None,
    send_email: Optional[Callable[..., Any]] = None,
    on_credentials_changed: Optional[Callable[..., Any]] = None,
    cookie_name: str = "enlace_session",
    session_max_age: int = 86400,
    secure_cookies: bool = True,
    fresh_seconds: int = 900,
    public_base_url: Optional[str] = None,
    pick_lang: Callable[[Optional[str]], str] = lambda _header: "en",
) -> APIRouter:
    """Build the passkey router. See the module docstring for the endpoints.

    Args:
        service: the ceremonies and records (:class:`PasskeyService`).
        session_store / user_store: the platform's sessions and accounts.
        relying_party: ``(request) -> RelyingParty``; the plugin pins it to the
            platform's public origin, a test may derive it from the request.
        policy: who must sign in by passkey (default: nobody).
        send_email: ``send(to=, subject=, body=)`` for add/remove notices
            (``None``: no notice).
        on_credentials_changed: ``hook(email, *, keep=None)`` run after a
            removal (default: none; the plugin passes the platform's).
        fresh_seconds: how recent a sign-in must be to add or remove a passkey.
        public_base_url: the site named in notices (else the request's base URL).
        pick_lang: ``(accept-language header) -> lang`` for the notices.
    """
    router = APIRouter(prefix="/auth/passkeys")
    policy = policy or PasskeyPolicy(frozenset(), count=service.count)

    def _session(request: Request) -> tuple[Optional[str], Optional[dict]]:
        token = request.cookies.get(cookie_name)
        sid = (
            verify_cookie(token, signing_key, max_age=session_max_age, salt="session")
            if token
            else None
        )
        return sid, (session_store.get(sid) if sid else None)

    def _signed_in(request: Request) -> str:
        email = getattr(request.state, "user_email", None)
        if not email:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return email

    def _fresh(request: Request) -> tuple[str, Optional[str]]:
        """``(email, session id)`` of a session opened within *fresh_seconds*."""
        email = _signed_in(request)
        sid, record = _session(request)
        created = record.get("created_at") if isinstance(record, dict) else None
        if not isinstance(created, (int, float)) or (
            time.time() - created > fresh_seconds
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"For your safety, sign in again (within {fresh_seconds // 60} "
                    "minutes) to add or remove a passkey."
                ),
                headers={REAUTH_HEADER: "1"},
            )
        return email, sid

    def _refused(e: PasskeyError) -> HTTPException:
        return HTTPException(status_code=400, detail=str(e))

    def _notify(request, background, email: str, which: str, name: str) -> None:
        if send_email is None:
            return
        lang = pick_lang(request.headers.get("accept-language"))
        site = (public_base_url or str(request.base_url)).rstrip("/")
        background.add_task(
            send_email,
            to=email,
            subject=t(lang, f"mail_{which}_subject"),
            body=t(lang, f"mail_{which}_body", name=name, email=email, site=site),
        )

    def _set_session_cookie(response: Response, session_id: str) -> None:
        attrs = [
            f"{cookie_name}={sign_cookie(session_id, signing_key, salt='session')}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={session_max_age}",
            "SameSite=Lax",
        ]
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))

    # ----- the browser helper ----------------------------------------------

    script = files("enlace_auth.passkeys").joinpath("passkeys.js").read_text("utf-8")

    @router.get("/passkeys.js", include_in_schema=False)
    async def passkeys_js() -> Response:
        return Response(
            script,
            media_type="text/javascript",
            headers={"Cache-Control": "public, max-age=300"},
        )

    # ----- the account's passkeys ------------------------------------------

    @router.get("")
    async def list_passkeys(request: Request) -> dict[str, Any]:
        """The signed-in account's passkeys, and whether it must use one."""
        email = _signed_in(request)
        return {
            "passkeys": service.list(email),
            "required": policy.requires(email),
            "enforced": policy.enforced(email),
            "enforce_from": policy.enforce_from,
        }

    @router.post("/register/options")
    async def register_options(request: Request) -> dict[str, Any]:
        email, _ = _fresh(request)
        return service.registration_options(email, relying_party(request))

    @router.post("/register/verify")
    async def register_verify(
        body: _RegisterBody, request: Request, background: BackgroundTasks
    ) -> dict[str, Any]:
        email, _ = _fresh(request)
        try:
            view = service.register(
                email, body.credential, relying_party(request), name=body.name
            )
        except PasskeyError as e:
            raise _refused(e) from None
        _notify(request, background, email, "added", view["name"])
        return {"ok": True, "passkey": view}

    @router.delete("/{passkey_id}")
    async def remove_passkey(
        passkey_id: str, request: Request, background: BackgroundTasks
    ) -> dict[str, Any]:
        email, sid = _fresh(request)
        if policy.requires(email) and service.count(email) <= 1:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This account must keep a passkey. Add another one first, "
                    "or ask the platform admin."
                ),
            )
        view = service.remove(email, passkey_id)
        if view is None:
            raise HTTPException(status_code=404, detail="No such passkey.")
        if on_credentials_changed is not None:
            on_credentials_changed(email, keep=sid)
        _notify(request, background, email, "removed", view["name"])
        return {"ok": True, "removed": view}

    # ----- sign-in ----------------------------------------------------------

    @router.post("/login/options")
    async def login_options(request: Request) -> dict[str, Any]:
        return service.login_options(relying_party(request))

    @router.post("/login/verify")
    async def login_verify(
        body: _LoginBody, request: Request, response: Response
    ) -> dict[str, Any]:
        try:
            email = service.login(body.credential, relying_party(request))
        except PasskeyError as e:
            raise _refused(e) from None
        try:
            record = user_store[email]
        except KeyError:
            raise HTTPException(
                status_code=400, detail="This passkey's account no longer exists."
            ) from None
        if is_disabled(record):
            raise HTTPException(status_code=403, detail=DISABLED_DETAIL)
        session_id = open_session(session_store, user_store, email, method="passkey")
        _set_session_cookie(response, session_id)
        return {"ok": True, "email": email, "next": safe_next(body.next)}

    # ----- step-up ----------------------------------------------------------

    @router.post("/step-up/options")
    async def step_up_options(body: _ActionBody, request: Request) -> dict[str, Any]:
        email = _signed_in(request)
        try:
            return service.step_up_options(email, body.action, relying_party(request))
        except PasskeyError as e:
            status = 409 if service.count(email) == 0 else 400
            raise HTTPException(status_code=status, detail=str(e)) from None

    @router.post("/step-up/verify")
    async def step_up_verify(body: _StepUpBody, request: Request) -> dict[str, Any]:
        email = _signed_in(request)
        try:
            return service.step_up(
                email, body.action, body.credential, relying_party(request)
            )
        except PasskeyError as e:
            raise _refused(e) from None

    @router.post("/step-up/redeem")
    async def step_up_redeem(body: _RedeemBody) -> dict[str, Any]:
        try:
            proven = service.redeem(body.proof, body.action)
        except PasskeyError as e:
            raise _refused(e) from None
        try:
            record = user_store[proven["email"]]
        except KeyError:
            raise HTTPException(
                status_code=400, detail="The account behind this proof is gone."
            ) from None
        if is_disabled(record):
            raise HTTPException(status_code=403, detail=DISABLED_DETAIL)
        return {"ok": True, **proven}

    return router
