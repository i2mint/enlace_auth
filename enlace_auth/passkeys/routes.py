"""``/auth/passkeys/*``: add, list and remove passkeys; sign in; step up; redeem.

Endpoints (every POST and DELETE is CSRF-checked like the rest of ``/auth``,
except ``step-up/redeem``, see below):

- ``GET    /auth/passkeys``                   the account's passkeys and policy
- ``POST   /auth/passkeys/register/options``  creation options (fresh sign-in needed)
- ``POST   /auth/passkeys/register/verify``   ``{credential, name}``: stores the passkey
- ``DELETE /auth/passkeys/{id}``              removes one (fresh sign-in needed)
- ``POST   /auth/passkeys/login/options``     request options for a sign-in by passkey
- ``POST   /auth/passkeys/login/verify``      ``{credential, next?}``: opens a session
- ``POST   /auth/passkeys/step-up/request``   a backend's ``{email, action, audience,
  return_url?}`` with ``Authorization: Bearer <audience key>``: ``{request,
  confirm_url, expires_in}``
- ``GET    /auth/passkeys/confirm?r=<request>`` the platform's confirmation page
- ``POST   /auth/passkeys/step-up/options``   ``{action}`` or ``{request}``: options
  bound to the action (and the request's audience)
- ``POST   /auth/passkeys/step-up/verify``    ``{action | request, credential}``:
  ``{proof, ...}``
- ``POST   /auth/passkeys/step-up/redeem``    ``{proof, action, email, audience?,
  methods?}``: spends it
- ``GET    /auth/passkeys/passkeys.js``       the browser helper, ``enlacePasskeys``

Adding or removing a passkey needs a session opened within ``fresh_seconds``:
a stolen session cookie should not be enough to plant a passkey or delete the
owner's. The refusal then carries an ``X-Enlace-Reauth: 1`` header so a page
can offer to sign in again. Both mail the account a notice; a removal also ends
the account's other sessions and connector refresh families
(``on_credentials_changed``).

``step-up/redeem`` is called by a backend, not a browser: no cookie
authenticates it, the proof in the body is the credential, so it is exempt from
the CSRF double-submit (the plugin lists it). The caller names the action AND the
account it expects; the answer (``{email, action, audience, verified_at, method,
passkey}``) comes once.

Two ways to ask for a step-up (i2mint/enlace_auth#95). A page may still call
``step-up/options {action}`` itself; such a proof carries no audience, so a
backend that names its audience refuses it. The strong way: the backend creates
the request (``step-up/request``, CSRF-exempt, authenticated by the audience key
``enlace-auth step-up-key AUDIENCE`` prints), and the browser opens the
platform's ``/auth/passkeys/confirm`` page, which shows the backend's action and
audience and mints a proof only that audience redeems. A page script never
chooses the text, and the page refuses to be framed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from importlib.resources import files
from typing import Any, Optional
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel

from enlace_auth.auth.accounts import DISABLED_DETAIL, is_disabled, open_session
from enlace_auth.auth.cookie_policy import CookiePolicy, request_host
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.pages import safe_next
from enlace_auth.auth.step_up import StepUpError
from enlace_auth.passkeys.core import (
    PasskeyError,
    PasskeyPolicy,
    PasskeyService,
    RelyingParty,
)
from enlace_auth.passkeys.texts import t

#: The redeem endpoint, which the plugin exempts from the CSRF check.
REDEEM_PATH = "/auth/passkeys/step-up/redeem"
#: The backend's request endpoint, exempt likewise (a bearer key, no cookie).
REQUEST_PATH = "/auth/passkeys/step-up/request"
#: Headers of the confirmation page: never framed, never cached.
_CONFIRM_HEADERS = {
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}
#: Set on a 403 that a fresh sign-in would turn into a success.
REAUTH_HEADER = "X-Enlace-Reauth"


class _RegisterBody(BaseModel):
    credential: dict
    name: str = ""


class _LoginBody(BaseModel):
    credential: dict
    next: Optional[str] = None


class _ActionBody(BaseModel):
    action: Optional[str] = None
    request: Optional[str] = None


class _StepUpBody(BaseModel):
    action: Optional[str] = None
    request: Optional[str] = None
    credential: dict


class _RedeemBody(BaseModel):
    proof: str
    action: str
    email: str
    audience: Optional[str] = None
    methods: Optional[list[str]] = None


class _RequestBody(BaseModel):
    email: str
    action: str
    audience: str
    return_url: Optional[str] = None


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
    cookie_domain: Optional[str] = None,
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
        cookie_domain: ``[auth] cookie_domain`` (#94), for the session cookie a
            passkey sign-in sets and the ``next`` it may return to.
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

    def _rp(request: Request) -> RelyingParty:
        try:
            return relying_party(request)
        except ValueError as e:  # e.g. a dev server reached over plain http
            raise HTTPException(
                status_code=503, detail=f"Passkeys are misconfigured here: {e}"
            ) from None

    def _fresh(request: Request) -> tuple[str, Optional[str]]:
        """``(email, session id)`` of a session fit to change the account's passkeys.

        Opened within *fresh_seconds*, and, once the account has a passkey,
        opened WITH a passkey: otherwise whoever holds the password (or the
        mailbox, or a fresh cookie) could plant a passkey of their own and then
        confirm step-ups as the owner.
        """
        email = _signed_in(request)
        sid, record = _session(request)
        record = record if isinstance(record, dict) else {}
        created = record.get("created_at")
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
        if record.get("method") != "passkey" and service.count(email) > 0:
            raise HTTPException(
                status_code=403,
                detail=(
                    "This account has a passkey: sign in again with it to add or "
                    "remove one. On a new device, sign in with the passkey on your "
                    "phone (scan the code your browser shows)."
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

    cookies = CookiePolicy(secure=secure_cookies, domain=cookie_domain)

    def _set_session_cookie(
        request: Request, response: Response, session_id: str
    ) -> None:
        cookies.set_cookie(
            response,
            cookie_name,
            sign_cookie(session_id, signing_key, salt="session"),
            max_age=session_max_age,
            host=request_host(request.headers),
        )

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
        return service.registration_options(email, _rp(request))

    @router.post("/register/verify")
    async def register_verify(
        body: _RegisterBody, request: Request, background: BackgroundTasks
    ) -> dict[str, Any]:
        email, sid = _fresh(request)
        was_enforced = policy.enforced(email)
        try:
            view = service.register(
                email, body.credential, _rp(request), name=body.name
            )
        except PasskeyError as e:
            raise _refused(e) from None
        if (
            not was_enforced
            and policy.enforced(email)
            and on_credentials_changed is not None
        ):
            # The account just became passkey-only: sessions and connector
            # tokens opened by a password must not outlive that.
            on_credentials_changed(email, keep=sid)
        _notify(request, background, email, "added", view["name"])
        return {"ok": True, "passkey": view}

    @router.delete("/{passkey_id}")
    async def remove_passkey(
        passkey_id: str, request: Request, background: BackgroundTasks
    ) -> dict[str, Any]:
        email, sid = _fresh(request)
        if policy.requires(email) and service.count(email) <= policy.enforce_from:
            # Removing one would let the password back in: only the admin's
            # CLI (remove-passkey) may take a required account below the rule.
            raise HTTPException(
                status_code=409,
                detail=(
                    "This account must keep its passkeys. Add another one first, "
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
        return service.login_options(_rp(request))

    @router.post("/login/verify")
    async def login_verify(
        body: _LoginBody, request: Request, response: Response
    ) -> dict[str, Any]:
        try:
            email = service.login(body.credential, _rp(request))
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
        _set_session_cookie(request, response, session_id)
        next_url = safe_next(body.next, cookie_domain=cookie_domain)
        return {"ok": True, "email": email, "next": next_url}

    # ----- step-up ----------------------------------------------------------

    def _what_to_confirm(
        email: str, body: _ActionBody | _StepUpBody
    ) -> tuple[Any, Optional[str]]:
        """``(action, audience)``: the page's action, or a backend's request.

        A page cannot name an audience: only a request signed with the
        audience's key carries one. A request is for one account only.
        """
        if body.request is None:
            return body.action, None
        try:
            wanted = service.proofs.read_request(body.request)
        except StepUpError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None
        if wanted["email"] != email.lower():
            raise HTTPException(
                status_code=403, detail="This confirmation is for another account."
            )
        return wanted["action"], wanted["audience"]

    @router.post("/step-up/request")
    async def step_up_request(body: _RequestBody, request: Request) -> dict[str, Any]:
        """A backend asks the account holder to confirm *action* for its audience."""
        scheme, _, key = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not key:
            raise HTTPException(status_code=401, detail="An audience key is needed.")
        back = None
        if body.return_url:
            back = safe_next(body.return_url, default="")
            if not back:
                raise HTTPException(
                    status_code=400, detail="return_url must be a path on this site."
                )
        try:
            request_id = service.proofs.create_request(
                email=body.email,
                action=body.action,
                audience=body.audience,
                key=key.strip(),
                return_url=back,
            )
        except StepUpError as e:
            status = 401 if "key" in str(e) else 400
            raise HTTPException(status_code=status, detail=str(e)) from None
        base = (public_base_url or str(request.base_url)).rstrip("/")
        return {
            "request": request_id,
            "confirm_url": f"{base}/auth/passkeys/confirm?r={quote(request_id)}",
            "expires_in": service.proofs.request_ttl,
        }

    @router.get("/confirm", response_class=HTMLResponse, include_in_schema=False)
    async def confirm_page(request: Request) -> Response:
        """The platform's page for confirming a backend's request."""
        from enlace_auth.auth.pages import _page, render_notice_page
        from enlace_auth.passkeys.pages import render_confirm_section

        lang = pick_lang(request.headers.get("accept-language"))
        request_id = request.query_params.get("r", "")
        try:
            wanted = service.proofs.read_request(request_id)
        except StepUpError:
            page = render_notice_page(
                title=t(lang, "confirm_title"),
                heading=t(lang, "confirm_title"),
                message=t(lang, "confirm_invalid"),
                links=[],
            )
            return HTMLResponse(page, status_code=400, headers=_CONFIRM_HEADERS)
        here = f"/auth/passkeys/confirm?r={quote(request_id)}"
        current = getattr(request.state, "user_email", None)
        if not current:
            return RedirectResponse(
                f"/auth/login?login_required=1&next={quote(here, safe='')}",
                status_code=303,
                headers=_CONFIRM_HEADERS,
            )
        if current.lower() != wanted["email"]:
            page = render_notice_page(
                title=t(lang, "confirm_title"),
                heading=t(lang, "confirm_title"),
                message=t(
                    lang,
                    "confirm_other_account",
                    email=wanted["email"],
                    current=current,
                ),
                links=[
                    (
                        t(lang, "confirm_switch", email=wanted["email"]),
                        f"/auth/login?next={quote(here, safe='')}",
                        True,
                    )
                ],
            )
            return HTMLResponse(page, status_code=403, headers=_CONFIRM_HEADERS)
        body = render_confirm_section(
            lang=lang,
            request_id=request_id,
            action=wanted["action"],
            audience=wanted["audience"],
            return_url=wanted["return_url"] or "",
        )
        return HTMLResponse(
            _page(t(lang, "confirm_title"), body, lang=lang), headers=_CONFIRM_HEADERS
        )

    @router.post("/step-up/options")
    async def step_up_options(body: _ActionBody, request: Request) -> dict[str, Any]:
        email = _signed_in(request)
        action, audience = _what_to_confirm(email, body)
        try:
            return service.step_up_options(
                email, action, _rp(request), audience=audience
            )
        except PasskeyError as e:
            status = 409 if service.count(email) == 0 else 400
            raise HTTPException(status_code=status, detail=str(e)) from None

    @router.post("/step-up/verify")
    async def step_up_verify(body: _StepUpBody, request: Request) -> dict[str, Any]:
        email = _signed_in(request)
        action, audience = _what_to_confirm(email, body)
        try:
            return service.step_up(
                email, action, body.credential, _rp(request), audience=audience
            )
        except PasskeyError as e:
            raise _refused(e) from None

    @router.post("/step-up/redeem")
    async def step_up_redeem(body: _RedeemBody) -> dict[str, Any]:
        try:
            proven = service.redeem(
                body.proof,
                body.action,
                email=body.email,
                audience=body.audience,
                methods=body.methods,
            )
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
