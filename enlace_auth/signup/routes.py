"""``/auth/email/*``, the verify-first ``/auth/register``, and self-service deletion.

Verify before create. No user record is written until the address has proved
it receives mail: ``start`` mails a one-time code, ``verify`` spends it and then
signs in an existing account or creates the new one. That closes the two gaps
of a register-then-verify flow: answering whether an address has an account
(enumeration), and an attacker creating an account for a victim's address
before the victim does (pre-hijacking).

``start`` answers every address the same way, byte for byte, and mails in the
background so the response time does not depend on the account either. What
differs is only the mail: a code for an existing account or an address the
app's policy admits, a short "sign-up here is by invitation" notice otherwise.
A submission failing the bot check gets the same answer and no mail. Rate
limits answer 429; they count hits, not accounts, so they reveal nothing.

Endpoints, all CSRF-checked like every other ``/auth`` POST:

- ``GET  /auth/email/challenge``     a bot-check token for an API client's form
- ``POST /auth/email/start``         ``{email, app?, next?, lang?, challenge, website}``
- ``POST /auth/email/verify``        ``{email, code}`` or ``{token}`` (the emailed link)
- ``GET  /auth/email/link``          the link's landing page (token in the fragment)
- ``POST /auth/register``            ``{email, password, ...}``: ``start`` that also
  sets a password on the account it creates
- ``POST /auth/account/delete/start``  mails the signed-in account a confirmation code
- ``POST /auth/account/delete``      ``{code}``: deletes it
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, MutableMapping
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from enlace_auth.auth.accounts import open_session
from enlace_auth.auth.cookies import sign_cookie
from enlace_auth.auth.email import EmailSender
from enlace_auth.auth.pages import safe_next
from enlace_auth.auth.passwords import hash_password, password_problem
from enlace_auth.emails import account_spellings, normalize_email, resolve_account
from enlace_auth.ratelimit import RateLimiter, SlidingWindowLimiter
from enlace_auth.signup import pages as signup_pages
from enlace_auth.signup.botcheck import BotCheck, TimedHoneypot
from enlace_auth.signup.codes import PendingCodes
from enlace_auth.signup.policy import SignupPolicy, app_from_next, consume_invite
from enlace_auth.signup.texts import (
    code_email,
    delete_email,
    pick_lang,
    refused_email,
    t,
)

#: NIST SP 800-63B-4: a password that is the only factor needs at least 15.
SIGNUP_MIN_PASSWORD_LEN = 15

#: The one answer ``start`` and ``register`` give to every address.
ACCEPTED = {
    "ok": True,
    "detail": "If this address can sign in here, a code is on its way.",
}

_DEFAULT_LIMITS = dict(
    window_seconds=3600,
    mail_per_address=5,
    mail_per_ip=20,
    mail_global=500,
    verify_per_address=10,
    verify_per_ip=50,
)


def make_limit_gates(
    rate_limiter: RateLimiter, limits: Optional[dict] = None
) -> tuple[Callable[[str, str], bool], Callable[[str, str], bool]]:
    """``(mail_allowed, verify_allowed)``, each ``(email, client_ip) -> bool``.

    *mail_allowed* charges the address, the IP and the global budget of mail
    sent; *verify_allowed* the address and the IP budget of code checks. Every
    key is charged even after one is over, or a client at its per-IP cap would
    stop counting against the per-address one.

    >>> mail, _ = make_limit_gates(SlidingWindowLimiter({}), {"mail_per_address": 1})
    >>> mail("a@x.io", "1.2.3.4"), mail("a@x.io", "5.6.7.8"), mail("b@x.io", "5.6.7.8")
    (True, False, True)
    """
    lim = {**_DEFAULT_LIMITS, **(limits or {})}
    window = lim["window_seconds"]

    def _within(checks: list[tuple[str, int]]) -> bool:
        results = [
            rate_limiter(key, limit=limit, window=window) for key, limit in checks
        ]
        return all(results)

    def mail_allowed(email: str, ip: str) -> bool:
        return _within(
            [
                (f"mail:addr:{email}", lim["mail_per_address"]),
                (f"mail:ip:{ip}", lim["mail_per_ip"]),
                ("mail:all", lim["mail_global"]),
            ]
        )

    def verify_allowed(email: str, ip: str) -> bool:
        return _within(
            [
                (f"verify:addr:{email}", lim["verify_per_address"]),
                (f"verify:ip:{ip}", lim["verify_per_ip"]),
            ]
        )

    return mail_allowed, verify_allowed


class _StartBody(BaseModel):
    email: str
    app: Optional[str] = None
    next: Optional[str] = None
    lang: Optional[str] = None
    challenge: str = ""
    website: str = ""


class _RegisterBody(_StartBody):
    password: str


class _VerifyBody(BaseModel):
    email: Optional[str] = None
    code: Optional[str] = None
    token: Optional[str] = None


class _DeleteBody(BaseModel):
    code: str


def make_signup_router(
    *,
    user_store: MutableMapping,
    session_store,
    signing_key: str,
    send_email: EmailSender,
    policy: Optional[SignupPolicy] = None,
    codes: Optional[PendingCodes] = None,
    rate_limiter: Optional[RateLimiter] = None,
    bot_check: Optional[BotCheck] = None,
    limits: Optional[dict] = None,
    known_apps: Iterable[str] = (),
    admin_emails: Iterable[str] = (),
    delete_account: Optional[Callable[[str], None]] = None,
    cookie_name: str = "enlace_session",
    session_max_age: int = 86400,
    secure_cookies: bool = True,
    public_base_url: Optional[str] = None,
    terms_version: Optional[str] = None,
) -> APIRouter:
    """Build the sign-up router. See the module docstring for the endpoints.

    Args:
        user_store / session_store: the platform's account records and sessions.
        signing_key: HMAC key for codes, link tokens, challenges and cookies.
        send_email: delivers the mails (``to=, subject=, body=``; never raises).
        policy: who may create an account from which app (default: nobody).
        codes: the pending-code store (default: in memory, 10 minutes, 5 tries).
        rate_limiter: ``allow(key, *, limit, window)`` (default: in memory).
        bot_check: ``challenge()`` / ``verify(fields)`` (default: honeypot plus
            a 2-second time-to-submit).
        limits: the counts of ``SignupLimitsConfig`` as a dict.
        known_apps: app names a sign-up may name, directly or through ``next``.
        admin_emails: addresses never created, nor deleted, by this router.
        delete_account: ``delete(email)``, removing an account and its data;
            ``None`` leaves the deletion endpoints unmounted.
        public_base_url: the origin put in mailed links. Without it the link is
            built from the request's ``Host``, which the requester controls.
        terms_version: stored on each account created, as the terms accepted.
    """
    router = APIRouter(prefix="/auth")
    policy = policy or SignupPolicy(default="closed")
    codes = codes or PendingCodes({}, signing_key=signing_key)
    _mail_allowed, _verify_allowed = make_limit_gates(
        rate_limiter or SlidingWindowLimiter({}), limits
    )
    bots: BotCheck = bot_check or TimedHoneypot(signing_key)
    apps = frozenset(known_apps)
    admins = frozenset(s for e in admin_emails for s in account_spellings(e))
    minutes = max(1, codes.ttl // 60)

    # ----- helpers --------------------------------------------------------

    def _normalized(raw: Optional[str]) -> str:
        try:
            return normalize_email(raw or "")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

    def _ip(request: Request) -> str:
        # The ASGI server's view of the client: behind a proxy, uvicorn rewrites
        # it from X-Forwarded-For only when the proxy is in forwarded_allow_ips,
        # so this is never a header a client chose.
        return request.client.host if request.client else "unknown"

    def _too_many() -> HTTPException:
        return HTTPException(
            status_code=429, detail="Too many requests. Wait a while, then try again."
        )

    def _app_for(app: Optional[str], next_url: str) -> Optional[str]:
        """The app a sign-up comes from: named, else the one ``next`` is in."""
        return app if app and app in apps else app_from_next(next_url, apps)

    def _base(request: Request) -> str:
        return (public_base_url or str(request.base_url)).rstrip("/")

    def _set_session_cookie(response: Response, session_id: str) -> None:
        signed = sign_cookie(session_id, signing_key, salt="session")
        attrs = [
            f"{cookie_name}={signed}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={session_max_age}",
            "SameSite=Lax",
        ]
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))

    def _start(
        body: _StartBody,
        request: Request,
        background: BackgroundTasks,
        *,
        extra: Optional[dict] = None,
    ) -> JSONResponse:
        """The shared body of ``start`` and ``register``: one answer for all."""
        email = _normalized(body.email)
        accepted = JSONResponse(ACCEPTED, status_code=202)
        # Before the limits: a bot's submissions must not use up the budget of
        # the address it names, or a dumb script could keep a victim's codes away.
        if not bots.verify(body.model_dump()):
            return accepted
        if not _mail_allowed(email, _ip(request)):
            raise _too_many()
        next_url = safe_next(body.next)
        app = _app_for(body.app, next_url)
        lang = pick_lang(request.headers.get("accept-language"), explicit=body.lang)
        base = _base(request)
        if resolve_account(email, user_store.__contains__) is not None or policy.allows(
            email, app
        ):
            data = {"app": app, "next": next_url, "lang": lang, **(extra or {})}
            code = codes.issue(email, data=data)
            link = f"{base}/auth/email/link#t={codes.link_token(email, code)}"
            subject, text = code_email(
                lang, code=code, link=link, site=base, minutes=minutes
            )
        else:
            subject, text = refused_email(lang, site=base)
        background.add_task(send_email, to=email, subject=subject, body=text)
        return accepted

    # ----- sign-in and sign-up --------------------------------------------

    @router.get("/email/challenge")
    async def email_challenge() -> dict[str, Any]:
        """A fresh bot-check token for a form that is not rendered by this server."""
        return {
            "challenge": bots.challenge(),
            "min_seconds": getattr(bots, "min_seconds", 0),
        }

    @router.post("/email/start", status_code=202)
    async def email_start(
        body: _StartBody, request: Request, background: BackgroundTasks
    ):
        """Mail a one-time code. The same 202 for every address."""
        return _start(body, request, background)

    @router.post("/register", status_code=202)
    async def register(
        body: _RegisterBody, request: Request, background: BackgroundTasks
    ):
        """Sign up with a password: mails a code, and the account is created at verify.

        The password is checked and hashed before anything else, for every
        address, so neither the answer nor its timing depends on the account.
        It is used only if verify *creates* the account: an existing account's
        password is never changed this way.
        """
        if problem := password_problem(
            body.password, min_length=SIGNUP_MIN_PASSWORD_LEN
        ):
            raise HTTPException(status_code=400, detail=problem)
        password_hash = hash_password(body.password)
        return _start(body, request, background, extra={"password_hash": password_hash})

    @router.post("/email/verify")
    async def email_verify(
        body: _VerifyBody, request: Request, response: Response
    ) -> dict[str, Any]:
        """Spend a code: sign in, or create the account and sign in."""
        if body.token:
            opened = codes.open_link_token(body.token)
            if opened is None or opened[2] != "signin":
                raise HTTPException(status_code=400, detail=t("en", "wrong_code"))
            email, code, _ = opened
        else:
            email, code = _normalized(body.email), body.code
        if not _verify_allowed(email, _ip(request)):
            raise _too_many()
        data = codes.check(email, code)
        if data is None:
            raise HTTPException(status_code=400, detail=t("en", "wrong_code"))
        key = resolve_account(email, user_store.__contains__)
        created = key is None
        if created:
            # Re-checked now: the policy (or an admin list) may have changed
            # since the code was sent, and an admin address is never created.
            if email in admins or not policy.allows(email, data.get("app")):
                raise HTTPException(
                    status_code=403,
                    detail=t(data.get("lang") or "en", "signup_closed"),
                )
            now = time.time()
            password_hash = data.get("password_hash")
            record = {
                "password_hash": password_hash,
                "created_at": now,
                "created_via": "register" if password_hash else "email-code",
                "email_verified_at": now,
            }
            if data.get("app"):
                record["signup_app"] = data["app"]
            if terms_version:
                record["terms_version"] = terms_version
                record["terms_accepted_at"] = now
            user_store[email] = record
            invites = getattr(policy, "invites", None)
            if invites is not None:
                consume_invite(invites, email)
            key = email
        session_id = open_session(session_store, user_store, key)
        _set_session_cookie(response, session_id)
        return {
            "ok": True,
            "email": key,
            "created": created,
            "next": safe_next(data.get("next")),
        }

    @router.get("/email/link", response_class=HTMLResponse, include_in_schema=False)
    async def email_link(request: Request) -> HTMLResponse:
        """The emailed link's page. A GET spends nothing (mail scanners fetch links)."""
        lang = pick_lang(request.headers.get("accept-language"))
        return HTMLResponse(
            signup_pages.render_link_page(lang=lang),
            headers={"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"},
        )

    # ----- self-service deletion ------------------------------------------

    if delete_account is None:
        return router

    def _deletable_account(request: Request) -> str:
        email = getattr(request.state, "user_email", None)
        if not email:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if email.strip().lower() in admins:
            raise HTTPException(
                status_code=409,
                detail="An admin account is removed by the platform owner, not here.",
            )
        return email

    @router.post("/account/delete/start", status_code=202)
    async def delete_start(request: Request, background: BackgroundTasks):
        """Mail the signed-in account a code that confirms its deletion."""
        email = _deletable_account(request)
        if not _mail_allowed(email, _ip(request)):
            raise _too_many()
        lang = pick_lang(request.headers.get("accept-language"))
        code = codes.issue(email, purpose="delete")
        subject, text = delete_email(
            lang, code=code, site=_base(request), minutes=minutes
        )
        background.add_task(send_email, to=email, subject=subject, body=text)
        return {"ok": True}

    @router.post("/account/delete")
    async def delete_confirm(
        body: _DeleteBody, request: Request, response: Response
    ) -> dict[str, Any]:
        """Delete the signed-in account, given the code mailed to it."""
        email = _deletable_account(request)
        if not _verify_allowed(email, _ip(request)):
            raise _too_many()
        if codes.check(email, body.code, purpose="delete") is None:
            raise HTTPException(status_code=400, detail=t("en", "wrong_code"))
        try:
            delete_account(email)
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found") from None
        response.headers.append(
            "set-cookie",
            f"{cookie_name}=; Path=/; Max-Age=0; SameSite=Lax"
            + ("; Secure" if secure_cookies else ""),
        )
        return {"ok": True, "email": email}

    return router
