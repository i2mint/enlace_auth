"""``/auth/email/*``, the verify-first ``/auth/register``, and self-service deletion.

Verify before create. No user record is written until the address has proved
it receives mail: ``start`` mails a one-time code, ``verify`` spends it and then
signs in an existing account or creates the new one. That closes the two gaps
of a register-then-verify flow: answering whether an address has an account
(enumeration), and an attacker creating an account for a victim's address
before the victim does (pre-hijacking).

The code is bound to the browser that asked for it. ``start`` sets an HttpOnly
cookie holding a fresh random nonce, the pending code is stored under it, and
``verify`` finds the code only through that cookie (refused when the request
carries it twice). Only the newest code of a browser works. So a sign-up is finished by
the browser that began it: nobody can register a victim's address with their
own password and wait for the victim to verify it, and nobody can sign a
victim's browser into an account of theirs by sending a link. A stranger asking
for codes for an address replaces only their own pending code, never the
owner's.

``start`` answers every address the same way, byte for byte, and does the same
work for each: it always stores a pending code (a decoy that can never verify
for an address the policy refuses, or for an admin account) and always mails in
the background. Only the mail differs: a code, or a short "sign-up here is by
invitation" notice. A submission failing the bot check gets the same answer and
no mail. Rate limits answer 429; they count hits, not accounts.

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

import secrets
import time
from collections.abc import Callable, Iterable, MutableMapping
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from enlace_auth.auth.accounts import open_session
from enlace_auth.auth.cookies import sign_cookie
from enlace_auth.auth.email import EmailSender
from enlace_auth.auth.pages import safe_next
from enlace_auth.auth.passwords import hash_password, password_problem
from enlace_auth.emails import normalize_email, resolve_account
from enlace_auth.ratelimit import RateLimiter, SlidingWindowLimiter
from enlace_auth.signup import pages as signup_pages
from enlace_auth.signup.botcheck import BotCheck, TimedHoneypot
from enlace_auth.signup.codes import PendingCodes
from enlace_auth.signup.policy import SignupPolicy, app_from_next
from enlace_auth.signup.texts import (
    code_email,
    delete_email,
    pick_lang,
    refused_email,
    t,
)

#: NIST SP 800-63B-4: a password that is the only factor needs at least 15.
SIGNUP_MIN_PASSWORD_LEN = 15
#: Longer than any passphrase, short enough that hashing it costs nothing extra.
SIGNUP_MAX_PASSWORD_LEN = 1024
#: The cookie naming the browser a pending code belongs to.
NONCE_COOKIE = "enlace_signup"

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
    verify_global=300,
)


def make_limit_gates(
    rate_limiter: RateLimiter, limits: Optional[dict] = None
) -> tuple[Callable[..., bool], Callable[[str, str], bool]]:
    """``(mail_allowed, verify_allowed)``, each ``(email, client_ip) -> bool``.

    *mail_allowed* (``kind=`` ``signin``, ``reset`` or ``delete``) charges the
    address, the IP and the overall budget of that kind of mail, so flooding one
    kind cannot stop the others. *verify_allowed* charges the address-and-IP pair,
    the IP, and the overall budget of code checks: keyed on the pair, so a
    stranger's wrong guesses do not lock the owner out, and the overall budget
    bounds how many guesses all clients together get. Every key is charged even
    after one is over, or a client at one cap would stop counting against the
    others.

    >>> mail, _ = make_limit_gates(SlidingWindowLimiter({}), {"mail_per_address": 1})
    >>> mail("a@x.io", "1.2.3.4"), mail("a@x.io", "5.6.7.8"), mail("b@x.io", "5.6.7.8")
    (True, False, True)
    >>> mail("a@x.io", "1.2.3.4", kind="reset")
    True
    """
    lim = {**_DEFAULT_LIMITS, **(limits or {})}
    window = lim["window_seconds"]

    def _within(checks: list[tuple[str, int]]) -> bool:
        results = [
            rate_limiter(key, limit=limit, window=window) for key, limit in checks
        ]
        return all(results)

    def mail_allowed(email: str, ip: str, *, kind: str = "signin") -> bool:
        return _within(
            [
                (f"mail:{kind}:addr:{email}", lim["mail_per_address"]),
                (f"mail:{kind}:ip:{ip}", lim["mail_per_ip"]),
                (f"mail:{kind}:all", lim["mail_global"]),
            ]
        )

    def verify_allowed(email: str, ip: str) -> bool:
        return _within(
            [
                (f"verify:addr-ip:{email}:{ip}", lim["verify_per_address"]),
                (f"verify:ip:{ip}", lim["verify_per_ip"]),
                ("verify:all", lim["verify_global"]),
            ]
        )

    return mail_allowed, verify_allowed


def _peer_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


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
    client_ip: Callable[[Request], str] = _peer_host,
    known_apps: Iterable[str] = (),
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
        policy: who may create an account from which app (default: nobody); its
            admin addresses are never created and get no sign-in codes.
        codes: the pending-code store (default: in memory, 10 minutes, 5 tries).
        rate_limiter: ``allow(key, *, limit, window)`` (default: in memory).
        bot_check: ``challenge()`` / ``verify(fields)`` (default: honeypot plus
            a 2-second time-to-submit).
        limits: the counts of ``SignupLimitsConfig`` as a dict.
        client_ip: ``(request) -> str``, the client a rate limit counts (the
            plugin reads ``X-Forwarded-For`` only from a trusted proxy).
        known_apps: app names a sign-up may name, directly or through ``next``.
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
    minutes = max(1, codes.ttl // 60)

    # ----- helpers --------------------------------------------------------

    def _normalized(raw: Optional[str]) -> str:
        try:
            return normalize_email(raw or "")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from None

    def _too_many() -> HTTPException:
        return HTTPException(
            status_code=429, detail="Too many requests. Wait a while, then try again."
        )

    def _wrong_code() -> HTTPException:
        return HTTPException(status_code=400, detail=t("en", "wrong_code"))

    def _app_for(app: Optional[str], next_url: str) -> Optional[str]:
        """The app a sign-up comes from: named, else the one ``next`` is in."""
        return app if app and app in apps else app_from_next(next_url, apps)

    def _base(request: Request) -> str:
        return (public_base_url or str(request.base_url)).rstrip("/")

    def _cookie(response: Response, name: str, value: str, *, max_age: int, path: str):
        attrs = [f"{name}={value}", f"Path={path}", "HttpOnly", f"Max-Age={max_age}"]
        attrs.append("SameSite=Lax")
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))

    def _nonce(request: Request) -> str:
        """The nonce this browser holds; empty when absent, malformed or doubled.

        Never reused by ``start`` (which always mints a fresh one), so a value
        planted before the sign-up began names nothing. A request carrying the
        cookie twice (one planted on another path beside ours) gets none, as
        the server cannot tell which one it set.
        """
        raw = request.headers.get("cookie", "")
        names = [c.split("=", 1)[0].strip() for c in raw.split(";")]
        if names.count(NONCE_COOKIE) != 1:
            return ""
        value = request.cookies.get(NONCE_COOKIE) or ""
        return value if 20 <= len(value) <= 64 and value.isascii() else ""

    def _gate(body: _StartBody, request: Request) -> tuple[str, bool]:
        """``(email, passed)``: the address, and whether to mail it at all.

        The bot check comes before the limits, so a bot's submissions do not use
        up the budget of the address they name.
        """
        email = _normalized(body.email)
        if not bots.verify(body.model_dump()):
            return email, False
        if not _mail_allowed(email, client_ip(request)):
            raise _too_many()
        return email, True

    def _issue_and_mail(
        email: str,
        body: _StartBody,
        request: Request,
        background: BackgroundTasks,
        *,
        extra: Optional[dict] = None,
    ) -> JSONResponse:
        """Store a pending code (a decoy when it must not verify) and mail."""
        next_url = safe_next(body.next)
        app = _app_for(body.app, next_url)
        lang = pick_lang(request.headers.get("accept-language"), explicit=body.lang)
        base = _base(request)
        existing = resolve_account(email, user_store.__contains__)
        # Admin accounts sign in with their password or a provider, never by a
        # mailed code: they are the accounts worth guessing codes for.
        usable = not policy.is_admin(email) and (
            existing is not None or policy.allows(email, app)
        )
        nonce = secrets.token_urlsafe(24)  # fresh: a planted value names nothing
        data = {"app": app, "next": next_url, "lang": lang, **(extra or {})}
        code = codes.issue(email, nonce=nonce, data=data if usable else {"decoy": 1})
        if usable:
            link = f"{base}/auth/email/link#t={codes.link_token(email, code)}"
            subject, text = code_email(
                lang, code=code, link=link, site=base, minutes=minutes
            )
        else:
            subject, text = refused_email(lang, site=base)
        background.add_task(send_email, to=email, subject=subject, body=text)
        response = JSONResponse(ACCEPTED, status_code=202)
        _cookie(response, NONCE_COOKIE, nonce, max_age=codes.ttl, path="/auth")
        return response

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
        email, passed = _gate(body, request)
        if not passed:
            return JSONResponse(ACCEPTED, status_code=202)
        return _issue_and_mail(email, body, request, background)

    @router.post("/register", status_code=202)
    async def register(
        body: _RegisterBody, request: Request, background: BackgroundTasks
    ):
        """Sign up with a password: mails a code; the account is created at verify.

        The password is used only if verify *creates* the account, from the
        browser that sent it (the code is bound to that browser): an existing
        account's password is never changed this way. It is hashed, off the
        event loop, only after the bot check and the rate limits.
        """
        if problem := password_problem(
            body.password, min_length=SIGNUP_MIN_PASSWORD_LEN
        ):
            raise HTTPException(status_code=400, detail=problem)
        if len(body.password) > SIGNUP_MAX_PASSWORD_LEN:
            raise HTTPException(status_code=400, detail="Password is too long.")
        email, passed = _gate(body, request)
        if not passed:
            return JSONResponse(ACCEPTED, status_code=202)
        password_hash = await run_in_threadpool(hash_password, body.password)
        return _issue_and_mail(
            email, body, request, background, extra={"password_hash": password_hash}
        )

    @router.post("/email/verify")
    async def email_verify(
        body: _VerifyBody, request: Request, response: Response
    ) -> dict[str, Any]:
        """Spend a code from the browser that asked for it: sign in, or create."""
        if body.token:
            opened = codes.open_link_token(body.token)
            if opened is None or opened[2] != "signin":
                raise _wrong_code()
            email, code, _ = opened
        else:
            email, code = _normalized(body.email), body.code
        if not _verify_allowed(email, client_ip(request)):
            raise _too_many()
        data = codes.check(email, code, nonce=_nonce(request))
        if data is None or data.get("decoy"):
            raise _wrong_code()
        key = resolve_account(email, user_store.__contains__)
        created = key is None
        if created:
            # Re-checked now: the policy (or the admin list) may have changed
            # since the code was sent.
            if not policy.allows(email, data.get("app")):
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
            on_created = getattr(policy, "on_created", None)
            if callable(on_created):
                on_created(email)
            key = email
        session_id = open_session(session_store, user_store, key)
        _cookie(
            response,
            cookie_name,
            sign_cookie(session_id, signing_key, salt="session"),
            max_age=session_max_age,
            path="/",
        )
        _cookie(response, NONCE_COOKIE, "", max_age=0, path="/auth")
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
        if policy.is_admin(email):
            raise HTTPException(
                status_code=409,
                detail="An admin account is removed by the platform owner, not here.",
            )
        return email

    @router.post("/account/delete/start", status_code=202)
    async def delete_start(request: Request, background: BackgroundTasks):
        """Mail the signed-in account a code that confirms its deletion."""
        email = _deletable_account(request)
        if not _mail_allowed(email, client_ip(request), kind="delete"):
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
        if not _verify_allowed(email, client_ip(request)):
            raise _too_many()
        if codes.check(email, body.code, purpose="delete") is None:
            raise _wrong_code()
        try:
            delete_account(email)
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found") from None
        _cookie(response, cookie_name, "", max_age=0, path="/")
        return {"ok": True, "email": email}

    return router
