"""Auth HTTP routes: register, login, logout, shared-login, csrf, recovery.

This router serves both the JSON API (``POST /auth/login`` etc., consumed by
app frontends) and the browser-facing HTML pages (``GET /auth/login``,
``GET /auth/account``, the password-recovery screens) so the platform is usable
from a bare URL with no app frontend in the way.

The three ways a password can be set, and who can use each:

- ``GET /auth/account`` — a signed-in user changing their own.
- ``GET /auth/forgot-password`` — a locked-out user, *if* SMTP is configured.
- ``enlace-auth reset-link`` — an admin, handing a link over out-of-band.

The last exists because the middle one needs a mail server. Without one the
forgot-password page says so plainly instead of promising an email that is only
written to the log.

OAuth routes live in ``enlace.auth.oauth`` and are attached separately so the
Authlib dependency stays lazy.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

from enlace_auth.auth import pages
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.email import EmailSender, make_console_sender
from enlace_auth.auth.passwords import hash_password, verify_password
from enlace_auth.auth.reset_tokens import (
    DEFAULT_EMAIL_TTL,
    mint_reset_token,
    reset_url,
    verify_reset_token,
)
from enlace_auth.auth.sessions import SessionStore


class _LoginBody(BaseModel):
    email: EmailStr
    password: str


class _RegisterBody(BaseModel):
    email: EmailStr
    password: str


class _SharedLoginBody(BaseModel):
    app: str
    password: str


class _ChangeOwnPasswordBody(BaseModel):
    old_password: str
    new_password: str


class _ResetRequestBody(BaseModel):
    email: EmailStr


class _ResetConfirmBody(BaseModel):
    token: str
    new_password: str


# Minimum new-password length enforced server-side (the forms also check it).
_MIN_PASSWORD_LEN = 8


def make_auth_router(
    *,
    session_store: SessionStore,
    user_store,  # MutableMapping[email -> {password_hash, created_at}]
    signing_key: str,
    cookie_name: str = "enlace_session",
    session_max_age: int = 86400,
    secure_cookies: bool = True,
    shared_password_for: Callable[[str], Optional[str]] = lambda _: None,
    can_register: Callable[[str], bool] = lambda _: False,
    send_email: Optional[EmailSender] = None,
    reset_token_max_age: int = DEFAULT_EMAIL_TTL,
) -> APIRouter:
    """Build a FastAPI router exposing ``/auth/*`` endpoints.

    Args:
        session_store / user_store: backing stores.
        signing_key: HMAC key for session, CSRF, shared, and reset tokens.
        cookie_name / session_max_age / secure_cookies: session-cookie policy.
        shared_password_for: maps an app id to its shared-password hash.
        can_register: predicate gating self-registration by email.
        send_email: delivers password-reset emails. ``None`` means no delivery
            channel is configured: the flow falls back to the console sender
            (which logs the link) *and* the forgot-password page says so, rather
            than telling the user to check an inbox nothing was sent to.
        reset_token_max_age: lifetime of an emailed password-reset link, in
            seconds (default 30 minutes). Links an admin mints by hand carry
            their own, longer lifetime — see ``enlace_auth.auth.reset_tokens``.
    """
    router = APIRouter(prefix="/auth")
    # Distinguish "no delivery channel configured" from "a sender was wired":
    # the page copy must not promise an email the platform cannot send.
    email_delivery_configured = send_email is not None
    email_sender: EmailSender = send_email or make_console_sender()

    def _set_session_cookie(
        response: Response, value: str, *, max_age: int, salt: str, name: str
    ):
        signed = sign_cookie(value, signing_key, salt=salt)
        attrs = [
            f"{name}={signed}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={max_age}",
            "SameSite=Lax",
        ]
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))

    def _clear_cookie(response: Response, name: str):
        response.headers.append(
            "set-cookie",
            f"{name}=; Path=/; Max-Age=0; SameSite=Lax"
            + ("; Secure" if secure_cookies else ""),
        )

    @router.post("/register")
    async def register(body: _RegisterBody, response: Response) -> dict[str, Any]:
        email = body.email.lower()
        if email in user_store:
            raise HTTPException(status_code=409, detail="Email already registered")
        if not can_register(email):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Registration is closed. Ask the platform admin to create "
                    "an account, or to add your email to the registration "
                    "allowlist."
                ),
            )
        user_store[email] = {
            "password_hash": hash_password(body.password),
            "created_at": time.time(),
        }
        session_id = session_store.create(user_id=email, email=email)
        _set_session_cookie(
            response,
            session_id,
            max_age=session_max_age,
            salt="session",
            name=cookie_name,
        )
        return {"ok": True, "email": email}

    @router.post("/login")
    async def login(body: _LoginBody, response: Response) -> dict[str, Any]:
        email = body.email.lower()
        try:
            record = user_store[email]
        except KeyError:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not isinstance(record, dict) or "password_hash" not in record:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not verify_password(record["password_hash"], body.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        session_id = session_store.create(user_id=email, email=email)
        _set_session_cookie(
            response,
            session_id,
            max_age=session_max_age,
            salt="session",
            name=cookie_name,
        )
        return {"ok": True, "email": email}

    @router.post("/logout")
    async def logout(request: Request, response: Response) -> dict[str, Any]:
        token = request.cookies.get(cookie_name)
        if token:
            session_id = verify_cookie(token, signing_key, salt="session")
            if session_id:
                session_store.delete(session_id)
        _clear_cookie(response, cookie_name)
        return {"ok": True}

    @router.get("/shared-login", response_class=HTMLResponse, include_in_schema=False)
    async def shared_login_page(request: Request):
        """Serve the shared-password form for a ``protected:shared`` app.

        Renders a 404 notice when ``?app=`` is missing or names an app that
        isn't shared-password protected. Skipped (303 to ``next``) if a valid
        shared cookie for the app is already present.
        """
        app = request.query_params.get("app", "")
        next_url = pages.safe_next(request.query_params.get("next"))
        if not app or shared_password_for(app) is None:
            return HTMLResponse(
                pages.render_notice_page(
                    title="App not found",
                    heading="No such shared app",
                    message=(
                        "This link points to an app that doesn't exist or "
                        "isn't protected by a shared password."
                    ),
                    links=[("Back to apps", "/", True)],
                ),
                status_code=404,
            )
        existing = request.cookies.get(f"shared_auth_{app}")
        if existing and verify_cookie(existing, signing_key, salt=f"shared:{app}"):
            return RedirectResponse(next_url, status_code=303)
        return HTMLResponse(pages.render_shared_login_page(app=app, next_url=next_url))

    @router.post("/shared-login")
    async def shared_login(
        body: _SharedLoginBody, response: Response
    ) -> dict[str, Any]:
        stored_hash = shared_password_for(body.app)
        if not stored_hash:
            raise HTTPException(status_code=404, detail=f"Unknown app '{body.app}'")
        if not verify_password(stored_hash, body.password):
            raise HTTPException(status_code=401, detail="Invalid password")
        token = sign_cookie("1", signing_key, salt=f"shared:{body.app}")
        cookie_name_shared = f"shared_auth_{body.app}"
        attrs = [
            f"{cookie_name_shared}={token}",
            "Path=/",
            "HttpOnly",
            f"Max-Age={session_max_age}",
            "SameSite=Lax",
        ]
        if secure_cookies:
            attrs.append("Secure")
        response.headers.append("set-cookie", "; ".join(attrs))
        return {"ok": True, "app": body.app}

    @router.get("/whoami")
    async def whoami(request: Request) -> dict[str, Any]:
        return {
            "user_id": getattr(request.state, "user_id", None),
            "email": getattr(request.state, "user_email", None),
        }

    @router.post("/me/password")
    async def change_own_password(
        body: _ChangeOwnPasswordBody, request: Request
    ) -> dict[str, Any]:
        email = (getattr(request.state, "user_email", None) or "").lower()
        if not email:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Same floor as the reset flow — otherwise the two ways to set a
        # password disagree on what counts as one.
        if len(body.new_password) < _MIN_PASSWORD_LEN:
            raise HTTPException(
                status_code=400,
                detail=f"Password must be at least {_MIN_PASSWORD_LEN} characters.",
            )
        try:
            record = user_store[email]
        except KeyError:
            raise HTTPException(status_code=404, detail="User not found")
        if not isinstance(record, dict) or "password_hash" not in record:
            raise HTTPException(status_code=500, detail="Corrupt user record")
        if not verify_password(record["password_hash"], body.old_password):
            raise HTTPException(status_code=401, detail="Invalid current password")
        record = dict(record)
        record["password_hash"] = hash_password(body.new_password)
        user_store[email] = record
        return {"ok": True, "email": email}

    # ----- Password recovery ---------------------------------------------

    def _verify_reset_token(token: str) -> tuple[Optional[str], Optional[dict]]:
        """Return ``(email, record)`` for a valid token, else ``(None, None)``."""
        return verify_reset_token(token, signing_key=signing_key, user_store=user_store)

    @router.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_page(request: Request):
        """Serve the sign-in form. Honors ``?next=``; skipped if already in."""
        next_url = pages.safe_next(request.query_params.get("next"))
        if getattr(request.state, "user_id", None):
            return RedirectResponse(next_url, status_code=303)
        return HTMLResponse(pages.render_login_page(next_url=next_url))

    @router.get("/account", response_class=HTMLResponse, include_in_schema=False)
    async def account_page(request: Request):
        """Serve the signed-in user's 'change my password' form.

        The browser-facing counterpart to ``POST /auth/me/password``, which
        until now had no UI — leaving a user who knew their password with no
        way to change it, and an admin with no answer but to set one for them.
        Unauthenticated visitors are bounced to sign-in and returned here.
        """
        email = getattr(request.state, "user_email", None)
        if not email:
            return RedirectResponse(
                "/auth/login?next=%2Fauth%2Faccount", status_code=303
            )
        return HTMLResponse(pages.render_account_page(email=email))

    @router.get(
        "/forgot-password", response_class=HTMLResponse, include_in_schema=False
    )
    async def forgot_password_page() -> HTMLResponse:
        """Serve the 'request a reset link' form.

        ``email_delivery_configured`` is a property of the *deployment*, not of
        any account, so telling the user about it leaks nothing — unlike the
        submit response, which must stay identical for known and unknown
        addresses.
        """
        return HTMLResponse(
            pages.render_forgot_page(
                email_delivery_configured=email_delivery_configured
            )
        )

    @router.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
    async def reset_password_page(request: Request) -> HTMLResponse:
        """Serve the 'set a new password' form, or a notice if the link is bad."""
        token = request.query_params.get("token", "")
        email, _ = _verify_reset_token(token)
        if email is None:
            return HTMLResponse(
                pages.render_notice_page(
                    title="Reset link invalid",
                    heading="This reset link is invalid or expired",
                    message=(
                        "Password-reset links expire quickly and work only "
                        "once. Request a fresh one to continue."
                    ),
                    links=[
                        ("Request a new link", "/auth/forgot-password", True),
                        ("Back to sign in", "/auth/login", False),
                    ],
                ),
                status_code=400,
            )
        return HTMLResponse(pages.render_reset_page(token=token))

    @router.post("/password-reset/request")
    async def password_reset_request(
        body: _ResetRequestBody, request: Request
    ) -> dict[str, Any]:
        """Email a password-reset link.

        Always returns ``{"ok": true}`` whether or not the address has an
        account — otherwise the response would leak which emails are
        registered.
        """
        email = body.email.lower()
        try:
            record = user_store[email]
        except KeyError:
            record = None
        if isinstance(record, dict):
            token = mint_reset_token(
                record=record,
                email=email,
                signing_key=signing_key,
                ttl_seconds=reset_token_max_age,
            )
            base = str(request.base_url).rstrip("/")
            link = reset_url(base, token)
            minutes = max(1, reset_token_max_age // 60)
            email_sender(
                to=email,
                subject="Reset your password",
                body=(
                    "Someone asked to reset the password for your account "
                    f"on {base}.\n\n"
                    f"Open this link within {minutes} minutes to choose a "
                    f"new password:\n\n"
                    f"  {link}\n\n"
                    "If you didn't request this, ignore this email — your "
                    "password stays unchanged."
                ),
            )
        return {"ok": True}

    @router.post("/password-reset/confirm")
    async def password_reset_confirm(
        body: _ResetConfirmBody, response: Response
    ) -> dict[str, Any]:
        """Set a new password from a valid reset token and sign the user in."""
        if len(body.new_password) < _MIN_PASSWORD_LEN:
            raise HTTPException(
                status_code=400,
                detail=(f"Password must be at least {_MIN_PASSWORD_LEN} characters."),
            )
        email, record = _verify_reset_token(body.token)
        if email is None or record is None:
            raise HTTPException(
                status_code=400,
                detail="This reset link is invalid, expired, or already used.",
            )
        record = dict(record)
        record["password_hash"] = hash_password(body.new_password)
        user_store[email] = record
        session_id = session_store.create(user_id=email, email=email)
        _set_session_cookie(
            response,
            session_id,
            max_age=session_max_age,
            salt="session",
            name=cookie_name,
        )
        return {"ok": True, "email": email}

    @router.get("/csrf")
    async def csrf(request: Request) -> dict[str, Any]:
        """Return the unsigned CSRF token.

        Three cases, in priority order:
        1. CSRFMiddleware just minted a token for this request (no inbound
           cookie). It exposes the unsigned value via ``request.state.csrf_token``
           and sets the signed cookie in the response itself — we just echo.
        2. The request already carried a valid signed cookie — unseal it and
           return the unsigned value. No new cookie is set.
        3. No cookie and no minted token (shouldn't happen in practice, but
           defensive): fall through to a 500-like empty string. Prefer to let
           the next request set the cookie via the middleware.
        """
        minted = getattr(request.state, "csrf_token", None)
        if minted:
            return {"csrf": minted}
        existing = request.cookies.get("enlace_csrf")
        if existing:
            token = verify_cookie(existing, signing_key, salt="csrf")
            if token:
                return {"csrf": token}
        # Degenerate: no cookie, no minted token. Let the client retry.
        raise HTTPException(
            status_code=503, detail="CSRF token unavailable; retry this request"
        )

    return router
