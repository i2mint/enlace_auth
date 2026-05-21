"""Auth HTTP routes: register, login, logout, shared-login, csrf, recovery.

This router serves both the JSON API (``POST /auth/login`` etc., consumed by
app frontends) and the browser-facing HTML pages (``GET /auth/login``, the
password-recovery screens) so the platform is usable from a bare URL with no
app frontend in the way.

OAuth routes live in ``enlace.auth.oauth`` and are attached separately so the
Authlib dependency stays lazy.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, EmailStr

from enlace_auth.auth import pages
from enlace_auth.auth.cookies import sign_cookie, verify_cookie
from enlace_auth.auth.email import EmailSender, make_console_sender
from enlace_auth.auth.passwords import hash_password, verify_password
from enlace_auth.auth.sessions import SessionStore

# Salt namespace for password-reset tokens — distinct from "session" / "csrf"
# / "shared:*" so a token minted for one purpose can never verify for another.
_RESET_SALT = "pwreset"


def _pw_fingerprint(record: dict) -> str:
    """Short, stable fingerprint of a user's current password hash.

    Embedded in reset tokens so a token stops working the moment the password
    changes — that makes every reset link naturally single-use (using it
    changes the hash) and also invalidates outstanding links after any other
    password change. No server-side token store needed.
    """
    raw = str(record.get("password_hash"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


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
    reset_token_max_age: int = 1800,
) -> APIRouter:
    """Build a FastAPI router exposing ``/auth/*`` endpoints.

    Args:
        session_store / user_store: backing stores.
        signing_key: HMAC key for session, CSRF, shared, and reset tokens.
        cookie_name / session_max_age / secure_cookies: session-cookie policy.
        shared_password_for: maps an app id to its shared-password hash.
        can_register: predicate gating self-registration by email.
        send_email: delivers password-reset emails. Defaults to the console
            sender (logs the link) so the flow works without SMTP configured.
        reset_token_max_age: lifetime of a password-reset link, in seconds
            (default 30 minutes).
    """
    router = APIRouter(prefix="/auth")
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
        """Return ``(email, record)`` for a valid token, else ``(None, None)``.

        Validates the signature, the age, AND that the embedded password
        fingerprint still matches the stored hash — the last check is what
        makes a link single-use (consuming it changes the hash).
        """
        if not token:
            return None, None
        payload = verify_cookie(
            token, signing_key, max_age=reset_token_max_age, salt=_RESET_SALT
        )
        if not payload or len(payload) <= 16:
            return None, None
        fp, email = payload[:16], payload[16:]
        try:
            record = user_store[email]
        except KeyError:
            return None, None
        if not isinstance(record, dict) or _pw_fingerprint(record) != fp:
            return None, None
        return email, record

    @router.get("/login", response_class=HTMLResponse, include_in_schema=False)
    async def login_page(request: Request):
        """Serve the sign-in form. Honors ``?next=``; skipped if already in."""
        next_url = pages.safe_next(request.query_params.get("next"))
        if getattr(request.state, "user_id", None):
            return RedirectResponse(next_url, status_code=303)
        return HTMLResponse(pages.render_login_page(next_url=next_url))

    @router.get(
        "/forgot-password", response_class=HTMLResponse, include_in_schema=False
    )
    async def forgot_password_page() -> HTMLResponse:
        """Serve the 'request a reset link' form."""
        return HTMLResponse(pages.render_forgot_page())

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
            token = sign_cookie(
                _pw_fingerprint(record) + email, signing_key, salt=_RESET_SALT
            )
            base = str(request.base_url).rstrip("/")
            link = f"{base}/auth/reset-password?token={token}"
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
