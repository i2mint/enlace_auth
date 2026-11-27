"""``/auth/handles/*``: the signed-in user's handle, the availability check, lookups.

Every route needs a signed-in account (a handle is public to the platform's users,
not to the open web) and none of them ever returns an email.

- ``GET  /auth/handles/me`` -> ``{"handle", "chosen"}``; assigns the default on
  first call. While ``chosen`` is false, a frontend offers its "choose your
  username" step.
- ``GET  /auth/handles/check?handle=<typed>`` -> ``{"handle", "available",
  "problem", "code", "suggestions"}``. Called as the person types.
- ``POST /auth/handles/me`` body ``{"handle"}`` -> ``{"handle", "chosen"}``; posting
  the current handle confirms it. Errors are ``{"detail": {"code", "message",
  "suggestions"}}`` with 409 (taken), 429 (cooldown) or 422 (invalid, reserved).
  Under ``/auth/``, so the platform's double-submit CSRF check covers it.
- ``GET  /auth/handles/{handle}`` -> ``{"handle"}`` or ``{"handle",
  "renamed_from"}`` (a recent rename), 404 when no account holds it publicly.

Every route but ``GET /me`` is rate-limited per account (429): the check and the
lookup at *check_limit* per *check_window_seconds*, a claim at *claim_limit*.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from enlace_auth.handles.registry import HandleError, HandleRegistry
from enlace_auth.ratelimit import RateLimiter, SlidingWindowLimiter

#: HTTP status of each HandleError code
_STATUS = {
    "invalid": 422,
    "reserved": 422,
    "taken": 409,
    "cooldown": 429,
    "no-account": 404,
    "exhausted": 409,
}


class _ClaimBody(BaseModel):
    handle: str


def make_handle_router(
    *,
    registry: HandleRegistry,
    rate_limiter: Optional[RateLimiter] = None,
    check_limit: int = 120,
    check_window_seconds: float = 60.0,
    claim_limit: int = 20,
) -> APIRouter:
    """Build the ``/auth/handles`` router over *registry*.

    *rate_limiter* (``allow(key, *, limit, window)``) bounds the availability
    check and the lookup to *check_limit* calls per account per
    *check_window_seconds*, and claims to *claim_limit*; the default counts in
    memory, per process.
    """
    router = APIRouter(prefix="/auth/handles")
    allow = rate_limiter or SlidingWindowLimiter({})

    def _me(request: Request) -> str:
        user = getattr(request.state, "user_id", None)
        if not user or user == "shared":
            raise HTTPException(status_code=401, detail="Not authenticated")
        return str(user).lower()

    def _limit(what: str, account: str, limit: int) -> None:
        if not allow(
            f"handle-{what}:{account}", limit=limit, window=check_window_seconds
        ):
            raise HTTPException(status_code=429, detail="Too many requests; slow down.")

    def _refuse(err: HandleError) -> HTTPException:
        return HTTPException(
            status_code=_STATUS.get(err.code, 400),
            detail={
                "code": err.code,
                "message": err.message,
                "suggestions": err.suggestions,
            },
        )

    @router.get("/me")
    async def my_handle(request: Request) -> dict:
        try:
            return registry.ensure(_me(request))
        except HandleError as err:
            raise _refuse(err) from None

    @router.post("/me")
    async def set_my_handle(body: _ClaimBody, request: Request) -> dict:
        account = _me(request)
        _limit("claim", account, claim_limit)
        try:
            return registry.claim(account, body.handle[:200])
        except HandleError as err:
            raise _refuse(err) from None

    @router.get("/check")
    async def check(handle: str, request: Request) -> dict:
        account = _me(request)
        _limit("check", account, check_limit)
        return registry.check(handle[:200], account=account)

    @router.get("/{handle}")
    async def lookup(handle: str, request: Request) -> dict:
        _limit("check", _me(request), check_limit)
        found = registry.resolve(handle[:200])
        if found is None:
            raise HTTPException(status_code=404, detail="No such username")
        return found

    return router
