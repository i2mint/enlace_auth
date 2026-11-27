"""``/auth/handles/*``: the signed-in user's handle, the availability check, lookups.

Every route needs a signed-in account (a handle is public to the platform's users,
not to the open web) and none of them ever returns an email.

- ``GET  /auth/handles/me`` -> ``{"handle", "chosen"}``; assigns the default on
  first call. While ``chosen`` is false, a frontend offers its "choose your
  username" step.
- ``GET  /auth/handles/check?handle=<typed>`` -> ``{"handle", "available",
  "problem", "code", "suggestions"}`` (rate-limited per account: it is called as
  the person types).
- ``POST /auth/handles/me`` body ``{"handle"}`` -> ``{"handle", "chosen"}``; posting
  the current handle confirms it. Errors are ``{"detail": {"code", "message",
  "suggestions"}}`` with 409 (taken), 429 (cooldown) or 422 (invalid, reserved).
  Under ``/auth/``, so the platform's double-submit CSRF check covers it.
- ``GET  /auth/handles/{handle}`` -> ``{"handle"}`` or ``{"handle",
  "renamed_from"}`` (a recent rename), 404 when no account holds it.
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
}


class _ClaimBody(BaseModel):
    handle: str


def make_handle_router(
    *,
    registry: HandleRegistry,
    rate_limiter: Optional[RateLimiter] = None,
    check_limit: int = 120,
    check_window_seconds: float = 60.0,
) -> APIRouter:
    """Build the ``/auth/handles`` router over *registry*.

    *rate_limiter* (``allow(key, *, limit, window)``) bounds the availability
    check to *check_limit* calls per account per *check_window_seconds*; the
    default counts in memory, per process.
    """
    router = APIRouter(prefix="/auth/handles")
    allow = rate_limiter or SlidingWindowLimiter({})

    def _me(request: Request) -> str:
        user = getattr(request.state, "user_id", None)
        if not user or user == "shared":
            raise HTTPException(status_code=401, detail="Not authenticated")
        return str(user).lower()

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
        try:
            return registry.claim(_me(request), body.handle)
        except HandleError as err:
            raise _refuse(err) from None

    @router.get("/check")
    async def check(handle: str, request: Request) -> dict:
        account = _me(request)
        if not allow(
            f"handle-check:{account}",
            limit=check_limit,
            window=check_window_seconds,
        ):
            raise HTTPException(status_code=429, detail="Too many checks; slow down.")
        return registry.check(handle[:200], account=account)

    @router.get("/{handle}")
    async def lookup(handle: str, request: Request) -> dict:
        _me(request)
        found = registry.resolve(handle[:200])
        if found is None:
            raise HTTPException(status_code=404, detail="No such username")
        return found

    return router
