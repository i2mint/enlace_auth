"""``/auth/shares/*`` — the signed-in user manages the shares of their own data.

The owner side of a share is always the signed-in user: there is no route by which
a grantee can grant onward, or anyone can share someone else's data (an admin does
that through ``/_admin/api/shares`` or the CLI). These routes live under ``/auth/``,
so the platform's double-submit CSRF check covers every write.

- ``GET    /auth/shares/{app_id}`` → ``{"owner", "granted": [...], "received": [...]}``
- ``PUT    /auth/shares/{app_id}/{grantee}``
  (body ``{"access"?, "label"?, "expires_at"?}``)
- ``DELETE /auth/shares/{app_id}/received/{owner}`` — a grantee leaves a share
- ``DELETE /auth/shares/{app_id}/{grantee}`` — the owner revokes one

See ``misc/docs/decisions/0001-owner-granted-data-shares.md``.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional, Union

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from enlace_auth.auth.grants import GrantError, parse_expires_at
from enlace_auth.auth.shares import ShareError, ShareStore


class _ShareBody(BaseModel):
    access: str = "rw"
    label: Optional[str] = None
    # A date ("YYYY-MM-DD", end of day UTC) or full ISO-8601 timestamp; null = never.
    expires_at: Optional[str] = None


def make_share_router(
    *,
    share_store: ShareStore,
    store_apps: Union[Iterable[str], Callable[[], Iterable[str]]],
) -> APIRouter:
    """Build the ``/auth/shares`` router.

    ``store_apps`` names the apps that have a per-user store (``protected:user``
    apps and ``user_store = true`` apps); a share in any other app is refused,
    since there would be nothing to share. A callable is re-read per request.
    """
    router = APIRouter(prefix="/auth/shares")

    def _apps() -> set[str]:
        return set(store_apps() if callable(store_apps) else store_apps)

    def _me(request: Request) -> str:
        user = getattr(request.state, "user_id", None)
        if not user or user == "shared":
            raise HTTPException(status_code=401, detail="Not authenticated")
        return str(user).lower()

    def _app(app_id: str) -> str:
        if app_id not in _apps():
            raise HTTPException(
                status_code=404, detail=f"No per-user store for app {app_id!r}"
            )
        return app_id

    @router.get("/{app_id}")
    async def list_shares(app_id: str, request: Request) -> dict[str, Any]:
        me, app_id = _me(request), _app(app_id)
        return {
            "owner": me,
            "granted": share_store.granted(app_id, me),
            "received": share_store.received(app_id, me),
        }

    @router.put("/{app_id}/{grantee}")
    async def put_share(
        app_id: str, grantee: str, body: _ShareBody, request: Request
    ) -> dict[str, Any]:
        me, app_id = _me(request), _app(app_id)
        try:
            record = share_store.share(
                app_id,
                me,
                grantee,
                access=body.access,
                label=body.label,
                expires_at=parse_expires_at(body.expires_at),
                granted_by=me,
            )
        except ShareError as e:
            status = 409 if e.code == "no_account" else 422
            raise HTTPException(status_code=status, detail=str(e))
        except GrantError as e:
            raise HTTPException(status_code=422, detail=str(e))
        return {"ok": True, "share": record}

    # Registered before "/{app_id}/{grantee}" so "received" is never read as a grantee.
    @router.delete("/{app_id}/received/{owner}")
    async def leave_share(app_id: str, owner: str, request: Request) -> dict[str, Any]:
        me, app_id = _me(request), _app(app_id)
        if not share_store.revoke(app_id, owner, me):
            raise HTTPException(status_code=404, detail="Share not found")
        return {"ok": True}

    @router.delete("/{app_id}/{grantee}")
    async def revoke_share(
        app_id: str, grantee: str, request: Request
    ) -> dict[str, Any]:
        me, app_id = _me(request), _app(app_id)
        if not share_store.revoke(app_id, me, grantee):
            raise HTTPException(status_code=404, detail="Share not found")
        return {"ok": True}

    return router
