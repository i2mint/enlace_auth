"""Store injection middleware and per-app store router.

``StoreInjectionMiddleware`` runs after the auth middleware. It reads
``scope["state"]["user_id"]`` and ``scope["state"]["app_id"]`` (the latter set
by the per-mount wrapper in ``enlace.compose``) and attaches a
``PrefixedStore(base, f"{user_id}/{app_id}/")`` to ``scope["state"]["store"]``.

If either id is missing, ``store`` is ``None`` — apps are expected to handle
that case gracefully (they do so naturally by providing a dict fallback in
standalone mode).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, MutableMapping
from typing import Any, Callable, Optional, Union

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from enlace_auth.stores.prefixed import PrefixedStore
from enlace_auth.stores.validation import sanitize_key


class StoreInjectionMiddleware:
    """Pure-ASGI middleware that injects ``request.state.store``."""

    def __init__(self, app, *, base_store: Optional[MutableMapping] = None):
        self.app = app
        self._base = base_store

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        state = scope.setdefault("state", {})
        user_id = state.get("user_id")
        app_id = state.get("app_id")

        if self._base is not None and user_id and app_id:
            try:
                prefix = f"{sanitize_key(str(user_id))}/{sanitize_key(app_id)}/"
                state["store"] = PrefixedStore(self._base, prefix)
            except ValueError:
                state["store"] = None
        else:
            state["store"] = None

        await self.app(scope, receive, send)


#: The 404 details of the store routes: no (more) share for ``?owner=``, or no such key.
NO_ACCESS = "no_access"
NO_KEY = "no_key"


def _refuse_constant(name: str):
    """Refuse ``NaN``/``Infinity``: not JSON a browser can read back."""
    raise ValueError(f"non-finite number {name}")


#: How many items the list route returns before it says ``"truncated": true``.
DEFAULT_MAX_ITEMS = 5000


def etag_of(value: Any) -> str:
    """A strong ETag for a stored JSON value: a hash of its canonical serialisation."""
    # ensure_ascii: a lone surrogate (which a browser can send) must hash, not raise.
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return '"' + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32] + '"'


def make_store_router(
    *,
    base_store_getter: Callable[[], Optional[MutableMapping]],
    protected_apps: Union[Iterable[str], Callable[[], Iterable[str]]],
    share_access: Optional[Callable[[str, str, str], Optional[str]]] = None,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> APIRouter:
    """Return a router exposing the per-user store of each app that has one.

    Routes:

    - ``GET    /api/{app_id}/store?prefix=<p>``
      → ``{"items": {key: {"value", "etag"}}, "truncated"}``
    - ``GET    /api/{app_id}/store/{key}`` → ``{"value": v}`` with an ``ETag`` header
    - ``PUT    /api/{app_id}/store/{key}`` — conditional with ``If-Match: <etag>``
      or ``If-None-Match: *``
    - ``DELETE /api/{app_id}/store/{key}`` — ``If-Match`` likewise

    A failed precondition is **412** with the current ``{"value", "etag"}`` (``value``
    null when the key is absent), so the client can resolve and retry.

    ``protected_apps`` names the apps with a per-user store: ``protected:user``
    apps and those whose ``app.toml`` sets ``user_store = true`` (a callable is
    re-read per request). ``?owner=<email>`` on any route acts on that user's
    data instead of the caller's, when ``share_access(app_id, owner, caller)``
    says so (``"rw"``, or ``"ro"`` for GET only); otherwise 404, as if the owner
    had nothing. Without ``share_access`` every ``?owner=`` naming someone else
    is 404. See ``misc/docs/decisions/0001-owner-granted-data-shares.md``.

    The router assumes ``PlatformAuthMiddleware`` has set ``request.state.user_id``
    (public apps get it too, when the visitor is signed in). CSRF on writes is the
    ``CSRFMiddleware``'s, through its ``enforce_prefixes``.
    """
    router = APIRouter()

    def _apps() -> set[str]:
        return set(protected_apps() if callable(protected_apps) else protected_apps)

    def _scoped_store(request: Request, app_id: str, *, write: bool) -> PrefixedStore:
        if app_id not in _apps():
            raise HTTPException(
                status_code=404, detail=f"No user store for app '{app_id}'"
            )
        user_id = getattr(request.state, "user_id", None)
        if not user_id or user_id == "shared":
            raise HTTPException(status_code=401, detail="Not authenticated")
        base = base_store_getter()
        if base is None:
            raise HTTPException(status_code=503, detail="User data store disabled")
        owner = (request.query_params.get("owner") or "").strip().lower()
        me = str(user_id).lower()
        if owner and owner != me:
            granted = share_access(app_id, owner, me) if share_access else None
            if granted not in ("rw", "ro") or (write and granted != "rw"):
                # 404, not 403: a caller probing for owners learns nothing. Detail is
                # "no_access", so a grantee's client can tell a revoked share from a
                # missing key (which says "no_key"); a stranger never gets past here.
                raise HTTPException(status_code=404, detail=NO_ACCESS)
            whose = owner
        else:
            whose = me
        try:
            prefix = f"{sanitize_key(whose)}/{sanitize_key(app_id)}/"
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return PrefixedStore(base, prefix)

    def _check_key(key: str) -> None:
        try:
            sanitize_key(key)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

    def _current(store: PrefixedStore, key: str) -> tuple[Any, Optional[str]]:
        try:
            value = store[key]
        except KeyError:
            return None, None
        return value, etag_of(value)

    def _precondition(request: Request, store: PrefixedStore, key: str) -> None:
        """Raise 412 when ``If-Match`` / ``If-None-Match: *`` no longer hold."""
        if_match = request.headers.get("if-match")
        if_none_match = request.headers.get("if-none-match")
        if if_match is None and if_none_match is None:
            return
        value, etag = _current(store, key)
        failed = (
            if_none_match is not None
            and if_none_match.strip() == "*"
            and etag is not None
        )
        if if_match is not None:
            wanted = if_match.strip()
            failed = failed or etag is None or (wanted != "*" and wanted != etag)
        # No await between this check and the write, so within one worker the pair is
        # atomic. Across workers two writers can still interleave in the window of one
        # file write; the conditional write narrows the lost-update race, it does not
        # serialise it. # seam candidate: a per-key lock on the base store.
        if failed:
            raise HTTPException(status_code=412, detail={"value": value, "etag": etag})

    @router.get("/api/{app_id}/store")
    @router.get("/api/{app_id}/store/", include_in_schema=False)
    async def list_values(app_id: str, request: Request, prefix: str = ""):
        store = _scoped_store(request, app_id, write=False)
        if prefix:
            _check_key(prefix)
        items: dict[str, Any] = {}
        truncated = False
        for key in sorted(store.keys_under(prefix)):
            if len(items) >= max_items:
                truncated = True
                break
            value, etag = _current(store, key)
            if etag is not None:
                items[key] = {"value": value, "etag": etag}
        return {"items": items, "truncated": truncated}

    @router.get("/api/{app_id}/store/{key:path}")
    async def get_value(app_id: str, key: str, request: Request):
        store = _scoped_store(request, app_id, write=False)
        _check_key(key)
        value, etag = _current(store, key)
        if etag is None:
            raise HTTPException(status_code=404, detail=NO_KEY)
        return JSONResponse({"value": value}, headers={"ETag": etag})

    @router.put("/api/{app_id}/store/{key:path}")
    async def put_value(app_id: str, key: str, request: Request):
        store = _scoped_store(request, app_id, write=True)
        _check_key(key)
        try:
            body = json.loads(await request.body(), parse_constant=_refuse_constant)
        except ValueError as e:
            raise HTTPException(
                status_code=400, detail="Body must be JSON (no NaN or Infinity)"
            ) from e
        value = (
            body.get("value") if isinstance(body, dict) and "value" in body else body
        )
        try:
            # A lone surrogate parses, but no response could send it back: refuse it
            # here, or one bad value makes every read of the collection fail.
            json.dumps(value, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError as e:
            raise HTTPException(
                status_code=400, detail="Body holds text that is not valid Unicode"
            ) from e
        etag = etag_of(value)
        _precondition(request, store, key)
        store[key] = value
        return JSONResponse({"ok": True, "etag": etag}, headers={"ETag": etag})

    @router.delete("/api/{app_id}/store/{key:path}")
    async def delete_value(app_id: str, key: str, request: Request):
        store = _scoped_store(request, app_id, write=True)
        _check_key(key)
        _precondition(request, store, key)
        try:
            del store[key]
        except KeyError:
            raise HTTPException(status_code=404, detail=NO_KEY)
        return {"ok": True}

    return router
