"""Editable app-metadata overlay: the write surface for the launcher.

enlace core owns the *read* model for launcher metadata (title / description /
keywords / icon) — it harvests app-declared values and serves ``/_apps`` and the
icon endpoint. But the *editable* layer — an owner-curated overlay of added
keywords and icon/title/description overrides, mutated live from the launcher UI
— needs authentication, CSRF, an admin allowlist, and durable per-app storage.
Those are exactly the concerns enlace core delegates to this plugin, so the
overlay lives here, mirroring the runtime-grants pattern
(:mod:`enlace_auth.auth.grants`).

The contract with core is two dependency-injection slots on the parent app's
``state`` (read by core, written here):

- ``app_meta_overlay``  — a ``MutableMapping[str, dict]`` of per-app overlay
  records; core reads it when resolving ``/_apps`` and the icon.
- ``app_meta_can_edit`` — ``Callable[[Optional[str]], bool]`` deciding whether
  an email may edit; core surfaces the result as ``can_edit_meta``.

Without this plugin (or on an older enlace_auth), those slots default in core to
an empty overlay and "nobody can edit", so the launcher still works read-only.

Overlay record schema (one JSON file per app under ``<store>/app_meta/{name}``)::

    {
      "keywords":     ["owner", "added", "tags"],  # additive; unioned by core
      "icon":         "emoji:🎸" | "assets/x.png" | null,
      "display_name": "Override Title" | null,
      "description":  "Override blurb" | null
    }

Empty records are deleted, so "no overlay" and "empty overlay" coincide.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Callable, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

# Bounds so an editor can't wedge the store with absurd input.
_MAX_KEYWORDS = 40
_MAX_KEYWORD_LEN = 60
_MAX_SPEC_LEN = 4096


class _MetaPatchBody(BaseModel):
    """PATCH body — every field optional. ``null`` on a scalar *clears* it."""

    add_keywords: Optional[list[str]] = None
    remove_keywords: Optional[list[str]] = None
    icon: Optional[str] = None
    display_name: Optional[str] = None
    description: Optional[str] = None

    # Distinguish "field omitted" from "field set to null" so a caller can
    # explicitly clear an override. Pydantic v2: model_fields_set.
    model_config = {"extra": "forbid"}


def make_appmeta_can_edit(editors: tuple[str, ...]) -> Callable[[Optional[str]], bool]:
    """Build the ``app_meta_can_edit`` closure over a normalized editor set.

    Case-insensitive; an empty editor set means *nobody* can edit (safe default,
    so a misconfigured deploy fails closed rather than open).
    """
    editor_set = frozenset(e.strip().lower() for e in editors if e and e.strip())

    def can_edit(email: Optional[str]) -> bool:
        if not editor_set or not email:
            return False
        return email.strip().lower() in editor_set

    return can_edit


def _norm_keywords(values) -> list[str]:
    """Strip, drop blanks/oversize/non-strings, casefold-dedupe, keep first form."""
    out: list[str] = []
    seen: set[str] = set()
    for v in values or ():
        if not isinstance(v, str):
            continue
        s = v.strip()
        if not s or len(s) > _MAX_KEYWORD_LEN:
            continue
        key = s.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


def _clean_record(record: dict) -> dict:
    """Drop empty/None fields so an emptied overlay round-trips to deletion."""
    out: dict = {}
    kw = _norm_keywords(record.get("keywords"))
    if kw:
        out["keywords"] = kw
    for key in ("icon", "display_name", "description"):
        val = record.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def _apply_patch(current: dict, body: _MetaPatchBody) -> dict:
    """Apply a PATCH to an overlay record; return the cleaned new record.

    Keywords are read-modify-write (add ∪, then remove); scalar fields set when
    present (``null`` clears, a string sets). ``model_fields_set`` distinguishes
    "omitted" (leave as-is) from "explicitly null" (clear).
    """
    record = dict(current)
    keywords = _norm_keywords(record.get("keywords"))

    if body.add_keywords:
        keywords = _norm_keywords([*keywords, *body.add_keywords])
    if body.remove_keywords:
        drop = {k.casefold() for k in _norm_keywords(body.remove_keywords)}
        keywords = [k for k in keywords if k.casefold() not in drop]
    if len(keywords) > _MAX_KEYWORDS:
        raise HTTPException(400, f"Too many overlay keywords (max {_MAX_KEYWORDS}).")
    record["keywords"] = keywords

    fields_set = body.model_fields_set
    for key in ("icon", "display_name", "description"):
        if key not in fields_set:
            continue
        val = getattr(body, key)
        if val is None:
            record.pop(key, None)  # explicit clear
        else:
            if len(val) > _MAX_SPEC_LEN:
                raise HTTPException(400, f"{key} too long.")
            record[key] = val

    return _clean_record(record)


def make_appmeta_router(
    *,
    apps: list,
    config,
    overlay_store: MutableMapping,
    can_edit: Callable[[Optional[str]], bool],
) -> APIRouter:
    """Build the ``PATCH/DELETE /_apps/{name}/meta`` router (CSRF-gated by the
    plugin's middleware, since ``/_apps/*`` is not in the CSRF-exempt list).

    Editor authz is enforced per request via ``can_edit``. The app name is
    validated against the known-apps set (unknown ⇒ 404), which also keeps the
    store key confined to a real app name — defense-in-depth over the ``[^/]+``
    path convertor that already blocks traversal.
    """
    from enlace.compose import build_launcher_item

    app_by_name = {a.name: a for a in apps}
    router = APIRouter()

    def _require_editor(request: Request) -> str:
        email = (getattr(request.state, "user_email", None) or "").strip()
        if not can_edit(email):
            # Uniform 403 for anonymous / non-editor — never 500 when auth is off.
            raise HTTPException(403, "Not permitted to edit app metadata.")
        return email

    def _require_app(name: str):
        app = app_by_name.get(name)
        if app is None or name != app.name or any(c in name for c in "/\\"):
            raise HTTPException(404, "Unknown app.")
        return app

    def _item(app) -> dict:
        try:
            record = overlay_store.get(app.name, {})
        except Exception:
            record = {}
        return build_launcher_item(
            app, config, record if isinstance(record, dict) else {}
        )

    @router.patch("/_apps/{name}/meta")
    async def patch_meta(name: str, body: _MetaPatchBody, request: Request) -> dict:
        _require_editor(request)
        app = _require_app(name)
        try:
            current = overlay_store.get(name, {})
        except Exception:
            current = {}
        new_record = _apply_patch(current if isinstance(current, dict) else {}, body)
        if new_record:
            overlay_store[name] = new_record
        else:
            # An emptied overlay is a deletion — keep "absent" and "empty" one state.
            try:
                del overlay_store[name]
            except KeyError:
                pass
        return _item(app)

    @router.delete("/_apps/{name}/meta")
    async def delete_meta(name: str, request: Request) -> dict:
        _require_editor(request)
        app = _require_app(name)
        try:
            del overlay_store[name]
        except KeyError:
            pass
        return _item(app)

    return router
