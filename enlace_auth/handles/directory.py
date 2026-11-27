"""The read-only view of handles every app gets at ``request.state.handles``.

An app's server stores the account of whoever made something (its
``request.state.user_id``) and shows their handle with
``request.state.handles.handle_of(account)``. Accounts go in; only handles go out
to the browser. Renames need nothing from the app: it looks the handle up when it
shows it, so it never stores a stale one.

>>> from enlace_auth.handles.registry import HandleRegistry
>>> reg = HandleRegistry({}, {}, account_exists=lambda a: True)
>>> _ = reg.claim("thorwhalen@example.com", "thorwhalen")
>>> _ = reg.ensure("ann@example.com")            # a default, not confirmed yet
>>> d = HandleDirectory(reg)
>>> d.handles_of(["thorwhalen@example.com", "ann@example.com"])
{'thorwhalen@example.com': 'thorwhalen'}
>>> d.account_of("@ThorWhalen")
'thorwhalen@example.com'
>>> hasattr(d, "claim")   # read-only: apps cannot rename anyone
False
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Optional

from enlace_auth.handles.registry import HandleRegistry

__all__ = ["HandleDirectory", "HandleDirectoryMiddleware"]


class HandleDirectory:
    """Look handles up by account and accounts up by handle; nothing else.

    Only confirmed handles: an account that has not yet confirmed its default (made
    from its email) has none to show, and ``handle_of`` returns ``None``. An app
    then shows no name, or sends its user to its "choose your username" step.

    This is a convenience for trusted server code, not a boundary between apps:
    every app server on the platform runs in the platform's process and already
    sees its own users' emails. What must never happen is an email reaching a
    browser; that is the app's duty, and this view makes it easy by dealing in
    handles.
    """

    def __init__(self, registry: HandleRegistry):
        self._registry = registry

    def handle_of(self, account: str) -> Optional[str]:
        """The public handle of *account* (a ``request.state.user_id``), or ``None``."""
        return self._registry.handle_of(str(account).lower())

    def handles_of(self, accounts: Iterable[str]) -> dict:
        """``{account: handle}`` for many accounts at once (a list page)."""
        accounts = list(accounts)
        found = self._registry.handles_of(str(a).lower() for a in accounts)
        return {a: found[str(a).lower()] for a in accounts if str(a).lower() in found}

    def account_of(self, handle: str) -> Optional[str]:
        """The account holding *handle* (any spelling, ``@`` or not), or ``None``.

        For server code only (filtering "everything by @x"); never send it on.
        """
        return self._registry.account_of(handle)

    def resolve(self, handle: str) -> Optional[dict]:
        """``{"handle"}``, or ``{"handle", "renamed_from"}`` after a recent rename."""
        return self._registry.resolve(handle)


class HandleDirectoryMiddleware:
    """Pure-ASGI middleware that sets ``request.state.handles`` on every request."""

    def __init__(self, app, *, directory: HandleDirectory):
        self.app = app
        self._directory = directory

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope.setdefault("state", {})["handles"] = self._directory
        await self.app(scope, receive, send)
