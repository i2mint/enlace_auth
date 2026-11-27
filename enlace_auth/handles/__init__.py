"""Handles (usernames): the public, unique, case-insensitive name of an account.

The email stays the account's private key; the handle is what other people and
apps see ("by @thorwhalen"). Three layers, imported one way:

- :mod:`~enlace_auth.handles.core`: the rules (normal form, validity, reserved
  names, the default from an email, suggestions). Pure; no web or storage imports.
- :mod:`~enlace_auth.handles.registry`: :class:`HandleRegistry`, which account holds
  which handle, over two ``MutableMapping`` s, unique under a lock.
- :mod:`~enlace_auth.handles.directory`: :class:`HandleDirectory`, the read-only
  view every app gets at ``request.state.handles`` (set by
  :class:`HandleDirectoryMiddleware`).
- :mod:`~enlace_auth.handles.routes`: ``/auth/handles/*`` for the browser.

An app's server shows "by <handle>" with ``request.state.handles.handle_of(owner)``,
where *owner* is the ``request.state.user_id`` it stored; it never sends emails to
the browser. See ``misc/docs/research/general/usernames.md`` for the rules' sources.
"""

from enlace_auth.handles.core import (
    DEFAULT_POLICY,
    RESERVED,
    HandlePolicy,
    base_from_email,
    candidates,
    handle_problem,
    normalize,
    suggestions,
    uniqueness_key,
)
from enlace_auth.handles.directory import HandleDirectory, HandleDirectoryMiddleware
from enlace_auth.handles.registry import (
    HandleError,
    HandleRegistry,
    file_lock,
    make_handle_registry,
)

__all__ = [
    "DEFAULT_POLICY",
    "HandleDirectory",
    "HandleDirectoryMiddleware",
    "HandleError",
    "HandlePolicy",
    "HandleRegistry",
    "RESERVED",
    "base_from_email",
    "candidates",
    "file_lock",
    "handle_problem",
    "make_handle_registry",
    "normalize",
    "suggestions",
    "uniqueness_key",
]
