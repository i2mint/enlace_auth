"""Named groups of accounts: one list of emails, referenced as ``@name`` wherever an
email list is.

``[auth.groups]`` in ``platform.toml`` names lists of emails::

    [auth.groups]
    acme = ["ann@acme.com", "bob@acme.com"]

and ``@acme`` then stands for that list in an app's ``allowed_users`` and in a
connector's ``[auth.oauth_server.resource_allowlist]`` entry. A client team that may
reach two connectors and a document room is listed once; adding or removing a person
is one edit.

``@admins`` is the built-in group (the platform admins, see
:data:`enlace_auth.plugin.ADMINS_ALIAS`), so ``admins`` cannot be declared here.

Unknown references fail closed in both places, differently because the cost differs:
in a connector allowlist (validated when the config loads) an unknown ``@name`` is an
error, as every malformed allowlist entry is; in an app's ``allowed_users`` it is kept
as written, so it matches no account and the app admits nobody, since refusing to
start would take every other app down with it (the same rule as ``@admins`` with no
admins configured).

Pure functions, no web imports, so the config model can use them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

from enlace_auth.emails import bare_address_problem

__all__ = [
    "GROUP_PREFIX",
    "RESERVED_GROUPS",
    "expand_groups",
    "is_group_ref",
    "parse_groups",
]

#: how an email list refers to a group: ``@name``
GROUP_PREFIX = "@"
#: names enlace_auth defines itself (``@admins``), not redefinable in [auth.groups]
RESERVED_GROUPS = frozenset({"admins"})
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


def is_group_ref(entry: object) -> bool:
    """Whether *entry* names a group (``@name``) rather than an email.

    >>> is_group_ref("@acme"), is_group_ref("ann@acme.com"), is_group_ref("*")
    (True, False, False)
    """
    return (
        isinstance(entry, str)
        and entry.startswith(GROUP_PREFIX)
        and GROUP_PREFIX not in entry[1:]
    )


def parse_groups(raw: Mapping[str, object] | None) -> dict[str, tuple[str, ...]]:
    """Validate ``[auth.groups]``: ``{name: (email, ...)}``, or ``ValueError`` naming
    the entry.

    A name is lowercase letters, digits, ``-`` and ``_``; ``admins`` is reserved; each
    member is one bare address (no ``@group`` inside a group, no ``*``).

    >>> parse_groups({"acme": ["Ann@acme.com"]})
    {'acme': ('Ann@acme.com',)}
    """
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"[auth.groups] must be a table of lists, got {raw!r}")
    out: dict[str, tuple[str, ...]] = {}
    for name, members in raw.items():
        where = f"[auth.groups] {name!r}"
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ValueError(
                f"{where}: a group name is lowercase letters, digits, '-' and '_'"
            )
        if name in RESERVED_GROUPS:
            raise ValueError(f"{where}: '@{name}' is built in and cannot be redefined")
        if isinstance(members, (str, bytes)) or not isinstance(members, (list, tuple)):
            raise ValueError(f"{where} must be a list of emails, got {members!r}")
        for entry in members:
            if not isinstance(entry, str):
                raise ValueError(f"{where}: {entry!r} is not a string")
            if is_group_ref(entry) or "*" in entry:
                raise ValueError(
                    f"{where}: {entry!r}: a group lists emails only (no groups, no '*')"
                )
            if problem := bare_address_problem(entry.strip()):
                raise ValueError(f"{where}: {entry!r} is {problem}")
        out[name] = tuple(e.strip() for e in members)
    return out


def expand_groups(
    entries: Iterable[object],
    groups: Mapping[str, Iterable[str]],
    *,
    where: str = "",
    unknown: str = "raise",
) -> list:
    """*entries* with every ``@name`` of *groups* replaced by its emails, in order,
    deduplicated.

    Entries that are not group references pass through (emails, ``*``, and the built-in
    ``@admins``, which its own expansion handles). An unknown ``@name`` raises
    ``ValueError`` (``unknown="raise"``) or is kept as written (``unknown="keep"``),
    where it matches no account.

    >>> acme = {"acme": ["ann@acme.com", "bob@acme.com"]}
    >>> expand_groups(["@acme", "cy@x.com", "ann@acme.com"], acme)
    ['ann@acme.com', 'bob@acme.com', 'cy@x.com']
    """
    if unknown not in ("raise", "keep"):
        raise ValueError(f"unknown must be 'raise' or 'keep', not {unknown!r}")
    out: list = []
    for entry in entries:
        if is_group_ref(entry) and entry[1:] not in RESERVED_GROUPS:
            name = entry[1:]
            if name in groups:
                members = list(groups[name])
            elif unknown == "raise":
                known = ", ".join("@" + g for g in sorted(groups)) or "none"
                raise ValueError(
                    f"{where + ': ' if where else ''}{entry!r} names no group in "
                    f"[auth.groups] (known: {known})"
                )
            else:
                members = [entry]
        else:
            members = [entry]
        out.extend(m for m in members if m not in out)
    return out
