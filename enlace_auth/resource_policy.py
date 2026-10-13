"""The OAuth per-connector allowlist: its shape, its parsing and its one rule.

``[auth.oauth_server.resource_allowlist]`` maps a connector's resource URL to the
emails allowed to authorize for it. The authorization server enforces it
(:mod:`enlace_auth.auth.oauth_server`), the config model validates it
(:mod:`enlace_auth.config`), and the admin dashboard describes it
(:mod:`enlace_auth.admin.routes`). All three go through :func:`parse_resource_allowlist`
here, so they cannot disagree about what a key means or what a value may hold.

The rule is **fail closed, and fail loudly on anything malformed**:

- A listed resource admits exactly its listed emails; ``["*"]``
  (:data:`ANY_ACCOUNT`), on its own, admits every authenticated account.
- A key must be the resource URL exactly as a connector spells its audience
  (lowercase scheme and host, no default port, no ``//``, ``.`` or ``..``), since
  a key in any other spelling can never match one.
- An unlisted resource is refused to everyone.
- A server with no allowlist at all would admit everyone to every resource. That
  is never the result of a typo: it has to be asked for with
  ``allow_unlisted_resources = true``, and an allowlist that is present but
  malformed (a key that is not a URL, a value that is not a list of emails, a
  wildcard pattern, two keys that differ only by a trailing slash) is an error,
  not a guess.

Pure functions, no web or crypto imports, so the config model can use them.
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

__all__ = [
    "ANY_ACCOUNT",
    "normalize_resource",
    "parse_resource_allowlist",
    "parse_resource_display_names",
]

#: A ``resource_allowlist`` entry that opens a resource to every authenticated
#: account. Must be written out: an unlisted resource is refused (fail-closed).
ANY_ACCOUNT = "*"


def normalize_resource(resource: str) -> str:
    """Canonical form of a resource URL: the key both maps use, and the token ``aud``.

    >>> normalize_resource("https://apps.example.com/api/x_mcp/mcp/")
    'https://apps.example.com/api/x_mcp/mcp'
    """
    return (resource or "").rstrip("/")


def _resource_key_problem(key: object) -> str | None:
    """Why *key* cannot name a connector resource, or ``None`` if it can."""
    if not isinstance(key, str):
        return f"key {key!r} is not a string"
    parts = urlsplit(key)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return f"key {key!r} is not an absolute http(s) URL"
    if parts.query or parts.fragment or "@" in parts.netloc:
        return f"key {key!r} has a query, fragment or userinfo; a resource URL has none"
    if not normalize_resource(parts.path):
        return f"key {key!r} names an origin, not a connector (no path)"
    if why := _non_canonical(key, parts):
        return (
            f"key {key!r} is not in canonical form ({why}). A connector compares "
            "its token audience as an exact string, so this key could never match "
            "one, and the connector it was meant for would stay unlisted"
        )
    return None


def _non_canonical(key: str, parts) -> str | None:
    """How *key* differs from the one spelling a connector's audience takes."""
    if any(c.isspace() for c in key):
        return "whitespace"
    if not key.startswith(parts.scheme + "://"):
        return "scheme must be lowercase"
    if parts.netloc != parts.netloc.lower():
        return "host must be lowercase"
    host = parts.hostname or ""
    if host.endswith("."):
        return "host has a trailing dot"
    try:
        port = parts.port
    except ValueError:
        return "port is not a number"
    if (parts.scheme, port) in (("https", 443), ("http", 80)):
        return "default port written out"
    segments = normalize_resource(parts.path).split("/")[1:]
    if any(seg in ("", ".", "..") for seg in segments):
        return "empty, '.' or '..' path segment"
    return None


def _normalized_keys(raw: Mapping, *, field: str) -> dict[str, object]:
    """Validate and normalize the keys of *raw*; refuse two that collapse into one."""
    if not isinstance(raw, Mapping):
        raise ValueError(
            f"{field} must be a table mapping resource URLs to values, "
            f"got {type(raw).__name__}"
        )
    out: dict[str, object] = {}
    for key, value in raw.items():
        if problem := _resource_key_problem(key):
            raise ValueError(f"{field}: {problem}")
        norm = normalize_resource(key)
        if norm in out:
            raise ValueError(
                f"{field}: two keys name the same resource {norm!r} "
                "(they differ only by a trailing slash); keep one"
            )
        out[norm] = value
    return out


def _email_entry_problem(entry: object) -> str | None:
    """Why *entry* is not an allowlist email (or ``*``), or ``None`` if it is."""
    if not isinstance(entry, str):
        return f"{entry!r} is not a string"
    if entry == ANY_ACCOUNT:
        return None
    if "*" in entry:
        return (
            f"{entry!r} is a pattern; only a bare {ANY_ACCOUNT!r} (every "
            "authenticated account) is supported, so list each email"
        )
    local, at, domain = entry.partition("@")
    if not (at and local and domain) or "@" in domain or entry != entry.strip():
        return f"{entry!r} is not an email address"
    if any(c.isspace() for c in entry):
        return f"{entry!r} contains whitespace"
    return None


def parse_resource_allowlist(
    raw: Mapping[str, object] | None,
    *,
    allow_unlisted_resources: bool = False,
) -> dict[str, frozenset[str]]:
    """Validate *raw* and return ``{normalized resource: lowercased emails}``.

    Raises ``ValueError`` naming the offending entry for anything that is not
    exactly the documented shape, and for an empty allowlist unless
    *allow_unlisted_resources* says an open server is intended. Setting that flag
    alongside a non-empty allowlist is also an error: the allowlist always refuses
    unlisted resources, so the flag would promise something that does not happen.

    >>> allowlist = parse_resource_allowlist(
    ...     {"https://a.example/api/x/mcp/": ["Ann@Example.com", "bob@example.com"]}
    ... )
    >>> {k: sorted(v) for k, v in allowlist.items()}
    {'https://a.example/api/x/mcp': ['ann@example.com', 'bob@example.com']}
    >>> parse_resource_allowlist({}, allow_unlisted_resources=True)
    {}
    """
    field = "resource_allowlist"
    entries = _normalized_keys(raw or {}, field=field)
    if not entries and not allow_unlisted_resources:
        raise ValueError(
            "the OAuth server has no resource_allowlist, which would open every "
            "connector to every authenticated account. List each connector under "
            '[auth.oauth_server.resource_allowlist] (use ["*"] for every account), '
            "or set allow_unlisted_resources = true under [auth.oauth_server] if an "
            "open server is really intended. A misspelled or misnested table "
            "arrives here as an empty one."
        )
    if entries and allow_unlisted_resources:
        raise ValueError(
            "allow_unlisted_resources = true conflicts with a non-empty "
            "resource_allowlist: an allowlist always refuses unlisted resources. "
            'Remove the flag, or list the resource with ["*"] to open it.'
        )
    out: dict[str, frozenset[str]] = {}
    for resource, emails in entries.items():
        if isinstance(emails, (str, bytes)) or not isinstance(
            emails, (list, tuple, set, frozenset)
        ):
            raise ValueError(
                f"{field}[{resource!r}] must be a list of emails, got {emails!r}"
            )
        for entry in emails:
            if problem := _email_entry_problem(entry):
                raise ValueError(f"{field}[{resource!r}]: {problem}")
        if ANY_ACCOUNT in emails and len(emails) > 1:
            # ["ann@example.com", "*"] means everyone, which reads like a list
            # that was meant to be narrower.
            raise ValueError(
                f"{field}[{resource!r}]: {ANY_ACCOUNT!r} admits every account, "
                "so it must stand alone; drop it or drop the emails"
            )
        out[resource] = frozenset(e.lower() for e in emails)
    return out


def parse_resource_display_names(raw: Mapping[str, object] | None) -> dict[str, str]:
    """Validate *raw* and return ``{normalized resource: display name}``.

    Keys follow the same rule as the allowlist's, so a key that would never match
    a resource is reported rather than silently showing generic consent copy.
    """
    field = "resource_display_names"
    out: dict[str, str] = {}
    for resource, name in _normalized_keys(raw or {}, field=field).items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{field}[{resource!r}] must be a non-empty string")
        out[resource] = name
    return out
