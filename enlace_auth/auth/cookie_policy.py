"""Where the platform's sign-in cookies go, in one place (#94).

Every sign-in path (password, reset, email code, passkey, OAuth, shared password)
sets the same kind of cookie, and every sign-out clears it. They used to build the
``Set-Cookie`` line each on its own; :class:`CookiePolicy` builds it once, so adding
an attribute (``Domain``) cannot miss a path.

``cookie_domain`` (``[auth] cookie_domain``) lets one sign-in serve apps on sibling
subdomains of one parent (``a.apps.example.com``, ``b.apps.example.com``, sign-in on
``apps.example.com``): sign-in cookies then carry ``Domain=apps.example.com`` when
the request came to that host or one under it. On any other host (an IP, a second
name) the cookie stays host-only, as a browser would refuse the ``Domain`` there.
Unset, nothing changes.

Every host under ``cookie_domain`` receives the session cookie, so it must be one
the platform serves: an outside service on a sibling subdomain would see it.

>>> p = CookiePolicy(secure=True, domain="apps.example.com")
>>> p.set_header("s", "v", max_age=60, host="a.apps.example.com")
's=v; Path=/; HttpOnly; Max-Age=60; SameSite=Lax; Secure; Domain=apps.example.com'
>>> p.set_header("s", "v", max_age=60, host="10.0.0.5")
's=v; Path=/; HttpOnly; Max-Age=60; SameSite=Lax; Secure'
>>> len(p.clear_headers("s"))  # the Domain form and the host-only one
2
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

# A host name as a cookie Domain or an allowed ``next`` host: lower-case labels of
# letters, digits and hyphens. Anything else (a backslash, ``@``, ``%``, a space)
# is refused rather than parsed, since browsers and Python disagree on those.
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_PORT = re.compile(r"^[0-9]{1,5}$")


def cookie_domain_problem(domain: str) -> Optional[str]:
    """Why *domain* cannot be a ``cookie_domain``, or None when it can.

    >>> cookie_domain_problem("apps.example.com") is None
    True
    >>> cookie_domain_problem("localhost")
    "'localhost' has no dot: browsers refuse a Domain cookie for a single label"
    """
    if not isinstance(domain, str) or not _HOST.match(domain):
        return (
            f"{domain!r} must be a lower-case host name "
            "(no scheme, port, path or leading dot)"
        )
    if "." not in domain:
        return (
            f"{domain!r} has no dot: browsers refuse a Domain cookie for a single label"
        )
    return None


def host_within(host: Optional[str], domain: Optional[str]) -> bool:
    """Whether *host* (a bare host name, no port) is *domain* or under it.

    >>> host_within("a.apps.example.com", "apps.example.com")
    True
    >>> host_within("apps.example.com", "apps.example.com")
    True
    >>> host_within("evilapps.example.com", "apps.example.com")
    False
    """
    if not host or not domain or not _HOST.match(host):
        return False
    return host == domain or host.endswith("." + domain)


def request_host(headers) -> Optional[str]:
    """The lower-case host name a request was sent to (``Host`` without its port).

    *headers* is an ASGI header list or a mapping. Returns None for anything that
    is not a plain host name.
    """
    if isinstance(headers, (list, tuple)):
        raw = next(
            (v.decode("latin-1") for k, v in headers if k.lower() == b"host"), ""
        )
    else:
        raw = headers.get("host", "") or ""
    host, _, port = raw.strip().lower().partition(":")
    if port and not _PORT.match(port):
        return None
    return host if _HOST.match(host) else None


def absolute_next_problem(raw: str, domain: Optional[str]) -> Optional[str]:
    """None when *raw* is an ``https://`` URL on *domain* or a host under it.

    Strict on purpose: the authority must be a plain host name (an optional port),
    so a backslash, ``@`` or percent sign that a browser reads differently from
    Python is refused, not parsed.

    >>> d = "apps.example.com"
    >>> absolute_next_problem("https://a.apps.example.com/x?y=1", d)
    >>> absolute_next_problem("https://evil.com\\\\.apps.example.com/", d)
    'control or ambiguous character'
    """
    if not domain:
        return "no cookie_domain"
    if any(c in raw for c in "\\\r\n\t ") or any(ord(c) < 32 for c in raw):
        return "control or ambiguous character"
    try:
        parts = urlsplit(raw)
    except ValueError:
        return "unparsable"
    if parts.scheme != "https":
        return "not https"
    host, _, port = parts.netloc.lower().partition(":")
    if "@" in parts.netloc or (port and not _PORT.match(port)):
        return "authority is not a plain host"
    if not host_within(host, domain):
        return "host outside cookie_domain"
    return None


@dataclass(frozen=True)
class CookiePolicy:
    """The attributes of the platform's sign-in cookies.

    ``secure`` adds ``Secure``; ``domain`` is ``[auth] cookie_domain``.
    """

    secure: bool = True
    domain: Optional[str] = None

    def domain_for(self, host: Optional[str]) -> Optional[str]:
        """The ``Domain`` to set for a request to *host*, or None (host-only)."""
        return self.domain if host_within(host, self.domain) else None

    def set_header(
        self,
        name: str,
        value: str,
        *,
        max_age: int,
        host: Optional[str] = None,
        path: str = "/",
    ) -> str:
        """The ``Set-Cookie`` value for a sign-in cookie sent to *host*."""
        attrs = [f"{name}={value}", f"Path={path}", "HttpOnly", f"Max-Age={max_age}"]
        attrs.append("SameSite=Lax")
        if self.secure:
            attrs.append("Secure")
        if domain := self.domain_for(host):
            attrs.append(f"Domain={domain}")
        return "; ".join(attrs)

    def clear_headers(self, name: str, *, path: str = "/") -> list[str]:
        """``Set-Cookie`` values that remove *name*: host-only, and the Domain form.

        Both, whatever the host: a browser holding a cookie from before
        ``cookie_domain`` was set (or after it was unset) must lose it too.
        """
        base = f"{name}=; Path={path}; Max-Age=0; SameSite=Lax" + (
            "; Secure" if self.secure else ""
        )
        out = [base]
        if self.domain:
            out.append(f"{base}; Domain={self.domain}")
        return out

    def set_cookie(self, response, name: str, value: str, **kwargs) -> None:
        """Append :meth:`set_header` to a Starlette *response*."""
        response.headers.append("set-cookie", self.set_header(name, value, **kwargs))

    def clear_cookie(self, response, name: str, *, path: str = "/") -> None:
        """Append :meth:`clear_headers` to a Starlette *response*."""
        for header in self.clear_headers(name, path=path):
            response.headers.append("set-cookie", header)
