"""Platform auth middleware (pure ASGI).

Runs before any mounted sub-app. Responsibilities:

1. Normalize the request path and reject known traversal bypasses.
2. Strip client-provided identity headers so apps can't be fooled by spoofed
   ``X-User-ID`` / ``X-Forwarded-User`` / similar.
3. Resolve the access level for the request by longest-prefix match on the
   route prefix of each mounted app. Deny-by-default: an unmatched path is
   treated as ``protected:user``.
4. For ``public`` / ``local``, pass through with ``user_id=None``.
5. For ``protected:shared``, look for a per-app signed cookie; on failure
   return 401 (JSON) or redirect browsers to ``login_redirect_path``.
6. For ``protected:user``, look for the platform session cookie, load the
   session from ``SessionStore``, set ``user_id`` / ``user_email``; on
   failure return 401 (JSON) or redirect browsers to ``login_redirect_path``.

Wherever ``user_email`` is set, ``user_groups`` is set beside it: a ``frozenset`` of the
group names the account belongs to (``[auth.groups]``, plus ``"admins"``), from the
``groups_of`` resolver. All three are assigned at the top of every request, never
``setdefault``, so neither a client (headers are stripped, the session cookie is
signed) nor another app's lifespan state can seed them; with no account they are empty.
A ``protected:shared`` app reads no user session, so its ``user_groups`` is always
empty (i2mint/enlace_auth#108).

Browser vs. API deny behavior: GET/HEAD navigations that look like a browser
(``Accept`` header contains ``text/html``) get a 303 redirect to the login
page with ``?login_required=1&next=<original-path>``, so the user lands
somewhere meaningful instead of seeing a raw JSON error. Non-HTML requests
(XHR, fetch with ``Accept: application/json``, curl, etc.) keep getting the
machine-readable 401.

Design notes:
- Pure ASGI three-callable pattern. Never ``BaseHTTPMiddleware`` (see
  CLAUDE.md).
- Exempts ``/auth/*`` from auth checks so login/register pages stay reachable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Optional
from urllib.parse import unquote

from enlace.access import granted_users, is_user_allowed

from enlace_auth.auth.cookies import verify_cookie
from enlace_auth.auth.revocation import shared_cookie_valid
from enlace_auth.auth.sessions import SessionStore

_logger = logging.getLogger("enlace_auth.middleware")

# Headers clients could try to spoof identity with. Always stripped inbound.
_IDENTITY_HEADERS = (
    b"x-user-id",
    b"x-user-email",
    b"x-forwarded-user",
    b"x-forwarded-email",
    b"x-remote-user",
    b"x-remote-email",
    b"x-auth-user",
    b"x-user-groups",
    b"x-forwarded-groups",
)

# Traversal markers that should never appear in a normalized path. We reject
# both raw and percent-encoded forms without touching the rest of the path.
_TRAVERSAL_MARKERS = ("..", "\\", "\x00")
_ENCODED_TRAVERSAL = ("%2e%2e", "%2f%2f", "%5c", "%00")


@dataclass(frozen=True)
class AccessRule:
    """Auth policy for a single mount prefix."""

    prefix: str  # e.g. "/api/my_app" or "/my_app"
    level: str  # "public" | "protected:shared" | "protected:user" | "local"
    app_id: str
    shared_password_hash: Optional[str] = None
    # Optional user whitelist (tuple for hashability). When non-empty, only
    # sessions whose email is in this set can access the app. Evaluated after
    # the standard session check, so it's a second gate on top of level.
    allowed_users: tuple[str, ...] = ()
    # What a signed-in user outside allowed_users gets. True (the default):
    # 403, "you are signed in, this is not for you". False: the same answer as
    # a signed-out one, a sign-in redirect / 401.
    deny_signed_in: bool = True


def _normalize_path(raw_path: str) -> Optional[str]:
    """Return a normalized path or None if the path contains a traversal marker.

    "Normalized" here means collapsed ``//`` and decoded once. We don't try to
    canonicalize `.` vs `./` or case; the goal is to reject known attacks, not
    to rewrite every input.
    """
    if not raw_path:
        return "/"
    lowered = raw_path.lower()
    for m in _ENCODED_TRAVERSAL:
        if m in lowered:
            return None
    decoded = unquote(raw_path)
    for m in _TRAVERSAL_MARKERS:
        if m in decoded:
            return None
    while "//" in decoded:
        decoded = decoded.replace("//", "/")
    return decoded


def _strip_identity_headers(
    headers: list[tuple[bytes, bytes]],
) -> list[tuple[bytes, bytes]]:
    return [(k, v) for (k, v) in headers if k.lower() not in _IDENTITY_HEADERS]


def _parse_cookies(header_value: bytes) -> dict[str, str]:
    """Light RFC-6265 cookie parser that only returns the first occurrence per name."""
    out: dict[str, str] = {}
    for part in header_value.decode("latin-1").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name not in out:
            out[name] = value.strip()
    return out


def _get_cookies(scope) -> dict[str, str]:
    for k, v in scope.get("headers", []):
        if k.lower() == b"cookie":
            return _parse_cookies(v)
    return {}


def _longest_prefix(path: str, rules: Iterable[AccessRule]) -> Optional[AccessRule]:
    best: Optional[AccessRule] = None
    best_len = -1
    for r in rules:
        if path == r.prefix or path.startswith(r.prefix.rstrip("/") + "/"):
            if len(r.prefix) > best_len:
                best = r
                best_len = len(r.prefix)
    return best


async def _send_json_response(send, status: int, body: dict):
    import json as _json

    data = _json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": data})


async def _send_html_response(send, status: int, html: str, *, head: bool = False):
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"text/html; charset=utf-8"),
                (b"cache-control", b"no-store"),
                (b"x-frame-options", b"DENY"),
                (b"content-security-policy", b"frame-ancestors 'none'"),
            ],
        }
    )
    body = b"" if head else html.encode("utf-8")
    await send({"type": "http.response.body", "body": body})


async def _send_redirect(send, location: str):
    await send(
        {
            "type": "http.response.start",
            "status": 303,
            "headers": [
                (b"location", location.encode("latin-1")),
                (b"content-type", b"text/html; charset=utf-8"),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": b""})


async def _reject_websocket(send):
    await send({"type": "websocket.close", "code": 1008})


def _wants_html(scope) -> bool:
    """True if the request looks like a browser HTML navigation.

    Heuristic: GET/HEAD with an ``Accept`` header that prefers ``text/html``.
    XHR/fetch calls typically send ``Accept: application/json`` (or ``*/*``
    with ``X-Requested-With`` / ``Sec-Fetch-Mode: cors``), so they still get
    the JSON 401.
    """
    if scope.get("method", "GET").upper() not in ("GET", "HEAD"):
        return False
    for k, v in scope.get("headers", []):
        if k.lower() == b"accept":
            return b"text/html" in v.lower()
    return False


def _original_target(scope) -> str:
    """The path (and query string) the denied request asked for."""
    raw_path = scope.get("path", "/") or "/"
    raw_qs = scope.get("query_string", b"") or b""
    return f"{raw_path}?{raw_qs.decode('latin-1')}" if raw_qs else raw_path


def _sign_in_origins(scope, cookie_domain: Optional[str]) -> Optional[tuple[str, str]]:
    """``(this origin, the sign-in origin)`` for an app host under *cookie_domain*.

    Such a request is sent to sign in on *cookie_domain* itself, with an absolute
    ``next`` back to this host (#94); the parent host and any host outside the
    domain sign in where they are, as before (None). A port in ``Host`` is kept
    on both: the parent is served where its apps are.
    """
    if not cookie_domain:
        return None
    from enlace_auth.auth.cookie_policy import host_within, request_host, request_port

    headers = scope.get("headers", [])
    host = request_host(headers)
    if host and host != cookie_domain and host_within(host, cookie_domain):
        port = request_port(headers)
        suffix = f":{port}" if port else ""
        return f"https://{host}{suffix}", f"https://{cookie_domain}{suffix}"
    return None


def _redirect_target(
    scope, login_path: str, *, cookie_domain: Optional[str] = None
) -> str:
    """Build the login-redirect URL, preserving the original path as ``next``.

    On an app host under *cookie_domain*, the sign-in page is the parent's and
    ``next`` is this request's absolute ``https://`` URL.
    """
    from urllib.parse import quote

    sep = "&" if "?" in login_path else "?"
    target = _original_target(scope)
    prefix = ""
    if origins := _sign_in_origins(scope, cookie_domain):
        target, prefix = origins[0] + target, origins[1]
    nxt = quote(target, safe="")
    return f"{prefix}{login_path}{sep}login_required=1&next={nxt}"


def _shared_redirect_target(
    scope, shared_login_path: str, app_id: str, *, cookie_domain: Optional[str] = None
) -> str:
    """Build the shared-password redirect URL: the app's form, then ``next``.

    A ``protected:shared`` app is opened with its shared password, never with a
    user account. Sending it to the USER sign-in page instead looped forever for
    anyone already signed in: that page 303s a signed-in visitor straight back
    to ``next``, which denied them again (no shared cookie), and so on.
    """
    from urllib.parse import quote

    sep = "&" if "?" in shared_login_path else "?"
    target = _original_target(scope)
    prefix = ""
    if origins := _sign_in_origins(scope, cookie_domain):
        target, prefix = origins[0] + target, origins[1]
    nxt = quote(target, safe="")
    return f"{prefix}{shared_login_path}{sep}app={quote(app_id, safe='')}&next={nxt}"


class PlatformAuthMiddleware:
    """Pure-ASGI auth middleware. See module docstring for behavior."""

    def __init__(
        self,
        app,
        *,
        access_rules: Iterable[AccessRule],
        session_store: SessionStore,
        signing_key: str,
        cookie_name: str = "enlace_session",
        max_age: int = 86400,
        auth_path_prefix: str = "/auth",
        login_redirect_path: str = "/",
        shared_login_path: Optional[str] = None,
        dynamic_allowed_users: Optional[Callable[[str], set[str]]] = None,
        cookie_domain: Optional[str] = None,
        groups_of: Optional[Callable[[Optional[str]], frozenset[str]]] = None,
    ):
        self.app = app
        self._rules = list(access_rules)
        self._sessions = session_store
        self._signing_key = signing_key
        self._cookie = cookie_name
        self._max_age = max_age
        self._auth_prefix = auth_path_prefix
        self._login_redirect = login_redirect_path
        # Where a browser denied a ``protected:shared`` app goes: that app's
        # shared-password form (served by the auth router), never the user
        # sign-in page, which cannot admit it.
        self._shared_login = shared_login_path or f"{auth_path_prefix}/shared-login"
        # Optional resolver: ``app_id -> set[email]`` of currently-active runtime
        # grants, consulted live per request. Layered ON TOP of each rule's
        # static ``allowed_users``. When None (the default), behavior is
        # identical to a config-only whitelist.
        self._dynamic = dynamic_allowed_users
        # ``[auth] cookie_domain`` (#94): a browser denied on an app host under it
        # is sent to sign in on the domain itself, which sets the shared cookie.
        self._cookie_domain = cookie_domain
        # ``email -> frozenset[group name]`` for ``request.state.user_groups``
        # (#108); None means no groups are configured, so every account is in none.
        self._groups_of = groups_of

    def _set_identity(self, state, session) -> None:
        """Copy the session's account into *state*, with its groups."""
        state["user_id"] = session.get("user_id")
        state["user_email"] = session.get("email")
        if self._groups_of is not None:
            state["user_groups"] = frozenset(self._groups_of(state["user_email"]))

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        raw_path = scope.get("path", "/")
        normalized = _normalize_path(raw_path)
        if normalized is None:
            if scope["type"] == "websocket":
                await _reject_websocket(send)
            else:
                await _send_json_response(send, 400, {"detail": "Bad request path"})
            return

        scope["headers"] = _strip_identity_headers(scope.get("headers", []))
        state = scope.setdefault("state", {})
        # Assigned, never setdefault: scope["state"] starts as a copy of the lifespan
        # state, which any app's lifespan can add keys to, so identity seeded there
        # would reach every request. Only _set_identity sets these (#108).
        state["user_id"] = None
        state["user_email"] = None
        state["user_groups"] = frozenset()

        # /auth/* endpoints bypass the access-rule check (login/register/etc.
        # must stay reachable to anonymous users), but we still opportunistically
        # populate user_id/user_email so endpoints like /auth/whoami and
        # /auth/me/password can act on the authenticated user.
        if (
            normalized.startswith(self._auth_prefix + "/")
            or normalized == self._auth_prefix
        ):
            cookies = _get_cookies(scope)
            token = cookies.get(self._cookie)
            if token:
                session_id = verify_cookie(
                    token, self._signing_key, max_age=self._max_age, salt="session"
                )
                session = self._sessions.get(session_id) if session_id else None
                if session is not None:
                    self._set_identity(state, session)
            await self.app(scope, receive, send)
            return

        # Resolve auth rule for this path.
        rule = _longest_prefix(normalized, self._rules)
        level = rule.level if rule is not None else "protected:user"
        if rule is not None:
            state["app_id"] = rule.app_id

        cookies = _get_cookies(scope)

        if level in ("public", "local"):
            # Public paths still opportunistically populate user_id if the
            # session cookie is valid, so downstream handlers (e.g. /_apps)
            # can filter by access level for authenticated users.
            token = cookies.get(self._cookie)
            if token:
                session_id = verify_cookie(
                    token, self._signing_key, max_age=self._max_age, salt="session"
                )
                session = self._sessions.get(session_id) if session_id else None
                if session is not None:
                    self._set_identity(state, session)
            await self.app(scope, receive, send)
            return

        if level == "protected:shared":
            app_id = rule.app_id if rule is not None else ""
            name = f"shared_auth_{app_id}"
            token = cookies.get(name)
            # The cookie must carry the fingerprint of the app's CURRENT shared
            # password hash: rotating the password ends every older cookie, and
            # an app with no configured password admits no cookie at all.
            value = (
                verify_cookie(
                    token,
                    self._signing_key,
                    max_age=self._max_age,
                    salt=f"shared:{app_id}",
                )
                if token
                else None
            )
            expected_hash = rule.shared_password_hash if rule is not None else None
            if not shared_cookie_valid(value, expected_hash, self._signing_key):
                return await self._deny(scope, send, "shared", app_id=app_id)
            state["user_id"] = "shared"
            await self.app(scope, receive, send)
            return

        if level == "protected:user":
            token = cookies.get(self._cookie)
            session_id = None
            if token:
                session_id = verify_cookie(
                    token, self._signing_key, max_age=self._max_age, salt="session"
                )
            session = self._sessions.get(session_id) if session_id else None
            if session is None:
                return await self._deny(scope, send, "user")
            self._set_identity(state, session)
            # Per-app user whitelist = static config ``allowed_users`` ∪ active
            # runtime grants (the dynamic resolver, when wired), decided by
            # enlace core's ``is_user_allowed`` — the SAME predicate the /_apps
            # launcher calls, so a user sees in the launcher exactly the apps
            # this gate lets them open (enlace issue #35). ``granted_users``
            # resolves grants live, per request, and fails closed on a
            # grants-store error (config users still work).
            if rule is not None and not is_user_allowed(
                state.get("user_id"),
                state.get("user_email"),
                allowed_users=rule.allowed_users,
                granted=granted_users(self._dynamic, rule.app_id),
            ):
                return await self._deny(
                    scope, send, "forbidden", signed_in_403=rule.deny_signed_in
                )
            await self.app(scope, receive, send)
            return

        # Unknown level — deny by default.
        await self._deny(scope, send, "unknown")

    async def _deny(
        self,
        scope,
        send,
        kind: str,
        *,
        signed_in_403: bool = False,
        app_id: Optional[str] = None,
    ):
        if scope["type"] == "websocket":
            await _reject_websocket(send)
            return
        if signed_in_403:
            # Signed in, but this account may not open it: 403, not a sign-in
            # redirect ("you are signed in, this is not for you").
            if _wants_html(scope):
                from enlace_auth.auth.pages import render_forbidden_page

                email = (scope.get("state") or {}).get("user_email")
                page = render_forbidden_page(
                    email=email,
                    switch_url=_redirect_target(
                        scope, self._login_redirect, cookie_domain=self._cookie_domain
                    ),
                )
                head = scope.get("method", "GET").upper() == "HEAD"
                await _send_html_response(send, 403, page, head=head)
                return
            await _send_json_response(
                send, 403, {"detail": "Not allowed for this account", "auth": kind}
            )
            return
        if _wants_html(scope):
            if kind == "shared" and app_id:
                target = _shared_redirect_target(
                    scope,
                    self._shared_login,
                    app_id,
                    cookie_domain=self._cookie_domain,
                )
            else:
                target = _redirect_target(
                    scope, self._login_redirect, cookie_domain=self._cookie_domain
                )
            await _send_redirect(send, target)
            return
        await _send_json_response(
            send, 401, {"detail": "Not authenticated", "auth": kind}
        )


# ---------------------------------------------------------------------------
# CSRF middleware
# ---------------------------------------------------------------------------


def _is_https(scope) -> bool:
    """Whether the request came over HTTPS (directly, or per the proxy's header).

    ``X-Forwarded-Proto`` is trusted only to *add* ``Secure``, which a forged
    header can do no harm with.
    """
    if scope.get("scheme") == "https":
        return True
    for k, v in scope.get("headers", []):
        if k.lower() == b"x-forwarded-proto":
            return v.decode("latin-1").split(",")[0].strip().lower() == "https"
    return False


_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _path_spellings(path: str) -> set[str]:
    """The forms of *path* an upstream router might resolve to the same handler.

    Compared against enforced prefixes so that a spelling the browser sends
    verbatim (``//``, a different case, a ``;param`` suffix) cannot step out
    from under one. Every form only ever adds enforcement.

    >>> sorted(_path_spellings("/api/X//edit;v=1/"))
    ['/api/x//edit/', '/api/x//edit;v=1/', '/api/x/edit/', '/api/x/edit;v=1/']
    """
    from enlace.ratelimit import normalize_path

    forms = {path, unquote(path)}  # unquote: an upstream that decodes twice
    forms |= {normalize_path(f) for f in forms}
    forms |= {"/".join(seg.split(";", 1)[0] for seg in f.split("/")) for f in forms}
    forms |= {normalize_path(f) for f in forms}
    return {f.lower() for f in forms}


def _cross_origin_handshake(scope) -> bool:
    """Whether a websocket handshake names an ``Origin`` other than its ``Host``.

    Browsers always send ``Origin`` on a websocket handshake and the CSRF
    header cannot ride on one, so a page on another host (a sibling under
    ``cookie_domain``) is told apart by its origin. No ``Origin`` is not a
    browser, hence not a forgery. A proxy that rewrites ``Host`` must pass the
    public one on, or same-origin handshakes there are refused (fails closed).

    >>> _cross_origin_handshake({"headers": [(b"host", b"a.io"), (b"origin", b"https://a.io")]})
    False
    >>> _cross_origin_handshake({"headers": [(b"host", b"a.io"), (b"origin", b"https://b.a.io")]})
    True
    >>> _cross_origin_handshake({"headers": [(b"host", b"a.io:443"), (b"origin", b"https://a.io")]})
    False
    """
    from urllib.parse import urlsplit

    headers = {k.lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    origin = headers.get(b"origin")
    if origin is None:
        return False
    try:
        parts = urlsplit(origin.strip())
        scheme, netloc = parts.scheme.lower(), parts.netloc.lower()
    except ValueError:
        return True
    host = headers.get(b"host", "").strip().lower()
    default = {"http": ":80", "https": ":443", "ws": ":80", "wss": ":443"}.get(scheme)
    if default:  # a.io and a.io:443 are the same origin over https
        netloc, host = netloc.removesuffix(default), host.removesuffix(default)
    return netloc != host


def _under_any(path: str, prefixes: tuple[str, ...]) -> bool:
    """Whether some spelling of *path* is one of *prefixes* or below it.

    Prefixes are lower-case with no trailing slash; matching is by whole
    segments, so ``/api/x/edit`` never covers ``/api/x/editor``.

    >>> _under_any("/API/x/Edit/1", ("/api/x/edit",))
    True
    >>> _under_any("/api/x/editor", ("/api/x/edit",))
    False
    """
    return any(
        f == p or f.startswith(p + "/") for f in _path_spellings(path) for p in prefixes
    )


class CSRFMiddleware:
    """Signed double-submit CSRF for state-changing requests.

    On safe-method requests, sets an ``enlace_csrf`` cookie if one isn't
    present. On state-changing requests, requires the cookie and an
    ``X-CSRF-Token`` header to match after signature verification.

    ``mint_prefixes`` narrows *where* the cookie is set (not where the check
    runs): a request outside every prefix never receives one. The default,
    ``None``, mints on every safe request. The platform plugin passes the
    places a state-changing request can follow, so a ``public`` app's pages
    set no cookie (i2mint/enlace_auth#31).

    Exempt paths skip the check entirely. Defaults exempt sub-app APIs
    under ``/api/`` because the ``enlace_session`` cookie is ``SameSite=Lax``:
    a cross-site POST from an attacker site arrives without credentials and
    is rejected by PlatformAuthMiddleware regardless of CSRF. This keeps
    pre-enlace apps working out of the box without each having to implement
    the ``/auth/csrf`` double-submit flow. The auth endpoints themselves
    (``/auth/login``, ``/auth/register``, ``/auth/logout``) stay protected.
    """

    def __init__(
        self,
        app,
        *,
        signing_key: str,
        cookie_name: str = "enlace_csrf",
        header_name: str = "X-CSRF-Token",
        exempt_prefixes: Iterable[str] = (
            "/auth/callback",
            "/auth/login/",
            "/api/",
        ),
        enforce_prefixes: Iterable[str] = (),
        mint_prefixes: Optional[Iterable[str]] = None,
        secure: bool = False,
    ):
        """``enforce_prefixes`` are checked even under an exempt prefix: the per-user
        store routes (``/api/{app}/store``) sit under ``/api/`` but carry data a
        share can expose to someone else's cookie, so they never skip the check,
        and neither do the paths an app opts in with app.toml ``csrf``
        (i2mint/enlace_auth#110). They match by whole segments, ignoring case,
        repeated slashes, dot segments and ``;params``: a looser match only
        enforces more.

        ``mint_prefixes``: path prefixes (whole segments: ``/auth`` matches
        ``/auth`` and ``/auth/x``, not ``/authors``) where the cookie may be
        set. ``None`` means everywhere.

        ``secure`` marks the cookie ``Secure`` (the plugin passes ``[auth]
        secure_cookies``); it is marked so on any HTTPS request regardless (#78).
        The cookie stays host-only under ``cookie_domain``: each host mints its
        own, and the double-submit check works per host."""
        self.app = app
        self._signing_key = signing_key
        self._cookie = cookie_name
        self._secure = secure
        self._enforce = tuple(p.rstrip("/").lower() for p in enforce_prefixes)
        if "" in self._enforce:
            raise ValueError(
                "an enforce prefix cannot be the site root: it would put the "
                "check on every path, the exempt auth callbacks included"
            )
        self._header = header_name.lower().encode("latin-1")
        self._exempt = tuple(exempt_prefixes)
        self._mint = (
            None
            if mint_prefixes is None
            else tuple(p.rstrip("/") for p in mint_prefixes)
        )

    def _may_mint(self, path: str) -> bool:
        if self._mint is None:
            return True
        return any(path == p or path.startswith(p + "/") for p in self._mint)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            # A handshake carries no CSRF header; under an enforced prefix a
            # page on another origin must not open one with the visitor's
            # cookies (#110).
            if _under_any(scope.get("path", "/"), self._enforce) and (
                _cross_origin_handshake(scope)
            ):
                await _reject_websocket(send)
                return
            await self.app(scope, receive, send)
            return
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "/")

        # Exempt paths skip the check entirely.
        is_exempt = any(path.startswith(p) for p in self._exempt) and not _under_any(
            path, self._enforce
        )

        cookies = _get_cookies(scope)
        existing = cookies.get(self._cookie)
        existing_value = (
            verify_cookie(existing, self._signing_key, salt="csrf")
            if existing
            else None
        )

        if method in _SAFE_METHODS or is_exempt:
            # Ensure a token is present on safe requests, where one can be
            # needed (see ``mint_prefixes``).
            if existing_value is None and self._may_mint(path):
                await self._send_with_csrf_cookie(scope, receive, send)
                return
            await self.app(scope, receive, send)
            return

        # State-changing request — enforce double-submit.
        header_value = None
        for k, v in scope.get("headers", []):
            if k.lower() == self._header:
                header_value = v.decode("latin-1")
                break

        if (
            existing_value is None
            or header_value is None
            or header_value != existing_value
        ):
            await _send_json_response(send, 403, {"detail": "CSRF check failed"})
            return

        await self.app(scope, receive, send)

    async def _send_with_csrf_cookie(self, scope, receive, send):
        """Wrap the downstream response to inject a Set-Cookie for CSRF."""
        import secrets

        from enlace_auth.auth.cookies import sign_cookie

        new_value = secrets.token_urlsafe(32)
        signed = sign_cookie(new_value, self._signing_key, salt="csrf")
        attrs = f"{self._cookie}={signed}; Path=/; SameSite=Lax"
        if self._secure or _is_https(scope):
            attrs += "; Secure"
        cookie_header = attrs.encode("latin-1")

        # Expose the minted unsigned value to downstream handlers (e.g.
        # /auth/csrf) so they can return it in the body without minting a
        # second token — otherwise two Set-Cookie headers race and the
        # body-vs-cookie values disagree.
        state = scope.setdefault("state", {})
        state["csrf_token"] = new_value

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                headers = list(message.get("headers", []))
                headers.append((b"set-cookie", cookie_header))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped_send)
