# enlace_auth.auth.middleware

Platform auth middleware (pure ASGI).

Runs before any mounted sub-app. Responsibilities:

1. Normalize the request path and reject known traversal bypasses.
2. Strip client-provided identity headers so apps can’t be fooled by spoofed
   `X-User-ID` / `X-Forwarded-User` / similar.
3. Resolve the access level for the request by longest-prefix match on the
   route prefix of each mounted app. Deny-by-default: an unmatched path is
   treated as `protected:user`.
4. For `public` / `local`, pass through with `user_id=None`.
5. For `protected:shared`, look for a per-app signed cookie; on failure
   return 401 (JSON) or redirect browsers to `login_redirect_path`.
6. For `protected:user`, look for the platform session cookie, load the
   session from `SessionStore`, set `user_id` / `user_email`; on
   failure return 401 (JSON) or redirect browsers to `login_redirect_path`.

Browser vs. API deny behavior: GET/HEAD navigations that look like a browser
(`Accept` header contains `text/html`) get a 303 redirect to the login
page with `?login_required=1&next=<original-path>`, so the user lands
somewhere meaningful instead of seeing a raw JSON error. Non-HTML requests
(XHR, fetch with `Accept: application/json`, curl, etc.) keep getting the
machine-readable 401.

Design notes:

- Pure ASGI three-callable pattern. Never `BaseHTTPMiddleware` (see
  CLAUDE.md).
- Exempts `/auth/*` from auth checks so login/register pages stay reachable.

### Classes

| [`AccessRule`](#enlace_auth.auth.middleware.AccessRule)(prefix, level, app_id[, ...])           | Auth policy for a single mount prefix.                 |
|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------|
| [`CSRFMiddleware`](#enlace_auth.auth.middleware.CSRFMiddleware)(app, \*, signing_key[, ...])        | Signed double-submit CSRF for state-changing requests. |
| [`PlatformAuthMiddleware`](#enlace_auth.auth.middleware.PlatformAuthMiddleware)(app, \*, access_rules, ...) | Pure-ASGI auth middleware.                             |

### *class* enlace_auth.auth.middleware.AccessRule(prefix, level, app_id, shared_password_hash=None, allowed_users=())

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Auth policy for a single mount prefix.

### *class* enlace_auth.auth.middleware.CSRFMiddleware(app, , signing_key, cookie_name='enlace_csrf', header_name='X-CSRF-Token', exempt_prefixes=('/auth/callback', '/auth/login/', '/api/'))

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Signed double-submit CSRF for state-changing requests.

On safe-method requests, sets an `enlace_csrf` cookie if one isn’t
present. On state-changing requests, requires the cookie and an
`X-CSRF-Token` header to match after signature verification.

Exempt paths skip the check entirely. Defaults exempt sub-app APIs
under `/api/` because the `enlace_session` cookie is `SameSite=Lax`:
a cross-site POST from an attacker site arrives without credentials and
is rejected by PlatformAuthMiddleware regardless of CSRF. This keeps
pre-enlace apps working out of the box without each having to implement
the `/auth/csrf` double-submit flow. The auth endpoints themselves
(`/auth/login`, `/auth/register`, `/auth/logout`) stay protected.

### *class* enlace_auth.auth.middleware.PlatformAuthMiddleware(app, , access_rules, session_store, signing_key, cookie_name='enlace_session', max_age=86400, auth_path_prefix='/auth', login_redirect_path='/', dynamic_allowed_users=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI auth middleware. See module docstring for behavior.
