# enlace_auth.admin.routes

Admin HTTP routes: user CRUD, password reset, app policy + grants.

Endpoints (all under `/_admin/api/`):

- `GET    /users`                — list registered users
- `POST   /users`                — create a user (admin-created)
- `DELETE /users/{email}`        — delete a user (refuses last admin)
- `POST   /users/{email}/password` — admin reset another user’s password
- `POST   /users/{email}/reset-link` — mint a one-time link the user follows
  to choose their *own* password. Preferred over the endpoint above: the admin
  never learns, transmits, or has to invent a credential. It is also the only
  recovery path that works when no SMTP sender is configured, since the admin
  delivers the link by hand.
- `GET    /apps`                 — list apps with their access policy +
  (for `protected:user` apps) their runtime grants
- `POST   /grants`               — grant a user runtime access to an app
- `DELETE /grants/{app_id}/{email}` — revoke a runtime grant

A minimal HTML dashboard is also mounted at `GET /_admin/` (and
`/_admin/index.html`); it consumes the JSON endpoints above. The HTML
lives next to this file at `static/index.html` and is served via
`importlib.resources` so it ships in the wheel without any build step.

Self-service `POST /auth/me/password` (change own password) lives in
`enlace_auth.auth.routes` so it’s reachable to any authenticated user — it
is NOT under `/_admin` because the admin access rule would block non-admins.

Access control:

- `/_admin/*` is gated by `PlatformAuthMiddleware` via the access rule the
  plugin installs (`allowed_users=admin_emails`). By the time a request
  reaches this router, the caller is an admin.

Runtime grants are ADDITIVE on top of each app’s static `app.toml`
`allowed_users` and carry an optional UTC expiry — see
`enlace_auth.auth.grants`.

### Functions

| [`make_admin_router`](#enlace_auth.admin.routes.make_admin_router)(\*, user_store, session_store)   | Build a FastAPI router exposing `/_admin/api/*` endpoints.     |
|-----------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| [`make_admin_ui_router`](#enlace_auth.admin.routes.make_admin_ui_router)()                             | Build a FastAPI router that serves the bundled HTML dashboard. |

### enlace_auth.admin.routes.make_admin_router(, user_store, session_store, admin_emails=(), apps=(), grant_store=None, protected_user_apps=(), signing_key=None, reset_link_ttl=259200, resource_allowlist=None, public_base_url=None)

Build a FastAPI router exposing `/_admin/api/*` endpoints.

`admin_emails` is captured by closure so the router can enforce
last-admin protection on delete. The middleware handles the broader
“must be an admin to see /_admin” check.

`grant_store` (a [`GrantStore`](enlace_auth.auth.grants.md#enlace_auth.auth.grants.GrantStore)) and
`protected_user_apps` enable the runtime grant endpoints. When
`grant_store` is None those endpoints return 503.

`signing_key` enables the reset-link endpoint (same key the auth router
signs with, so the link it mints verifies there). Omit it and that endpoint
returns 503, mirroring how `grant_store` gates the grant endpoints.
`public_base_url` is the platform’s public origin for minted reset links
(falls back to the request origin).

`reset_link_ttl` is how long a minted link stays usable — longer than an
emailed one, because delivery is a human round trip.

`resource_allowlist` is the OAuth server’s per-connector allow-list (see
`enlace_auth.auth.oauth_server`). It exists here purely so `/apps` can
tell the truth about connectors: an OAuth resource server is declared
`access = "public"` because enlace must NOT gate it at the session layer
— it authenticates its own bearer tokens instead. Reporting that as a bare
“public” badge invites the reader to conclude private data is world-open
(it isn’t) or, worse, to make some *other* app public by analogy (which
would be). Passing the allow-list lets the dashboard show who can actually
reach each one.

* **Return type:**
  `APIRouter`

### enlace_auth.admin.routes.make_admin_ui_router()

Build a FastAPI router that serves the bundled HTML dashboard.

Mounted at `/_admin/`; gated by the same admin access rule as the API,
so unauthenticated browsers get redirected to login by the auth
middleware before they ever reach this handler.

* **Return type:**
  `APIRouter`
