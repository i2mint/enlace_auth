# enlace_auth.admin

Admin subsystem for enlace_auth.

Exposes `/_admin/api/*` endpoints for managing users and viewing app access
policy. Gated by an admin email allowlist supplied at construction time.

The middleware (`PlatformAuthMiddleware`) is what enforces “admin only” — it
sees the `/_admin` access rule with `allowed_users=admin_emails` and rejects
everyone else. The router itself only needs to enforce the *narrower* “any
authenticated user” gate for self-service endpoints like `/me/password`.

### Functions

| [`make_admin_router`](#enlace_auth.admin.make_admin_router)(\*, user_store, session_store)   | Build a FastAPI router exposing `/_admin/api/*` endpoints.   |
|-----------------------------------------------------------------------------------------------------|--------------------------------------------------------------|

### enlace_auth.admin.make_admin_router(, user_store, session_store, admin_emails=(), apps=(), grant_store=None, protected_user_apps=(), signing_key=None, reset_link_ttl=259200, resource_allowlist=None, public_base_url=None, on_credentials_changed=None)

Build a FastAPI router exposing `/_admin/api/*` endpoints.

`admin_emails` is captured by closure so the router can enforce
last-admin protection on delete. The middleware handles the broader
“must be an admin to see /_admin” check.

`grant_store` (a [`GrantStore`](enlace_auth.auth.grants.html.md#enlace_auth.auth.grants.GrantStore)) and
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

`on_credentials_changed` (`hook(email, *, keep=None)`) runs after a
user is deleted or has their password set. The default revokes the
account’s browser sessions; the plugin injects one that also revokes its
OAuth connector refresh families (`enlace_auth.auth.revocation`).

* **Return type:**
  `APIRouter`

### Modules

| [`routes`](enlace_auth.admin.routes.html.md#module-enlace_auth.admin.routes)   | Admin HTTP routes: user CRUD, password reset, app policy + grants.   |
|-------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
