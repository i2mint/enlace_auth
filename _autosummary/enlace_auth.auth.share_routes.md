# enlace_auth.auth.share_routes

`/auth/shares/*` — the signed-in user manages the shares of their own data.

The owner side of a share is always the signed-in user: there is no route by which
a grantee can grant onward, or anyone can share someone else’s data (an admin does
that through `/_admin/api/shares` or the CLI). These routes live under `/auth/`,
so the platform’s double-submit CSRF check covers every write.

- `GET    /auth/shares/{app_id}` → `{"owner", "granted": [...], "received": [...]}`
- `PUT    /auth/shares/{app_id}/{grantee}`
  (body `{"access"?, "label"?, "expires_at"?}`)
- `DELETE /auth/shares/{app_id}/received/{owner}` — a grantee leaves a share
- `DELETE /auth/shares/{app_id}/{grantee}` — the owner revokes one

See `misc/docs/decisions/0001-owner-granted-data-shares.md`.

### Functions

| [`make_share_router`](#enlace_auth.auth.share_routes.make_share_router)(\*, share_store, store_apps)   | Build the `/auth/shares` router.   |
|---------------------------------------------------------------------------------------------------|------------------------------------|

### enlace_auth.auth.share_routes.make_share_router(, share_store, store_apps)

Build the `/auth/shares` router.

`store_apps` names the apps that have a per-user store (`protected:user`
apps and `user_store = true` apps); a share in any other app is refused,
since there would be nothing to share. A callable is re-read per request.

* **Return type:**
  `APIRouter`
