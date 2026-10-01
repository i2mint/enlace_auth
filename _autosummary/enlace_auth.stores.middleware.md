# enlace_auth.stores.middleware

Store injection middleware and per-app store router.

`StoreInjectionMiddleware` runs after the auth middleware. It reads
`scope["state"]["user_id"]` and `scope["state"]["app_id"]` (the latter set
by the per-mount wrapper in `enlace.compose`) and attaches a
`PrefixedStore(base, f"{user_id}/{app_id}/")` to `scope["state"]["store"]`.

If either id is missing, `store` is `None` — apps are expected to handle
that case gracefully (they do so naturally by providing a dict fallback in
standalone mode).

### Module Attributes

| [`NO_ACCESS`](#enlace_auth.stores.middleware.NO_ACCESS)         | no (more) share for `?owner=`, or no such key.                            |
|--------------------------------------------------------------------|---------------------------------------------------------------------------|
| [`DEFAULT_MAX_ITEMS`](#enlace_auth.stores.middleware.DEFAULT_MAX_ITEMS) | How many items the list route returns before it says `"truncated": true`. |

### Functions

| [`etag_of`](#enlace_auth.stores.middleware.etag_of)(value)                                | A strong ETag for a stored JSON value: a hash of its canonical serialisation.   |
|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------|
| [`make_store_router`](#enlace_auth.stores.middleware.make_store_router)(\*, base_store_getter, ...) | Return a router exposing the per-user store of each app that has one.           |

### Classes

| [`StoreInjectionMiddleware`](#enlace_auth.stores.middleware.StoreInjectionMiddleware)(app, \*[, base_store])   | Pure-ASGI middleware that injects `request.state.store`.   |
|----------------------------------------------------------------------------------------------------|------------------------------------------------------------|

### enlace_auth.stores.middleware.DEFAULT_MAX_ITEMS *= 5000*

How many items the list route returns before it says `"truncated": true`.

### enlace_auth.stores.middleware.NO_ACCESS *= 'no_access'*

no (more) share for `?owner=`, or no such key.

* **Type:**
  The 404 details of the store routes

### *class* enlace_auth.stores.middleware.StoreInjectionMiddleware(app, , base_store=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI middleware that injects `request.state.store`.

### enlace_auth.stores.middleware.etag_of(value)

A strong ETag for a stored JSON value: a hash of its canonical serialisation.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.stores.middleware.make_store_router(, base_store_getter, protected_apps, share_access=None, max_items=5000)

Return a router exposing the per-user store of each app that has one.

Routes:

- `GET    /api/{app_id}/store?prefix=<p>`
  → `{"items": {key: {"value", "etag"}}, "truncated"}`
- `GET    /api/{app_id}/store/{key}` → `{"value": v}` with an `ETag` header
- `PUT    /api/{app_id}/store/{key}` — conditional with `If-Match: <etag>`
  or `If-None-Match: *`
- `DELETE /api/{app_id}/store/{key}` — `If-Match` likewise

A failed precondition is **412** with the current `{"value", "etag"}` (`value`
null when the key is absent), so the client can resolve and retry.

`protected_apps` names the apps with a per-user store: `protected:user`
apps and those whose `app.toml` sets `user_store = true` (a callable is
re-read per request). `?owner=<email>` on any route acts on that user’s
data instead of the caller’s, when `share_access(app_id, owner, caller)`
says so (`"rw"`, or `"ro"` for GET only); otherwise 404, as if the owner
had nothing. Without `share_access` every `?owner=` naming someone else
is 404. See `misc/docs/decisions/0001-owner-granted-data-shares.md`.

The router assumes `PlatformAuthMiddleware` has set `request.state.user_id`
(public apps get it too, when the visitor is signed in). CSRF on writes is the
`CSRFMiddleware`’s, through its `enforce_prefixes`.

* **Return type:**
  `APIRouter`
