# enlace_auth.stores.middleware

Store injection middleware and per-app store router.

`StoreInjectionMiddleware` runs after the auth middleware. It reads
`scope["state"]["user_id"]` and `scope["state"]["app_id"]` (the latter set
by the per-mount wrapper in `enlace.compose`) and attaches a
`PrefixedStore(base, f"{user_id}/{app_id}/")` to `scope["state"]["store"]`.

If either id is missing, `store` is `None` — apps are expected to handle
that case gracefully (they do so naturally by providing a dict fallback in
standalone mode).

### Functions

| [`make_store_router`](#enlace_auth.stores.middleware.make_store_router)(\*, base_store_getter, ...)   | Return a router exposing `/api/{app_id}/store/{key}` endpoints.   |
|--------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|

### Classes

| [`StoreInjectionMiddleware`](#enlace_auth.stores.middleware.StoreInjectionMiddleware)(app, \*[, base_store])   | Pure-ASGI middleware that injects `request.state.store`.   |
|----------------------------------------------------------------------------------------------------|------------------------------------------------------------|

### *class* enlace_auth.stores.middleware.StoreInjectionMiddleware(app, , base_store=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI middleware that injects `request.state.store`.

### enlace_auth.stores.middleware.make_store_router(, base_store_getter, protected_apps)

Return a router exposing `/api/{app_id}/store/{key}` endpoints.

Only apps whose name is in `protected_apps` (i.e. `protected:user`
access level) can have their store accessed this way. The router assumes
`PlatformAuthMiddleware` has already set `request.state.user_id`.

* **Return type:**
  `APIRouter`
