# enlace_auth.stores

Per-user stores for enlace.

Apps never import from this package. Apps read `request.state.store` — a
`MutableMapping` scoped to `{user_id}/{app_id}/` via `PrefixedStore`.

Public helpers:

- `PrefixedStore` — wraps any MutableMapping with a key prefix.
- `sanitize_key` — path-traversal guard for user-supplied keys.
- `make_file_store_factory` — file-backed MutableMapping factory.
- `StoreInjectionMiddleware` — pure-ASGI middleware that injects
  `scope["state"]["store"]` based on `user_id` and `app_id`.
- `make_store_router` — FastAPI router for `/api/{app_id}/store/{key}`.

### Functions

| [`make_file_store_factory`](#enlace_auth.stores.make_file_store_factory)(root, \*[, use_dol])   | Return a `StoreFactory` backed by JSON files under `root`.        |
|-------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| [`make_store_router`](#enlace_auth.stores.make_store_router)(\*, base_store_getter, ...)  | Return a router exposing `/api/{app_id}/store/{key}` endpoints.   |
| [`sanitize_key`](#enlace_auth.stores.sanitize_key)(key)                              | Return `key` unchanged if safe for use as a store path component. |

### Classes

| [`PrefixedStore`](#enlace_auth.stores.PrefixedStore)(base, prefix)                     | Transparently prepend a prefix to every key operation on a base store.   |
|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| [`StoreInjectionMiddleware`](#enlace_auth.stores.StoreInjectionMiddleware)(app, \*[, base_store]) | Pure-ASGI middleware that injects `request.state.store`.                 |

### *class* enlace_auth.stores.PrefixedStore(base, prefix)

Bases: [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)

Transparently prepend a prefix to every key operation on a base store.

### *class* enlace_auth.stores.StoreInjectionMiddleware(app, , base_store=None)

Bases: [`object`](https://docs.python.org/3/builtins/functions.html#object)

Pure-ASGI middleware that injects `request.state.store`.

### enlace_auth.stores.make_file_store_factory(root, , use_dol=False)

Return a `StoreFactory` backed by JSON files under `root`.

`factory(name)` returns a `MutableMapping` rooted at `root/name/`.

Defaults to a small stdlib implementation that auto-creates parent
directories on write. Pass `use_dol=True` to use `dol.Files` instead
(pulls in the soft dep and expects flat keys).

* **Return type:**
  [`Callable`](https://docs.python.org/3/library/typing.html#typing.Callable)[[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)], [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)]

### enlace_auth.stores.make_store_router(, base_store_getter, protected_apps)

Return a router exposing `/api/{app_id}/store/{key}` endpoints.

Only apps whose name is in `protected_apps` (i.e. `protected:user`
access level) can have their store accessed this way. The router assumes
`PlatformAuthMiddleware` has already set `request.state.user_id`.

* **Return type:**
  `APIRouter`

### enlace_auth.stores.sanitize_key(key)

Return `key` unchanged if safe for use as a store path component.

Raises `ValueError` with a specific reason if the key is unsafe. The goal
is fail-fast: we want the caller to see exactly why a key was rejected, not
a silently rewritten value.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### Modules

| [`backends`](enlace_auth.stores.backends.html.md#module-enlace_auth.stores.backends)     | MutableMapping-backed store factories for enlace.                       |
|--------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [`middleware`](enlace_auth.stores.middleware.html.md#module-enlace_auth.stores.middleware) | Store injection middleware and per-app store router.                    |
| [`prefixed`](enlace_auth.stores.prefixed.html.md#module-enlace_auth.stores.prefixed)     | PrefixedStore — MutableMapping wrapper that scopes keys under a prefix. |
| [`validation`](enlace_auth.stores.validation.html.md#module-enlace_auth.stores.validation) | Key sanitization for user-supplied store keys.                          |
