"""Per-user stores for enlace.

Apps never import from this package. Apps read ``request.state.store`` — a
``MutableMapping`` scoped to ``{user_id}/{app_id}/`` via ``PrefixedStore``.

Public helpers:

- ``PrefixedStore`` — wraps any MutableMapping with a key prefix.
- ``sanitize_key`` — path-traversal guard for user-supplied keys.
- ``make_file_store_factory`` — file-backed MutableMapping factory.
- ``StoreInjectionMiddleware`` — pure-ASGI middleware that injects
  ``scope["state"]["store"]`` based on ``user_id`` and ``app_id``.
- ``make_store_router`` — FastAPI router for ``/api/{app_id}/store/{key}``.
"""

from enlace_auth.stores.backends import StoreFactory, make_file_store_factory
from enlace_auth.stores.middleware import StoreInjectionMiddleware, make_store_router
from enlace_auth.stores.prefixed import PrefixedStore
from enlace_auth.stores.validation import sanitize_key

__all__ = [
    "PrefixedStore",
    "StoreFactory",
    "StoreInjectionMiddleware",
    "make_file_store_factory",
    "make_store_router",
    "sanitize_key",
]
