# enlace_auth.stores.prefixed

PrefixedStore — MutableMapping wrapper that scopes keys under a prefix.

The per-user injection pattern: a single base store is shared across all users
and apps, but each request sees a `PrefixedStore(base, f"{user_id}/{app_id}/")`
so keys can’t collide across tenants.

Keys the caller passes are validated via `sanitize_key`; the prefix itself is
sanitized at construction (each slash-separated segment).

### Classes

| [`PrefixedStore`](#enlace_auth.stores.prefixed.PrefixedStore)(base, prefix)   | Transparently prepend a prefix to every key operation on a base store.   |
|--------------------------------------------------------------------------------|--------------------------------------------------------------------------|

### *class* enlace_auth.stores.prefixed.PrefixedStore(base, prefix)

Bases: [`MutableMapping`](https://docs.python.org/3/library/collections.abc.html#collections.abc.MutableMapping)

Transparently prepend a prefix to every key operation on a base store.
