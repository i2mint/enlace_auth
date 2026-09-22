# enlace_auth.stores.validation

Key sanitization for user-supplied store keys.

Blocks the standard path-traversal attack surface: `..` segments, backslashes,
null bytes, control characters, absolute paths, and URL-encoded variants. Keys
that survive sanitization are still filesystem-safe and can be composed into a
prefix without risk of escaping the tenant namespace.

### Functions

| [`sanitize_key`](#enlace_auth.stores.validation.sanitize_key)(key)   | Return `key` unchanged if safe for use as a store path component.   |
|----------------------------------------------------------------------|---------------------------------------------------------------------|

### enlace_auth.stores.validation.sanitize_key(key)

Return `key` unchanged if safe for use as a store path component.

Raises `ValueError` with a specific reason if the key is unsafe. The goal
is fail-fast: we want the caller to see exactly why a key was rejected, not
a silently rewritten value.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)
