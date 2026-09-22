# enlace_auth.auth.passwords

Password hashing via argon2id.

argon2-cffi ships `PasswordHasher` which handles salting, tuning, and
constant-time verification. We surface only two helpers to keep callers away
from parameter tuning.

### Functions

| [`hash_password`](#enlace_auth.auth.passwords.hash_password)(password)           | Return an argon2id hash string for `password`.                |
|------------------------------------------------------------------------------------|---------------------------------------------------------------|
| [`verify_password`](#enlace_auth.auth.passwords.verify_password)(hashed, password) | Return True iff `password` matches the stored `hashed` value. |

### enlace_auth.auth.passwords.hash_password(password)

Return an argon2id hash string for `password`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.passwords.verify_password(hashed, password)

Return True iff `password` matches the stored `hashed` value.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)
