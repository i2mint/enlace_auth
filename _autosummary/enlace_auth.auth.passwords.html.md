# enlace_auth.auth.passwords

Password hashing via argon2id.

argon2-cffi ships `PasswordHasher` which handles salting, tuning, and
constant-time verification. We surface only two helpers to keep callers away
from parameter tuning.

### Module Attributes

| [`MIN_PASSWORD_LEN`](#enlace_auth.auth.passwords.MIN_PASSWORD_LEN)   | registration, the admin API, reset, change, and the `add-user` / `set-password` CLI.   |
|---------------------------------------------------------------------|----------------------------------------------------------------------------------------|

### Functions

| [`hash_password`](#enlace_auth.auth.passwords.hash_password)(password)           | Return an argon2id hash string for `password`.                |
|------------------------------------------------------------------------------------|---------------------------------------------------------------|
| [`password_problem`](#enlace_auth.auth.passwords.password_problem)(password)        | Why *password* may not be set, or `None` if it may.           |
| [`verify_password`](#enlace_auth.auth.passwords.verify_password)(hashed, password) | Return True iff `password` matches the stored `hashed` value. |

### enlace_auth.auth.passwords.MIN_PASSWORD_LEN *= 8*

registration, the
admin API, reset, change, and the `add-user` / `set-password` CLI.

* **Type:**
  Minimum password length, for every way a password is set

### enlace_auth.auth.passwords.hash_password(password)

Return an argon2id hash string for `password`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.passwords.password_problem(password)

Why *password* may not be set, or `None` if it may.

The one rule every way of setting a password applies (see
[`MIN_PASSWORD_LEN`](#enlace_auth.auth.passwords.MIN_PASSWORD_LEN)), so they cannot drift apart.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str) | [`None`](https://docs.python.org/3/builtins/constants.html#None)

```pycon
>>> password_problem("long-enough")
>>> password_problem("short")
'Password must be at least 8 characters.'
```

### enlace_auth.auth.passwords.verify_password(hashed, password)

Return True iff `password` matches the stored `hashed` value.

* **Return type:**
  [`bool`](https://docs.python.org/3/builtins/functions.html#bool)
