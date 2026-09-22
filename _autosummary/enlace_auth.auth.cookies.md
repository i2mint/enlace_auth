# enlace_auth.auth.cookies

Signed cookie helpers built on itsdangerous.

We wrap `URLSafeTimedSerializer` so signing_key rotation and `max_age` checks
are centralised; callers never touch itsdangerous directly.

### Functions

| [`sign_cookie`](#enlace_auth.auth.cookies.sign_cookie)(value, signing_key, \*[, salt])   | Return a signed, URL-safe token carrying `value`.               |
|------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| [`verify_cookie`](#enlace_auth.auth.cookies.verify_cookie)(token, signing_key, \*[, ...])  | Return the original value iff the token is valid and unexpired. |

### enlace_auth.auth.cookies.sign_cookie(value, signing_key, , salt='enlace-cookie')

Return a signed, URL-safe token carrying `value`.

* **Return type:**
  [`str`](https://docs.python.org/3/builtins/stdtypes.html#str)

### enlace_auth.auth.cookies.verify_cookie(token, signing_key, , max_age=None, salt='enlace-cookie')

Return the original value iff the token is valid and unexpired.

* **Return type:**
  [`Optional`](https://docs.python.org/3/library/typing.html#typing.Optional)[[`str`](https://docs.python.org/3/builtins/stdtypes.html#str)]
