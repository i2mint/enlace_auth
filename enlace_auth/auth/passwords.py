"""Password hashing via argon2id.

argon2-cffi ships `PasswordHasher` which handles salting, tuning, and
constant-time verification. We surface only two helpers to keep callers away
from parameter tuning.
"""

from __future__ import annotations

#: Minimum password length, for every way a password is set: registration, the
#: admin API, reset, change, and the ``add-user`` / ``set-password`` CLI.
MIN_PASSWORD_LEN = 8


def password_problem(password: str) -> str | None:
    """Why *password* may not be set, or ``None`` if it may.

    The one rule every way of setting a password applies (see
    :data:`MIN_PASSWORD_LEN`), so they cannot drift apart.

    >>> password_problem("long-enough")
    >>> password_problem("short")
    'Password must be at least 8 characters.'
    """
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    return None


def _hasher():
    try:
        from argon2 import PasswordHasher  # type: ignore
    except ImportError as e:
        raise ImportError(
            "argon2-cffi is required for password hashing. "
            "Install it via `pip install enlace[auth]`."
        ) from e
    return PasswordHasher()


def hash_password(password: str) -> str:
    """Return an argon2id hash string for ``password``."""
    return _hasher().hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """Return True iff ``password`` matches the stored ``hashed`` value."""
    try:
        from argon2.exceptions import VerifyMismatchError  # type: ignore
    except ImportError:
        VerifyMismatchError = Exception  # type: ignore[assignment,misc]
    ph = _hasher()
    try:
        ph.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception:
        return False
