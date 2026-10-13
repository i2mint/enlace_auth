"""One normal form for an email address, wherever one is compared.

Accounts are keyed by the address the HTTP routes accept (pydantic ``EmailStr``,
then lowercased): ``EmailStr`` decodes a punycode domain to Unicode, so
``admin@xn--bcher-kva.example`` is stored as ``admin@bücher.example``. Every list
an address is compared against (the admin list, the registration allowlist, a
connector's resource allowlist) must be put in the same form, or an entry
spelled the other way silently never matches.
"""

from __future__ import annotations

from functools import lru_cache

__all__ = ["normalize_email"]


#: Characters that only appear in the display-name or quoted forms, or in a list.
_NOT_IN_A_BARE_ADDRESS = frozenset('<>"(),;')


@lru_cache(maxsize=1)
def _email_adapter():
    from pydantic import EmailStr, TypeAdapter

    return TypeAdapter(EmailStr)


def normalize_email(email: str) -> str:
    """The key an account for *email* is stored under; ``ValueError`` if invalid.

    >>> normalize_email("  Admin@XN--BCHER-KVA.example ")
    'admin@bücher.example'
    >>> normalize_email("A@Example.COM")
    'a@example.com'

    Only a bare address is accepted. ``EmailStr`` also parses the display-name
    form, so ``ann <mallory@evil.com>`` would otherwise normalize to an address
    the text does not appear to name; in a list that grants access, that is a
    grant to someone other than the one written down.

    >>> normalize_email("ann <mallory@evil.com>")
    Traceback (most recent call last):
    ...
    ValueError: not a bare email address: 'ann <mallory@evil.com>'
    """
    from pydantic import ValidationError

    bare = email.strip()
    if any(c in _NOT_IN_A_BARE_ADDRESS or c.isspace() for c in bare):
        raise ValueError(f"not a bare email address: {email!r}")
    try:
        return _email_adapter().validate_python(bare).lower()
    except ValidationError as e:
        raise ValueError(f"not a valid email address: {email!r}") from e
