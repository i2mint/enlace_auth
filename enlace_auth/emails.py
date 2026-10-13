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

__all__ = ["account_spellings", "bare_address_problem", "normalize_email"]


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
    if bare_address_problem(bare):
        raise ValueError(f"not a bare email address: {email!r}")
    try:
        return _email_adapter().validate_python(bare).lower()
    except ValidationError as e:
        raise ValueError(f"not a valid email address: {email!r}") from e


def bare_address_problem(email: str) -> str | None:
    """Why *email* is not a bare ``local@domain`` address, or ``None``.

    Deliberately lenient about the domain (``.local``, ``localhost``): it only
    refuses what is not one plain address, such as the display-name form.

    >>> bare_address_problem("ann@corp.local") is None
    True
    >>> bare_address_problem("ann <mallory@evil.com>")
    'not a bare email address'
    """
    if any(c in _NOT_IN_A_BARE_ADDRESS or c.isspace() for c in email):
        return "not a bare email address"
    local, at, domain = email.partition("@")
    if not (at and local and domain) or "@" in domain:
        return "not an email address"
    return None


def account_spellings(email: str) -> frozenset[str]:
    """The keys an account for an operator-written *email* may be stored under.

    As written, lowercased (how an OAuth sign-in keys it), and normalized (how
    ``add-user`` and ``/auth/register`` key it), when those differ. For lists an
    operator wrote, never for an address an untrusted party sent: normalizing
    that could fold a look-alike spelling onto someone else's account.

    >>> sorted(account_spellings("Ann@XN--BCHER-KVA.example"))
    ['ann@bücher.example', 'ann@xn--bcher-kva.example']
    >>> sorted(account_spellings("ann@corp.local"))
    ['ann@corp.local']
    """
    forms = {email.strip().lower()}
    try:
        forms.add(normalize_email(email))
    except ValueError:
        pass  # a domain EmailStr refuses (.local): only the written form
    return frozenset(forms)
