"""One normal form for an email address, wherever one is compared.

Accounts are keyed by the address the HTTP routes accept (pydantic ``EmailStr``,
then lowercased): ``EmailStr`` decodes a punycode domain to Unicode, so
``admin@xn--bcher-kva.example`` is stored as ``admin@bücher.example``. Every list
an address is compared against (the admin list, the registration allowlist, a
connector's resource allowlist) must be put in the same form, or an entry
spelled the other way silently never matches.

One fold is refused rather than applied: ``EmailStr`` NFC-composes the local
part, but a mail system may deliver a composed and a decomposed local part to two
mailboxes, which one key would merge (#51). :func:`normalize_email` refuses a
local part that composing would change. So is one that lowercasing would
change by more than case (``İ`` -> ``i̇``, ``ẞ`` -> ``ß``, #57).

Two rules keep that safe. A written list entry is widened to both canonical
spellings of its address (:func:`account_spellings`); the address an account is
keyed under, which may come from an untrusted party (an OAuth provider), is
compared exactly as stored and never normalized.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

__all__ = [
    "account_spellings",
    "bare_address_problem",
    "local_part_problem",
    "lowercase_changes_letter",
    "normalize_email",
    "resolve_account",
]


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

    Nor is a local part that composing would change (see
    :func:`local_part_problem`): the key would name another mailbox's spelling.

    >>> normalize_email("jose\u0301@example.com")  # doctest: +ELLIPSIS
    Traceback (most recent call last):
    ...
    ValueError: the part before @ is not in composed (NFC) form...
    """
    from pydantic import ValidationError

    bare = email.strip()
    if bare_address_problem(bare):
        raise ValueError(f"not a bare email address: {_shown(email)}")
    if problem := local_part_problem(bare):
        raise ValueError(f"{problem}: {_shown(email)}")
    try:
        return _email_adapter().validate_python(bare).lower()
    except ValidationError as e:
        raise ValueError(f"not a valid email address: {_shown(email)}") from e


#: How much of a refused address an error message repeats back.
_SHOWN_LENGTH = 80


def _shown(email: str) -> str:
    """*email* for an error message: quoted, and cut short if it is long."""
    if len(email) > _SHOWN_LENGTH:
        email = email[: _SHOWN_LENGTH - 3] + "..."
    return repr(email)


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


def local_part_problem(email: str) -> str | None:
    """Why keying *email* would change its local part's characters, or ``None``.

    ``EmailStr`` NFC-composes the local part. Mail systems that compare local
    parts as bytes (a Postfix/Dovecot host with ``SMTPUTF8``, for one) deliver
    ``josé`` composed and ``josé`` decomposed to two mailboxes, so composing
    would map both onto one account (#51). A decomposed local part is refused,
    not folded, as an OAuth callback's address is never folded.

    >>> local_part_problem("jos\u00e9@example.com") is None
    True
    >>> local_part_problem("jose\u0301@example.com")
    'the part before @ is not in composed (NFC) form (U+0301); retype the address'

    The two spellings look identical, so the message names the first character
    to blame.

    Keys are also lowercased, and for a few letters that changes the letter, not
    only its case (#57): ``İ`` becomes ``i`` plus a combining dot, ``ẞ`` becomes
    ``ß``. A host that compares local parts as bytes reads another mailbox, and a
    password reset is mailed to the key. Such a local part is refused too.

    >>> local_part_problem("Ann@example.com") is None
    True
    >>> local_part_problem("\u0130stanbul@example.com")
    'the part before @ changes letters when lowercased (U+0130); retype the address'
    """
    local = email.rpartition("@")[0]
    if unicodedata.is_normalized("NFC", local):
        if culprit := lowercase_changes_letter(local):
            return (
                f"the part before @ changes letters when lowercased "
                f"(U+{ord(culprit):04X}); retype the address"
            )
        return None
    culprit = next(
        (
            c
            for c in local
            if unicodedata.combining(c) or not unicodedata.is_normalized("NFC", c)
        ),
        None,
    )
    named = f" (U+{ord(culprit):04X})" if culprit else ""
    return f"the part before @ is not in composed (NFC) form{named}; retype the address"


def lowercase_changes_letter(text: str) -> str | None:
    """The first character of *text* that lowercasing changes by more than case.

    A case map is one character for one, and goes back: ``"A".lower().upper()``
    is ``"A"`` (``.title()`` for a titlecase digraph such as ``ǅ``). ``İ``
    lowercases to two characters, ``ẞ`` to ``ß`` (which uppercases to ``SS``),
    the Kelvin sign to ``k`` (which uppercases to ``K``).

    >>> lowercase_changes_letter("Ann-Marie") is None
    True
    >>> [hex(ord(lowercase_changes_letter(s))) for s in ("\u0130", "\u1e9e", "\u212a")]
    ['0x130', '0x1e9e', '0x212a']
    """
    for c in text:
        lowered = c.lower()
        if lowered == c:
            continue
        if len(lowered) != 1 or c not in (lowered.upper(), lowered.title()):
            return c
    return None


#: RFC 5321's limit on a forward path; nothing longer is a deliverable address.
_MAX_ADDRESS_LENGTH = 254


def lowercase_folds_to_ascii(email: str) -> bool:
    """Whether lowercasing turns a non-ASCII letter of *email* into plain ASCII.

    Such a letter is a look-alike: the lowercased address would name a
    different, ASCII mailbox than the one written.

    >>> lowercase_folds_to_ascii("\u212aen@corp.com")  # KELVIN SIGN
    True
    >>> lowercase_folds_to_ascii("Ken@corp.com"), lowercase_folds_to_ascii("Ünï@x.de")
    (False, False)
    """
    return any(not c.isascii() and c.lower().isascii() for c in email)


def account_spellings(email: str) -> tuple[str, ...]:
    """The keys an account for a written *email* may be stored under, as written first.

    A punycode domain and its Unicode form are one DNS name, so they name one
    mailbox, but an account is keyed in whichever spelling made it: ``add-user``
    and ``/auth/register`` store the Unicode form, an OAuth sign-in stores the
    provider's spelling, lowercased. A list entry written in either canonical
    spelling therefore admits both.

    >>> account_spellings("Ann@XN--BCHER-KVA.example")
    ('ann@xn--bcher-kva.example', 'ann@bücher.example')
    >>> account_spellings("ann@bücher.example")
    ('ann@bücher.example', 'ann@xn--bcher-kva.example')
    >>> account_spellings("ann@corp.local")  # a domain EmailStr refuses
    ('ann@corp.local',)

    Only an entry already in one of the two canonical spellings gets the other.
    Normalizing also folds look-alikes (fullwidth letters, the Kelvin sign) onto
    plain ASCII, so an entry that only becomes canonical by normalizing stays as
    written: it must not name someone else's account. That makes this safe to
    apply to any written list, an untrusted user's included. It is never applied
    to the address an account is keyed under.

    >>> account_spellings("ann@\uff42\u00fccher.example")  # fullwidth b
    ('ann@ｂücher.example',)

    Lowercasing alone folds a few letters (U+212A KELVIN SIGN -> ``k``); such an
    entry is not widened either. Over-long strings are not looked at (nor cached).
    """
    written = email.strip().lower()
    if len(written) > _MAX_ADDRESS_LENGTH or lowercase_folds_to_ascii(email):
        return (written,)
    return _canonical_spellings(email.strip(), written)


@lru_cache(maxsize=4096)
def _canonical_spellings(email: str, written: str) -> tuple[str, ...]:
    try:
        unicode_form = normalize_email(email)
        local, _, domain = unicode_form.rpartition("@")
        ascii_form = f"{local}@{_ascii_domain(domain)}"
    except ValueError:
        return (written,)
    if written not in (unicode_form, ascii_form):
        return (written,)
    return tuple(dict.fromkeys((written, unicode_form, ascii_form)))


def _ascii_domain(domain: str) -> str:
    """*domain*, as ``EmailStr`` returns it, in IDNA ASCII form; else ``ValueError``."""
    from email_validator import EmailNotValidError, validate_email

    try:
        parts = validate_email(f"x@{domain}", check_deliverability=False)
    except EmailNotValidError as e:
        raise ValueError(str(e)) from e
    return parts.ascii_domain.lower()


def resolve_account(email: str, exists) -> str | None:
    """The existing account key a written *email* names, or ``None``.

    Tries :func:`account_spellings` in order, so an exact match wins over the
    other spelling. *exists* is ``key -> bool`` (e.g. ``users.__contains__``).

    >>> users = {"ann@bücher.example"}
    >>> resolve_account("Ann@XN--BCHER-KVA.example", users.__contains__)
    'ann@bücher.example'
    >>> resolve_account("bob@example.com", set().__contains__) is None
    True
    """
    return next((key for key in account_spellings(email) if exists(key)), None)
