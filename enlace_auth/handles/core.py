"""What a handle is: its normal form, its rules, and the default made from an email.

A *handle* (a username) is the public name of an account: unique, case-insensitive,
shown as ``@name``. The account itself stays keyed by its email, which no other user
and no browser of another user ever sees. This module is pure (no web, no storage
imports), so the rules can move unchanged; ``registry.py`` holds the state.

The rules, and why (the research behind each is ``misc/docs/research/general/usernames.md``):

- **ASCII only**: lowercase ``a-z``, digits, and the separators ``.``, ``_``, ``-``.
  Input is NFKC-normalised and case-folded first, so ``ThorWhalen`` and fullwidth
  ``ｔｈｏｒ`` are accepted and stored as ``thorwhalen`` / ``thor``. Restricting the
  stored form to ASCII removes the Unicode confusables problem (UTS #39) instead of
  detecting it.
- **Case-insensitive by construction**: the stored form is lowercase, so the
  display form and the comparison form are the same string.
- **Separators and look-alikes do not distinguish**: ``john.smith``, ``john_smith``,
  ``johnsmith`` and ``j0hnsmith`` have one :func:`uniqueness_key`, so a name cannot
  be impersonated by moving a dot or swapping ``o`` for ``0``.
  A separator may not start or end a handle, nor follow another one (so a trailing
  dot is never swallowed as punctuation after ``@name.``).
- **Not all digits**: an all-digit handle reads as an id.
- **Reserved words** (:data:`RESERVED`): routes, roles and system words that would
  let an account pass for the platform. A host adds its own (its group names).

>>> normalize("@ThorWhalen ")
'thorwhalen'
>>> handle_problem("thorwhalen") is None
True
>>> handle_problem("thor..whalen")
'A dot, dash or underscore cannot follow another one.'
>>> {uniqueness_key(h) for h in ("john.smith", "john_smith", "j0hnsmith")}
{'johnsmlth'}
>>> base_from_email("John.Smith+news@example.com")
'john.smith'
>>> list(candidates("bo", limit=3))
['bo1', 'bo2', 'bo3']
"""

from __future__ import annotations

import random
import re
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from itertools import count, islice
from typing import Optional

__all__ = [
    "DEFAULT_POLICY",
    "HandlePolicy",
    "RESERVED",
    "base_from_email",
    "candidates",
    "handle_problem",
    "normalize",
    "suggestions",
    "uniqueness_key",
]

#: Names no account may take without an admin's ``--force``: routes and pages of the
#: platform, roles, system words, and words that read as "nobody". Kept short and
#: literal on purpose; a host adds its own through :class:`HandlePolicy.reserved`.
# fmt: off
RESERVED = frozenset(
    {
        # platform routes and pages
        "about", "account", "accounts", "admin", "admins", "api", "app", "apps",
        "auth", "blog", "callback", "check", "contact", "csrf", "dashboard",
        "docs", "help",
        "home", "login", "logout", "mail", "me", "new", "oauth", "privacy",
        "register", "search", "security", "settings", "signin", "signout",
        "signup", "static", "status", "store", "terms", "user", "users", "www",
        # roles and the platform speaking
        "administrator", "moderator", "mod", "mods", "official", "operator",
        "owner", "root", "staff", "support", "superuser", "sysadmin", "system",
        "team", "webmaster", "postmaster", "hostmaster", "abuse", "noreply",
        "no-reply", "info", "mailer-daemon", "noc",
        # names protocols and browsers assume the domain owner controls
        "localhost", "wpad", "autoconfig", "autodiscover", "favicon", "robots",
        "well-known", "xrpc",
        # words that read as nobody, or as a value
        "anonymous", "everyone", "guest", "here", "nobody", "none", "null",
        "undefined", "unknown", "deleted", "removed", "test", "true", "false",
        "you", "all",
    }
)
# fmt: on

_SEPARATORS = "._-"
_ALLOWED = re.compile(r"^[a-z0-9._-]+$")
_DOUBLE_SEPARATOR = re.compile(r"[._-]{2,}")


@dataclass(frozen=True)
class HandlePolicy:
    """The knobs of the handle rules. The defaults are the platform's.

    *reserved* is compared by :func:`uniqueness_key`, so reserving ``no-reply`` also
    reserves ``noreply`` and ``no.reply``.
    """

    min_length: int = 3
    max_length: int = 30
    reserved: frozenset = field(default=RESERVED)
    #: the base of a default handle when the email gives nothing usable
    fallback_base: str = "user"
    #: sequential suffixes tried (``name1`` .. ``name<N>``) before random ones
    max_sequential: int = 99
    #: digits of the random suffix used once the sequential ones are spent
    random_suffix_digits: int = 4

    def with_reserved(self, extra: Iterable[str]) -> "HandlePolicy":
        """This policy with *extra* names reserved too (a host's group names).

        >>> "acme" in DEFAULT_POLICY.with_reserved(["Acme"]).reserved_keys
        True
        """
        from dataclasses import replace

        return replace(
            self, reserved=frozenset(self.reserved) | {normalize(e) for e in extra}
        )

    @property
    def reserved_keys(self) -> frozenset:
        """The uniqueness keys of the reserved names."""
        return frozenset(uniqueness_key(r) for r in self.reserved)


DEFAULT_POLICY = HandlePolicy()


def normalize(text: str) -> str:
    """The stored form of what a person typed: NFKC, case-folded, trimmed, no ``@``.

    It does not validate: :func:`handle_problem` does, on this form.

    >>> normalize("  @Ｔhor_Whalen")
    'thor_whalen'
    >>> normalize("Straße")
    'strasse'
    """
    text = unicodedata.normalize("NFKC", str(text)).strip()
    if text.startswith("@"):
        text = text[1:]
    return unicodedata.normalize("NFKC", text.casefold())


#: look-alikes folded together in the uniqueness key (PyPI does the same for names)
_LOOKALIKES = str.maketrans({"0": "o", "1": "l", "i": "l"})


def uniqueness_key(handle: str) -> str:
    """The form two handles are compared by: normalised, without separators, with
    look-alike characters folded (``0`` as ``o``; ``1`` and ``i`` as ``l``).

    So ``th0r.whalen`` cannot pose as ``thorwhalen``. It is a key, never shown.

    >>> uniqueness_key("@Thor.Whalen") == uniqueness_key("th0r-whalen")
    True
    >>> uniqueness_key("bill") == uniqueness_key("b1ll")
    True
    """
    text = re.sub(f"[{re.escape(_SEPARATORS)}]", "", normalize(handle))
    return text.translate(_LOOKALIKES)


def handle_problem(
    handle: str, *, policy: HandlePolicy = DEFAULT_POLICY
) -> Optional[str]:
    """Why *handle* (already normalised) cannot be a handle, or ``None`` if it can.

    The message is written for the person choosing the name.

    >>> handle_problem("ab")
    'Use at least 3 characters.'
    >>> handle_problem("josé")
    'Use only letters a-z, digits, and . _ -'
    >>> handle_problem("12345")
    'Use at least one letter.'
    >>> handle_problem("admin")
    'This name is reserved.'
    """
    if len(handle) < policy.min_length:
        return f"Use at least {policy.min_length} characters."
    if len(handle) > policy.max_length:
        return f"Use at most {policy.max_length} characters."
    if not _ALLOWED.match(handle):
        return "Use only letters a-z, digits, and . _ -"
    if handle[0] in _SEPARATORS or handle[-1] in _SEPARATORS:
        return "Start and end with a letter or a digit."
    if _DOUBLE_SEPARATOR.search(handle):
        return "A dot, dash or underscore cannot follow another one."
    if not any(c.isalpha() for c in handle):
        return "Use at least one letter."
    if uniqueness_key(handle) in policy.reserved_keys:
        return "This name is reserved."
    return None


def _ascii_fold(text: str) -> str:
    """Accents dropped (``josé`` -> ``jose``); other non-ASCII letters removed.

    Stdlib only (NFKD, then drop combining marks): it covers Latin scripts. A
    transliterator for other scripts (ICU ``Any-Latin``) is a later strategy.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    kept = "".join(c for c in decomposed if not unicodedata.combining(c))
    return kept.encode("ascii", "ignore").decode("ascii")


def base_from_email(email: str, *, policy: HandlePolicy = DEFAULT_POLICY) -> str:
    """The base of a default handle: the email's local part, made into a handle.

    The ``+tag`` of plus-addressing is dropped (it is private routing, and often
    names the site), accents are folded, other characters removed, separator runs
    collapsed, and the result cut so a suffix still fits. When nothing usable is
    left, or the local part is a reserved word (``info@``, ``admin@``: role
    mailboxes), *policy.fallback_base*. The base may still be too short:
    :func:`candidates` then starts at the first suffix.

    >>> base_from_email("José.Ñúñez@example.com")
    'jose.nunez'
    >>> base_from_email("o'brien@example.com")
    'obrien'
    >>> base_from_email("--@example.com"), base_from_email("info@example.com")
    ('user', 'user')
    """
    local = str(email).rsplit("@", 1)[0].split("+", 1)[0]
    text = _ascii_fold(normalize(local))
    text = re.sub(r"[^a-z0-9._-]", "", text)
    text = _DOUBLE_SEPARATOR.sub(lambda m: m.group(0)[0], text)
    room = policy.max_length - len(str(policy.max_sequential)) - 1
    text = text[:room].strip(_SEPARATORS)
    if not text or uniqueness_key(text) in policy.reserved_keys:
        return policy.fallback_base  # info@, admin@ ... are role mailboxes
    return text


def candidates(
    base: str,
    *,
    policy: HandlePolicy = DEFAULT_POLICY,
    limit: Optional[int] = None,
    rng: Callable[[int, int], int] = random.randint,
) -> Iterator[str]:
    """Valid handles to try, in order: *base*, ``base1`` .. ``base<max_sequential>``,
    then ``base`` plus a random number of *policy.random_suffix_digits* digits.

    Invalid ones (too short, reserved) are skipped, so ``bo`` starts at ``bo1``. The
    base is cut so the suffix fits. Sequential suffixes are what people expect (the
    first ``john`` is ``john``, the next ``john1``); the random tail keeps a crowded
    base from costing a hundred lookups.

    >>> list(candidates("thorwhalen", limit=3))
    ['thorwhalen', 'thorwhalen1', 'thorwhalen2']
    >>> list(candidates("agent007", limit=2))
    ['agent007', 'agent007_1']
    >>> no_sequence = HandlePolicy(max_sequential=0)
    >>> next(candidates("x", policy=no_sequence, rng=lambda a, b: 4242))
    'x4242'
    """

    def fit(suffix: str) -> str:
        head = base[: policy.max_length - len(suffix) - 1].rstrip(_SEPARATORS)
        # agent007 + 1 is agent007_1, never agent0071
        return head + ("_" if head[-1:].isdigit() else "") + suffix

    def sequence() -> Iterator[str]:
        yield base
        for n in range(1, policy.max_sequential + 1):
            yield fit(str(n))
        low = 10 ** (policy.random_suffix_digits - 1)
        for _ in count():
            yield fit(str(rng(low, 10 * low - 1)))

    valid = (c for c in sequence() if handle_problem(c, policy=policy) is None)
    return islice(valid, limit) if limit is not None else valid


def suggestions(
    wanted: str,
    is_free: Callable[[str], bool],
    *,
    policy: HandlePolicy = DEFAULT_POLICY,
    n: int = 3,
    max_tries: int = 200,
) -> list[str]:
    """Up to *n* free handles close to *wanted*, for a name that is taken or invalid.

    *wanted* is first made into a base the way an email's local part is, so
    ``Thor Whalen!`` suggests ``thorwhalen1`` and so on.

    >>> taken = {"thorwhalen", "thorwhalen1"}
    >>> suggestions("ThorWhalen", lambda h: h not in taken)
    ['thorwhalen2', 'thorwhalen3', 'thorwhalen4']
    """
    base = base_from_email(normalize(wanted), policy=policy)
    found = []
    for candidate in islice(candidates(base, policy=policy), max_tries):
        if normalize(candidate) != normalize(wanted) and is_free(candidate):
            found.append(candidate)
            if len(found) == n:
                break
    return found
