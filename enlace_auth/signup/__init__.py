"""Self-service sign-up and email-code sign-in.

``make_signup_router`` mounts ``/auth/email/*`` (a one-time code mailed to the
address, verify-before-create), the verify-first ``/auth/register``, and
self-service deletion (``/auth/account/delete``). The pieces are seams the
plugin wires from ``[auth.signup]``: :class:`~enlace_auth.signup.policy.SignupPolicy`
(who may create an account from which app), a rate limiter
(:mod:`enlace_auth.ratelimit`), and a bot check
(:class:`~enlace_auth.signup.botcheck.TimedHoneypot`). The design and its
research: ``misc/docs/research/self-signup-synthesis.md``.
"""

from enlace_auth.signup.botcheck import TimedHoneypot
from enlace_auth.signup.codes import PendingCodes
from enlace_auth.signup.policy import SignupPolicy, consume_invite, invite

__all__ = [
    "PendingCodes",
    "SignupPolicy",
    "TimedHoneypot",
    "consume_invite",
    "invite",
]
