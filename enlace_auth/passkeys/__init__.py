"""Passkeys (WebAuthn): sign-in, a step-up confirmation, and a per-account requirement.

Turned on by ``[auth.passkeys] enabled = true`` (py_webauthn does the WebAuthn
checks). Four pieces, one boundary:

1. **Add passkeys to any account** from ``/auth/account``: several per account,
   each named and removable, a notice mailed on each change
   (``/auth/passkeys/register/*``, ``DELETE /auth/passkeys/{id}``).
2. **Sign in with a passkey**, including autofill on the sign-in page's email
   field (``/auth/passkeys/login/*``). The email code stays the way back in.
3. **Step-up**: an app asks the signed-in user to confirm one described action
   with a passkey and gets a single-use, short-lived proof that its backend (or
   a connector's) redeems before acting (``/auth/passkeys/step-up/*``).
4. **Policy**: ``[auth.passkeys] required`` lists accounts (emails, ``@group``,
   ``@admins``) that must sign in with a passkey once they have
   ``enforce_from`` of them. Enforced in ``open_session``, which every sign-in
   path goes through.

The logic is in :mod:`enlace_auth.passkeys.core` (no web framework), the HTTP
surface in :mod:`enlace_auth.passkeys.routes`, the browser side in
``passkeys.js`` (served at ``/auth/passkeys/passkeys.js``).
"""

from enlace_auth.passkeys.core import (
    PasskeyError,
    PasskeyPolicy,
    PasskeyService,
    RelyingParty,
)

__all__ = ["PasskeyError", "PasskeyPolicy", "PasskeyService", "RelyingParty"]
