"""The stateless rules of the OAuth 2.1 authorization server, importable alone.

PKCE S256 verification, redirect-URI vetting, refresh-token hashing and the RS256
signing key: the security-critical checks a second gateway would otherwise copy
and let drift (i2mint/enlace_auth#98). No web framework is imported here;
``OAuthKeys`` needs ``cryptography`` and ``joserfc`` (the ``oauth`` extra), on
first use. :mod:`enlace_auth.auth.oauth_server` uses these same functions.

>>> import base64, hashlib
>>> verifier = "a" * 43
>>> challenge = b64url(hashlib.sha256(verifier.encode()).digest())
>>> verify_pkce_s256(verifier, challenge), verify_pkce_s256("b" * 43, challenge)
(True, False)
>>> len(hash_refresh("token")), hash_refresh("token") == hash_refresh("token")
(64, True)
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Optional

REFRESH_SALT = "oauth-refresh"  # domain separation for refresh-token hashing


def b64url(raw: bytes) -> str:
    """URL-safe base64 without padding (the PKCE / JOSE encoding)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def hash_refresh(token: str) -> str:
    """Storage key for a refresh token — the token itself is never persisted.

    Refresh tokens are long-lived credentials. Storing them verbatim would make a
    read of the store (a backup, a stray ``cat``, a misconfigured store API) a
    credential dump. Hashing means the store holds only something that can
    *recognise* a token presented back to us, never mint one.
    """
    return hashlib.sha256(f"{REFRESH_SALT}:{token}".encode()).hexdigest()


def verify_pkce_s256(verifier: str, challenge: str) -> bool:
    """True iff ``BASE64URL(SHA256(verifier)) == challenge`` (PKCE S256, RFC 7636)."""
    expected = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return secrets.compare_digest(expected, challenge)


class OAuthKeys:
    """The server's RSA signing key — persisted, exposed as a JWKS.

    Generates a 2048-bit RSA key on first use under *key_dir* (``private_key.pem``,
    mode 0600) and reuses it thereafter, so tokens stay verifiable across restarts.
    Signs JWTs (RS256) and publishes the public half as a one-key JWKS for the
    connector's verifier to fetch.
    """

    def __init__(self, key_dir: str | Path):
        self._dir = Path(key_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pem_path = self._dir / "private_key.pem"
        self._pem = self._load_or_create()
        from joserfc.jwk import RSAKey

        self._jwk = RSAKey.import_key(self._pem)
        self.kid = self._jwk.thumbprint()

    def _load_or_create(self) -> bytes:
        if self._pem_path.exists():
            return self._pem_path.read_bytes()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self._pem_path.write_bytes(pem)
        self._pem_path.chmod(0o600)
        return pem

    def jwks(self) -> dict[str, Any]:
        pub = self._jwk.as_dict(private=False)
        pub.update({"use": "sig", "alg": "RS256", "kid": self.kid})
        return {"keys": [pub]}

    def sign(self, claims: dict[str, Any]) -> str:
        from joserfc import jwt

        header = {"alg": "RS256", "kid": self.kid, "typ": "JWT"}
        return jwt.encode(header, claims, self._jwk, algorithms=["RS256"])


FORBIDDEN_REDIRECT_SCHEMES = frozenset(
    {"javascript", "data", "vbscript", "file", "blob", "about", "filesystem"}
)
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
MAX_REDIRECT_URI_LEN = 2048


def redirect_uri_problem(
    uri: object,
    *,
    https_hosts: Optional[Iterable[str]] = None,
    allow_loopback: bool = True,
) -> Optional[str]:
    """Why *uri* is not an acceptable registered redirect URI, or ``None``.

    Follows OAuth 2.1 / RFC 8252 for public clients: an absolute URI with no
    fragment; ``https`` for web clients; plain ``http`` only on a loopback host
    (native apps on a local port); private-use schemes (``cursor://...``) are
    allowed for native apps; script- and local-content schemes never are.
    Registration is anonymous, so this is the only gate on where an
    authorization code can be sent.

    *https_hosts*, when given, narrows ``https`` redirects to those hosts (a
    gateway whose clients are known); *allow_loopback* False refuses the
    loopback ``http`` exception (no native clients).

    >>> redirect_uri_problem("https://claude.ai/api/mcp/auth_callback") is None
    True
    >>> redirect_uri_problem("http://127.0.0.1:8765/cb", allow_loopback=False)
    'plain-http redirect_uri is only allowed on a loopback host'
    >>> redirect_uri_problem("https://evil.example/cb", https_hosts=["claude.ai"])
    "redirect_uri host 'evil.example' is not one this server accepts"
    """
    from urllib.parse import urlsplit

    if not isinstance(uri, str) or not uri:
        return "each redirect_uri must be a non-empty string"
    if len(uri) > MAX_REDIRECT_URI_LEN:
        return "redirect_uri is too long"
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in uri):
        return "redirect_uri must not contain whitespace or control characters"
    try:
        parts = urlsplit(uri)
        host = parts.hostname
    except ValueError:
        return "redirect_uri is not a valid URI"
    scheme = parts.scheme.lower()
    if not scheme:
        return "redirect_uri must be an absolute URI"
    if parts.fragment or uri.endswith("#"):
        return "redirect_uri must not contain a fragment"
    if scheme in FORBIDDEN_REDIRECT_SCHEMES:
        return f"redirect_uri scheme {scheme!r} is not allowed"
    if scheme in ("http", "https") and not host:
        return "redirect_uri must name a host"
    if "@" in parts.netloc or "\\" in uri:
        # Userinfo (``https://trusted@evil/``) and backslashes are where URL
        # parsers disagree with browsers, and they let a destination read as a
        # different host than the one a browser actually visits.
        return "redirect_uri must not contain userinfo or backslashes"
    if scheme == "http" and (not allow_loopback or host not in LOOPBACK_HOSTS):
        return "plain-http redirect_uri is only allowed on a loopback host"
    if https_hosts is not None and scheme == "https":
        if (host or "").lower() not in {h.lower() for h in https_hosts}:
            return f"redirect_uri host {host!r} is not one this server accepts"
    return None
