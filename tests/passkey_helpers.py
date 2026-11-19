"""A software WebAuthn authenticator for tests: real P-256 keys, real signatures.

It answers ``PublicKeyCredentialCreationOptionsJSON`` and
``PublicKeyCredentialRequestOptionsJSON`` the way a browser plus a platform
authenticator would (``fmt: none`` attestation), so the server's py_webauthn
checks run unmodified. ``origin`` is what the browser would put in
``clientDataJSON``; ``uv`` whether the user was verified (Face ID, Touch ID).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftAuthenticator:
    def __init__(self, origin: str = "https://testserver", *, uv: bool = True):
        self.origin = origin
        self.uv = uv
        self.creds: list[dict] = []  # {id, key, rp_id, user_handle, count}

    def _flags(self, *, attested: bool) -> int:
        flags = 0x01 | (0x04 if self.uv else 0)  # UP, UV
        return flags | (0x40 if attested else 0)

    def _client_data(self, kind: str, challenge: str, origin=None) -> bytes:
        return json.dumps(
            {
                "type": kind,
                "challenge": challenge,
                "origin": origin or self.origin,
                "crossOrigin": False,
            }
        ).encode()

    def create(self, options: dict, *, origin=None) -> dict:
        rp_id = options["rp"]["id"]
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        cred_id = os.urandom(32)
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", 0)
            + bytes(16)
            + struct.pack(">H", len(cred_id))
            + cred_id
            + cose
        )
        self.creds.append(
            {
                "id": cred_id,
                "key": key,
                "rp_id": rp_id,
                "user_handle": options["user"]["id"],
                "count": 0,
            }
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64(cred_id),
            "rawId": b64(cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(
                    self._client_data("webauthn.create", options["challenge"], origin)
                ),
                "attestationObject": b64(attestation),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(self, options: dict, *, cred=None, origin=None, user_handle=True) -> dict:
        allowed = {c["id"] for c in options.get("allowCredentials") or []}
        if cred is None:
            candidates = [
                c
                for c in self.creds
                if c["rp_id"] == options["rpId"]
                and (not allowed or b64(c["id"]) in allowed)
            ]
            cred = candidates[-1]
        cred["count"] += 1
        auth_data = (
            hashlib.sha256(cred["rp_id"].encode()).digest()
            + bytes([self._flags(attested=False)])
            + struct.pack(">I", cred["count"])
        )
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        signature = cred["key"].sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        response = {
            "clientDataJSON": b64(client_data),
            "authenticatorData": b64(auth_data),
            "signature": b64(signature),
        }
        if user_handle:
            response["userHandle"] = cred["user_handle"]
        return {
            "id": b64(cred["id"]),
            "rawId": b64(cred["id"]),
            "type": "public-key",
            "response": response,
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
