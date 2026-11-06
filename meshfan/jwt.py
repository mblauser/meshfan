"""Sign MeshCore device JWTs (Ed25519 via orlp).

The token is a "JWT-style" string: HEADER.PAYLOAD.SIGNATURE.

It is NOT a standard RFC 7519 JWT:
- the header alg is "Ed25519" (not "EdDSA")
- the signature is hex encoded, UPPERCASE (not base64url)
- the JSON is serialized with no whitespace

Match these exactly or the broker rejects the token. See docs/JWT.md.
"""
from __future__ import annotations

import base64
import json
import time

from ed25519_orlp import ed25519_sign


def _b64url(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_compact(obj: object) -> bytes:
    """JSON with no whitespace (matches the reference implementations)."""
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class Token:
    """A signed token plus its expiry, for renewal scheduling."""

    __slots__ = ("value", "exp")

    def __init__(self, value: str, exp: int) -> None:
        self.value = value
        self.exp = exp

    def should_renew(self, now: int, renew_before: int) -> bool:
        """True when the token is within `renew_before` seconds of expiry."""
        return now + renew_before >= self.exp


def sign_jwt(
    public_key: bytes,
    private_key: bytes,
    audience: str,
    client: str,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> Token:
    """Sign a MeshCore device JWT.

    Args:
        public_key: 32-byte public key.
        private_key: 64-byte private key (MeshCore expanded form).
        audience: the broker's expected `aud` claim.
        client: the MQTT client id (the `client` claim).
        ttl_seconds: token lifetime in seconds.
        now: Unix seconds (for tests). Defaults to the current time.

    Returns:
        A Token with the signed value and its expiry.
    """
    now = int(time.time()) if now is None else now
    iat = now
    exp = now + ttl_seconds

    header = _json_compact({"alg": "Ed25519", "typ": "JWT"})
    payload = _json_compact(
        {
            "publicKey": public_key.hex().upper(),
            "iat": iat,
            "exp": exp,
            "aud": audience,
            "client": client,
        }
    )

    signing_input = (_b64url(header) + "." + _b64url(payload)).encode("ascii")
    signature = ed25519_sign(signing_input, public_key, private_key)

    value = f"{_b64url(header)}.{_b64url(payload)}.{signature.hex().upper()}"
    return Token(value, exp)
