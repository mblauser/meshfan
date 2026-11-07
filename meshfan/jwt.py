"""Sign and verify MeshCore device JWTs (Ed25519 via orlp).

The token is a "JWT-style" string: HEADER.PAYLOAD.SIGNATURE.

It is NOT a standard RFC 7519 JWT (and is not PyJWT-compatible):
- the header alg is "Ed25519" (not "EdDSA")
- the signature is hex encoded, UPPERCASE (not base64url)
- the JSON is serialized with no whitespace

Match these exactly or the broker rejects the token. See docs/JWT.md.

This module is a pure leaf: it needs only the stdlib and ed25519-orlp
(no paho, no PyYAML), so a standalone signer is:

    from meshfan import sign_jwt, verify
"""
from __future__ import annotations

import base64
import json
import re
import time

from ed25519_orlp import ed25519_sign, ed25519_verify

from .errors import MeshfanError

_HEX64 = re.compile(r"^[0-9A-Fa-f]{64}$")
_HEX128 = re.compile(r"^[0-9A-Fa-f]{128}$")
_SIG_HEX = re.compile(r"^[0-9A-F]{128}$")

# A bound for untrusted token parts, so a hostile token cannot force an
# unbounded JSON parse or memory use.
_MAX_PART_BYTES = 65536


def _b64url(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_compact(obj: object) -> bytes:
    """JSON with no whitespace (matches the reference implementations)."""
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def _strip_hex_whitespace(value: str) -> str:
    """Strip whitespace (including newlines) from a hex string."""
    return "".join(value.split())


def parse_private_key(hex_str: str) -> bytes:
    """Validate a MeshCore private key and decode it to 64 bytes.

    The MeshCore expanded form is 128 hex characters: the 32-byte seed
    followed by the 32-byte public key (not a seed-only key).
    """
    raw = _strip_hex_whitespace(hex_str)
    if not _HEX128.match(raw):
        raise ValueError(
            "private key must be 128 hex characters (64 bytes, the MeshCore "
            "expanded form: 32-byte seed || 32-byte public key)"
        )
    return bytes.fromhex(raw)


def parse_public_key(hex_str: str) -> bytes:
    """Validate a MeshCore public key and decode it to 32 bytes."""
    raw = _strip_hex_whitespace(hex_str)
    if not _HEX64.match(raw):
        raise ValueError("public key must be 64 hex characters (32 bytes)")
    return bytes.fromhex(raw)


class Token:
    """A signed token plus its expiry, for renewal scheduling."""

    __slots__ = ("value", "exp")

    def __init__(self, value: str, exp: int) -> None:
        self.value = value
        self.exp = exp

    def should_renew(self, now: int, renew_before: int) -> bool:
        """True when the token is within `renew_before` seconds of expiry."""
        return now + renew_before >= self.exp

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Token):
            return NotImplemented
        return (self.value, self.exp) == (other.value, other.exp)

    def __hash__(self) -> int:
        return hash((self.value, self.exp))

    def __repr__(self) -> str:
        return f"Token(exp={self.exp}, value={self.value[:24]}...)"


def sign_jwt(
    *,
    public_key: bytes,
    private_key: bytes,
    audience: str,
    client: str,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> Token:
    """Sign a MeshCore device JWT.

    All arguments are keyword-only, so the 32-byte public key and the
    64-byte private key cannot be swapped silently.

    Args:
        public_key: 32-byte public key.
        private_key: 64-byte private key (MeshCore expanded form).
        audience: the broker's expected `aud` claim.
        client: the MQTT client id (the `client` claim).
        ttl_seconds: token lifetime in seconds.
        now: Unix seconds (for tests). Defaults to the current time.

    Returns:
        A Token with the signed value and its expiry.

    Raises:
        ValueError: on a wrong key length, ttl_seconds <= 0, or an empty
            audience/client.
    """
    if len(public_key) != 32:
        raise ValueError(
            f"public_key must be 32 bytes (got {len(public_key)}); MeshCore "
            "uses the raw 32-byte public key"
        )
    if len(private_key) != 64:
        raise ValueError(
            f"private_key must be 64 bytes (got {len(private_key)}); MeshCore "
            "uses the expanded form: 32-byte seed || 32-byte public key"
        )
    if ttl_seconds <= 0:
        raise ValueError(f"ttl_seconds must be > 0 (got {ttl_seconds})")
    if not audience:
        raise ValueError("audience must be a non-empty string")
    if not client:
        raise ValueError("client must be a non-empty string")

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


def _split_token(token: str) -> tuple[str, str, str]:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise MeshfanError(
            f"token must have 3 non-empty dot-separated parts (got {len(parts)})"
        )
    return parts[0], parts[1], parts[2]


def _decode_part(b64: str, what: str) -> dict:
    """Decode one base64url JSON part, enforcing canonical form."""
    try:
        data = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except ValueError as e:  # binascii.Error is a ValueError
        raise MeshfanError(f"token {what} is not valid base64url") from e
    if len(data) > _MAX_PART_BYTES:
        raise MeshfanError(f"token {what} is too large")
    try:
        obj = json.loads(data)
    except ValueError as e:  # JSONDecodeError / UnicodeDecodeError
        raise MeshfanError(f"token {what} is not valid JSON") from e
    if not isinstance(obj, dict):
        raise MeshfanError(f"token {what} must be a JSON object")
    # The signed bytes are canonical compact JSON; re-serializing the
    # decoded object must reproduce them exactly (rejects reordered or
    # padded encodings of the same logical content).
    if _json_compact(obj) != data:
        raise MeshfanError(f"token {what} is not in canonical compact form")
    return obj


def _check_payload(payload: dict) -> None:
    for claim in ("publicKey", "iat", "exp", "aud", "client"):
        if claim not in payload:
            raise MeshfanError(f"token payload is missing the {claim!r} claim")
    if not isinstance(payload["publicKey"], str) or len(payload["publicKey"]) != 64:
        raise MeshfanError("token payload publicKey must be 64 hex characters")
    if not isinstance(payload["iat"], int) or isinstance(payload["iat"], bool):
        raise MeshfanError("token payload iat must be an integer")
    if not isinstance(payload["exp"], int) or isinstance(payload["exp"], bool):
        raise MeshfanError("token payload exp must be an integer")
    if not isinstance(payload["aud"], str) or not payload["aud"]:
        raise MeshfanError("token payload aud must be a non-empty string")
    if not isinstance(payload["client"], str) or not payload["client"]:
        raise MeshfanError("token payload client must be a non-empty string")


def _decode_signature(b64: str) -> bytes:
    if not _SIG_HEX.match(b64):
        raise MeshfanError("signature must be 128 UPPERCASE hex characters")
    return bytes.fromhex(b64)


def verify(token: str, public_key: bytes) -> bool:
    """Verify a MeshCore device JWT against a 32-byte public key.

    Returns:
        False when the signature does not match `public_key`.

    Raises:
        ValueError: when `public_key` is not 32 bytes (a caller error).
        MeshfanError: when the token is structurally malformed.
    """
    if len(public_key) != 32:
        raise ValueError(
            f"public_key must be 32 bytes (got {len(public_key)}); MeshCore "
            "uses the raw 32-byte public key"
        )
    header_b64, payload_b64, sig_b64 = _split_token(token)
    header = _decode_part(header_b64, "header")
    if header.get("alg") != "Ed25519":
        raise MeshfanError(
            f"unsupported alg {header.get('alg')!r} (expected 'Ed25519')"
        )
    payload = _decode_part(payload_b64, "payload")
    _check_payload(payload)
    signature = _decode_signature(sig_b64)
    # The signature covers the exact encoded parts, so verify against the
    # original strings, not a re-serialization.
    message = f"{header_b64}.{payload_b64}".encode("ascii")
    return ed25519_verify(signature, message, public_key)


def decode(token: str) -> tuple[dict, dict]:
    """Split a token into (header, payload) without checking the signature.

    Raises MeshfanError when the token is structurally malformed.
    """
    header_b64, payload_b64, _ = _split_token(token)
    return _decode_part(header_b64, "header"), _decode_part(payload_b64, "payload")
