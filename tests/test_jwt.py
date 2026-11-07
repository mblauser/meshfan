"""JWT known-answer test (byte-exact) + verify + argument validation.

The wire format is the contract: fixed key + fixed clock -> fixed token.
This test pins it.
"""
from __future__ import annotations

import pytest

from meshfan import MeshfanError, sign_jwt, verify
from meshfan.jwt import Token, decode, parse_private_key, parse_public_key

# Fixed keypair: ed25519_create_keypair(seed=0xAA*32), MeshCore expanded form.
PUB = bytes.fromhex(
    "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
)
PRIV = bytes.fromhex(
    "00df8dd9e9eac760a1b68c1565388b1e93049b155baa8808cf4b4985f8665b68"
    "81617ba7b989e284fdf783f59a325285d6d0f5a2ead06ca2069b0191173db023"
)

FIXED_NOW = 1_751_881_234
EXPECTED_HEADER_B64 = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0"
EXPECTED_PAYLOAD_B64 = (
    "eyJwdWJsaWNLZXkiOiJFNzM0RUE2QzJCNjI1N0RFNzIzNTVFNDcyQUEwNUE0"
    "QzQ4N0U2QjQ2M0MwMjlFRDMwNkRGMkYwMUI1NjM2QjU4IiwiaWF0IjoxNzUx"
    "ODgxMjM0LCJleHAiOjE3NTE4ODQ4MzQsImF1ZCI6Im1hcC5leGFtcGxlLm5l"
    "dCIsImNsaWVudCI6Im1lc2hmYW4tMSJ9"
)
EXPECTED_SIG = (
    "7617580FF22C2629F816BFC3E8EA53CA5C3DF671C3721CB1CF45165361CF"
    "BC5529966A2ED799BC285C07CF97C5EF5898EBCB3A4F27A4A61B68142A9E"
    "AEE96E0E"
)
EXPECTED_TOKEN = f"{EXPECTED_HEADER_B64}.{EXPECTED_PAYLOAD_B64}.{EXPECTED_SIG}"


def test_known_answer_token_is_byte_exact():
    tok = sign_jwt(
        public_key=PUB,
        private_key=PRIV,
        audience="map.example.net",
        client="meshfan-1",
        ttl_seconds=3600,
        now=FIXED_NOW,
    )
    assert tok.value == EXPECTED_TOKEN
    assert tok.exp == FIXED_NOW + 3600
    header_b64, payload_b64, sig = tok.value.split(".")
    assert header_b64 == EXPECTED_HEADER_B64
    assert payload_b64 == EXPECTED_PAYLOAD_B64
    assert sig == EXPECTED_SIG  # uppercase hex, 128 chars


def test_verify_roundtrip():
    tok = sign_jwt(
        public_key=PUB, private_key=PRIV, audience="a", client="c", now=FIXED_NOW
    )
    assert verify(tok.value, PUB) is True


def test_verify_wrong_key_is_false(keypair):
    other_pub, _priv, _ = keypair
    assert other_pub != PUB
    tok = sign_jwt(
        public_key=PUB, private_key=PRIV, audience="a", client="c", now=FIXED_NOW
    )
    assert verify(tok.value, other_pub) is False


@pytest.mark.parametrize(
    "token",
    [
        "",
        "abc",
        "a.b",
        "a.b.c.d",
        "..c",
        "a.b." + "g" * 128,  # non-hex signature
        "a.b." + "0" * 127,  # short signature
        "a.b." + "0" * 129,  # long signature
        "a.b." + "0" * 128,  # valid sig, malformed b64 parts
        "eyJhbGciOiJFZDI1NTE5In0.eyJhIjoxfQ." + "0" * 128,  # missing claims
        "eyJhbGciOiJSUzI1NiJ9.eyJhIjoxfQ." + "0" * 128,  # wrong alg
    ],
)
def test_verify_malformed_raises_meshfan_error(token):
    with pytest.raises(MeshfanError):
        verify(token, PUB)


def test_verify_bad_key_length_raises_value_error():
    with pytest.raises(ValueError, match="32 bytes"):
        verify("a.b.c", b"\x00" * 31)


def test_sign_jwt_validates_key_lengths():
    with pytest.raises(ValueError, match="32 bytes"):
        sign_jwt(
            public_key=b"\x00" * 31, private_key=PRIV, audience="a", client="c"
        )
    with pytest.raises(ValueError, match="64 bytes"):
        sign_jwt(public_key=PUB, private_key=b"\x00" * 63, audience="a", client="c")


def test_sign_jwt_key_args_are_keyword_only():
    # The swapped-key call is no longer possible positionally.
    with pytest.raises(TypeError):
        sign_jwt(PUB, PRIV, "a", "c")


def test_sign_jwt_validates_ttl_and_claims():
    with pytest.raises(ValueError, match="ttl_seconds"):
        sign_jwt(
            public_key=PUB, private_key=PRIV, audience="a", client="c",
            ttl_seconds=0,
        )
    with pytest.raises(ValueError, match="ttl_seconds"):
        sign_jwt(
            public_key=PUB, private_key=PRIV, audience="a", client="c",
            ttl_seconds=-5,
        )
    with pytest.raises(ValueError, match="audience"):
        sign_jwt(public_key=PUB, private_key=PRIV, audience="", client="c")
    with pytest.raises(ValueError, match="client"):
        sign_jwt(public_key=PUB, private_key=PRIV, audience="a", client="")


def test_parse_keys():
    assert parse_public_key(PUB.hex()) == PUB
    assert parse_private_key(PRIV.hex()) == PRIV
    # whitespace is stripped
    assert parse_public_key(" ".join(PUB.hex()[i:i + 8] for i in range(0, 64, 8))) == PUB
    with pytest.raises(ValueError):
        parse_public_key(PUB.hex()[:63])
    with pytest.raises(ValueError):
        parse_private_key(PRIV.hex()[:127])
    with pytest.raises(ValueError):
        parse_public_key("g" * 64)


def test_decode():
    tok = sign_jwt(
        public_key=PUB,
        private_key=PRIV,
        audience="map.example.net",
        client="meshfan-1",
        ttl_seconds=3600,
        now=FIXED_NOW,
    )
    header, payload = decode(tok.value)
    assert header == {"alg": "Ed25519", "typ": "JWT"}
    assert payload["publicKey"] == PUB.hex().upper()
    assert payload["iat"] == FIXED_NOW
    assert payload["exp"] == FIXED_NOW + 3600
    assert payload["aud"] == "map.example.net"
    assert payload["client"] == "meshfan-1"


def test_token_repr_eq_hash():
    t1 = Token("abc", 123)
    t2 = Token("abc", 123)
    assert t1 == t2
    assert hash(t1) == hash(t2)
    assert "abc" in repr(t1)
    assert t1 != Token("abd", 123)
