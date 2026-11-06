# MeshCore device signing. The JWT contract

The login model shared by MeshCore's MQTT analyzers (MeshOMatic, MeshMapper,
LetsMesh US/EU, Meshat.se, MeshCore.CA, EastMesh, Waev, and others).

Ground truth sources:

- `Cisien/meshcoretomqtt`, `auth_token.py` (the exact Python signing code)
- `Colorado-Mesh/mesh-client`, `docs/letsmesh-mqtt-auth.md` (the shared
  device-signing contract)
- `michaelhart/meshcore-mqtt-broker` (the `createAuthToken` reference)

## Connection

- Username: `v1_<PUBLIC_KEY>`, the 64-hex public key, uppercase.
- Password: a short-lived Ed25519 signed token (below).
- Transport: MQTT over WebSocket (WSS), TLS, port 443.
- WebSocket path: broker specific. `/ws` for LetsMesh, MeshMapper, Colorado
  Mesh. `/mqtt` for Waev, Meshat.se, MeshCore.CA, EastMesh, MeshOMatic.
- Keepalive: 30 s default (60 s for some presets).

## Token format

A "JWT-style" token: `HEADER.PAYLOAD.SIGNATURE`.

Header. Base64url of JSON with no spaces (separators are comma and colon):

```json
{"alg": "Ed25519", "typ": "JWT"}
```

Payload. Base64url of JSON with no spaces:

```json
{"publicKey": "<64-hex UPPERCASE>", "iat": <unix-sec>, "exp": <unix-sec>, "aud": "<audience>", "client": "<client-id>"}
```

- `publicKey`: the node's 64-hex public key, uppercase.
- `iat`: issued at, Unix seconds.
- `exp`: expiry, Unix seconds (iat plus ttl).
- `aud`: audience. Broker specific. Usually the connect hostname, but
  MeshOMatic uses `map.meshomatic.net`. Take it from the broker's docs.
- `client`: the MQTT client id (optional, broker specific).

Signature. Ed25519 signature over `HEADER.PAYLOAD` (the two base64url parts
joined by a single dot), hex encoded, uppercase.

## Keys

- Public key: 32 bytes (64 hex chars).
- Private key: 64 bytes (128 hex chars, MeshCore format).
- The signature must come from the same Ed25519 implementation as the
  firmware (`orlp/ed25519`) to be byte identical and accepted.

## Renewal

Renew the token about 6 minutes before `exp` (proactive refresh), or on the
next connect after expiry. A typical TTL is 1 hour.

## Easy to get wrong

- This is not a standard RFC 7519 JWT. `alg` is `Ed25519` (not `EdDSA`) and
  the signature is hex (not base64url). Match it exactly or the broker
  rejects the token.
- Serialize the JSON with no whitespace to match the reference
  implementations byte for byte.
- `aud` is not always the connect host. It is broker specific.
