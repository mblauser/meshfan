# meshfan. Research, status, and open questions

This is the master record of what we know, what we decided, and what is left.
It is written to survive context compaction. Read this first when picking the
work back up.

Last updated: 2026-11-06.

## 1. What meshfan is, and why it exists

meshfan is a small Python daemon. It subscribes to one MQTT source and
republishes every message to a list of MQTT-over-WebSocket (WSS) brokers.
Each target is authenticated with MeshCore "device signing". The username is
`v1_<PUBLIC_KEY>` and the password is a short-lived Ed25519 signed JWT.

The wall it gets past:

1. No MQTT broker can sign the JWT. The password is a signature that changes
   over time (iat and exp move). A broker password field is a static string.
2. No MQTT broker does an outgoing WebSocket bridge. Mosquitto's address is
   TCP/TLS only. EMQX says an MQTT-over-WebSocket bridge is not in their plan.
3. Observers are slot limited (2 TLS/WSS max on no-PSRAM). Pointing a slot at
   each broker does not scale.

So a 2-slot observer cannot reach multiple device-signing brokers, and the
plain-MQTT Mosquitto relay only reaches static-credential brokers. meshfan
fills that gap. It runs on a server (the relay host), uses no observer slot,
and holds no persistent state.

## 2. Research findings. No off-the-shelf tool does this

We searched the whole space. Nothing subscribes to an existing MQTT broker and
fans out to multiple JWT/WebSocket brokers.

| Tool | What it is | Why it does not fit |
|---|---|---|
| Mosquitto / EMQX / HiveMQ | MQTT brokers with bridges | No outgoing WS bridge. No JWT signing. |
| c-mqtt-forwarder | Generic MQTT fan-in/fan-out (C) | Plain MQTT only (mqtts/mqtt). No WS. No JWT. |
| meshcoretomqtt (Cisien) | Radio to MQTT, with device signing | Needs a radio. Cannot consume an existing MQTT broker. |
| meshcore-packet-capture (agessaman) | Radio receiver | Needs a radio. |
| meshcore-mqtt-broker (michaelhart) | Receiving-side broker | Reverse direction. It is the target, not the forwarder. |
| meshgram (neoemit) | Radio to MQTT with device signing | Needs a radio. |
| mesh-client (Colorado-Mesh) | Radio client with device signing | Needs a radio. |

Conclusion: meshfan is genuinely needed. There is no fork-or-use shortcut.

## 3. The JWT contract (full reference in docs/JWT.md)

- Username: `v1_<PUBLIC_KEY>` (64 hex, uppercase).
- Password: a "JWT-style" token, `HEADER.PAYLOAD.SIGNATURE`.
- Header: `{"alg": "Ed25519", "typ": "JWT"}` (base64url, JSON with no spaces).
- Payload: `{"publicKey": <upper>, "iat": <sec>, "exp": <sec>, "aud": <aud>, "client": <id>}`.
- Signature: Ed25519 over `HEADER.PAYLOAD`, hex encoded, UPPERCASE.
- Renew about 6 minutes before exp. Typical TTL 1 hour.
- `aud` is broker specific (MeshOMatic uses `map.meshomatic.net`).
- WebSocket path is broker specific (`/mqtt` for MeshOMatic).

Pitfalls (easy to get wrong):

- `alg` is `Ed25519`, not `EdDSA`.
- The signature is hex, not base64url.
- JSON must be serialized with no whitespace.
- `aud` is not always the connect host.

## 4. CRITICAL. The 64-byte key format (the big gotcha)

The MeshCore 64-byte private key is NOT the standard `seed || pubkey`
extended-key format. It is the EXPANDED form:

    [ 32-byte scalar ][ 32-byte nonce prefix / filler ]

i.e. `h = SHA512(seed)`. Confirmed by:

- orlp/ed25519 README: "this library stores private keys in a different format
  than libsodium... you must keep the seed around."
- meshcore-keygen: "First 32 bytes: Clamped Ed25519 scalar. Last 32 bytes:
  random filler."

Consequence: `cryptography`'s `Ed25519PrivateKey.from_private_bytes(seed)`
CANNOT sign this key. It wants the 32-byte seed, and the seed is not
recoverable from `h` (SHA512 is one-way).

Decision: use `ed25519_orlp` (the exact library the reference uses). It is a
PyPI package (declared in meshcoretomqtt's pyproject.toml). It signs from the
scalar, so it works with the MeshCore key format. It is a C library (zlib
license, SUPERCOP ref10 based, 578 stars) with a Python binding.

Confirmed API (read from the 0.1.3 sdist, `src/ed25519_orlp/ed25519.py`):

```python
ed25519_sign(message: bytes, pubkey: bytes, prvkey: bytes) -> bytes  # 64-byte sig
ed25519_verify(signature: bytes, message: bytes, pubkey: bytes) -> bool
ed25519_create_keypair(seed=None) -> (pub, prv, seed)
```

Note `ed25519_sign` takes BOTH the public and private key. It is a ctypes
wrapper that loads a pre-compiled shared library (`libed25519.so` / `.dylib`).

Deployment note (confirmed from the sdist `setup.py` and the 0.1.3 release):
the 0.1.3 release only published wheels for macOS arm64 and x86_64 Linux
(manylinux + musl). There is NO armv7l wheel, even though the author's
cibuildwheel config lists armv7l targets. So on the Pi (PXEpi, buster,
armv7l) the sdist must be built. `setup.py` compiles the C source via a plain
setuptools `Extension` (no Python C API linkage), so it needs a C compiler
(gcc). python3-dev is not strictly required because there is no Python C API,
but a normal `apt install build-essential` covers it. This is a deployment
consideration, not a blocker. Verify on the Pi before relying on it.

## 5. Architecture prior art (meshcoretomqtt)

meshcoretomqtt is the best structural reference. Patterns to adopt:

- ABC boundaries for testability (AuthProvider, BrokerClient). Inject fakes in
  tests.
- Token caching with TTL (do not re-sign on every message).
- Graceful shutdown (SIGTERM sets a flag. The main loop checks it).
- systemd unit with security hardening (NoNewPrivileges, ProtectSystem,
  PrivateTmp).
- Test tiers (unit / network / system / e2e).
- Config with layered override.

meshfan is simpler (no serial, no message parsing). It is: source sub, then
fan-out, then N sinks. Each sink signs a fresh JWT (cached with TTL), opens a
WSS connection, publishes, renews before exp, and reconnects with backoff.

## 6. Dependencies (only what is beneficial)

- `ed25519_orlp` (signing. The exact reference library.)
- `paho-mqtt` (MQTT client. Plain TCP source plus WS targets; 2.x has
its own WebSocket transport, so `websocket-client` is not needed.)
- `PyYAML` (config file.)

Dropped: `cryptography` (cannot sign the MeshCore key format. See section 4.)

## 7. Status

Done:

- [x] Project scaffold (git, pyproject.toml, LICENSE, .gitignore, package root).
- [x] docs/SPEC.md (need plus objectives plus config plus security plus ops).
- [x] docs/JWT.md (the device-signing contract).
- [x] Language decision: Python.
- [x] Research: no off-the-shelf tool.
- [x] Key format discovery (section 4).
- [x] Signing library decision: ed25519_orlp.
- [x] Logging requirement: stdout only by default. Optional file or syslog.
- [x] Core code (config, key, jwt, source, sink, fanout, log, __main__).
- [x] JWT signing verified (round-trip sign/verify, tamper rejected, renewal window).
- [x] config/meshfan.example.yaml.
- [x] No-static-content pass (client_id, keepalive, max_queued_messages,
  shutdown_timeout, username_prefix all configurable).
- [x] Efficiency review (free model): 4 major + 4 minor findings, all fixed
  (shutdown stall, backoff OverflowError, publish race, jitter validation,
  SSL-context caching, off-by-one, source stop order).

In progress (delegated to subagents):

- [ ] Security review (free model): 8 major + 16 minor findings. Being applied
  by a subagent, together with the age-encrypted key feature.
- [ ] age-encrypted key file support + `meshfan key encrypt` helper (decided:
  age-sctl, passphrase from an env var, never on the command line).

Reusability / API review: first pass done (13 major, 20 minor; report in
docs/REVIEW-reusability-api.md). It ran on a non-preferred model and against a
moving tree (security edits landed mid-review), so it will be re-run on
deepseek-v4.1-flash-free once the security+age task completes and the tree
settles at a commit. Key recurring themes (several overlap with the security
findings already being applied): no tests (incl. the mandated JWT known-answer
test), no README, no public API surface / exception hierarchy, no client-factory
test seam, file-only config loading, unknown keys silently ignored, ValueError
tracebacks instead of ConfigError, unenforced chmod-600 claim, dependencies not
split, jwt.py missing length validation and a verify() helper.

Not done:

- [ ] Tests (JWT signing vs reference, config validation, key loading).
- [ ] docs/ARCHITECTURE.md, docs/SECURITY.md, docs/CONFIGURATION.md,
  docs/DEPLOYMENT.md.
- [ ] README.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md.
- [ ] contrib/systemd/meshfan.service (must set LimitCORE=0 per the security
  review).
- [ ] .github/workflows/ci.yml.
- [ ] Release artifacts (version, tags, release notes).

## 8. Open questions and roadblocks

- Verify `ed25519_orlp` installs on the Pi (buster, armv7l). Confirmed: no
  armv7l wheel in 0.1.3, so the sdist must be built (needs a C compiler, gcc).
  Confirm the build works before relying on it.
- Confirm the exact `aud` and `path` for each target broker from the broker's
  docs (MeshOMatic: aud `map.meshomatic.net`, path `/mqtt`).
- Confirm whether the `client` claim is required by each broker (optional in the
  reference).
- The 32-byte "filler" in the MeshCore key: confirm it is the nonce prefix
  (h[32:]) and not literal random. orlp/ed25519 signs correctly with the key
  as-is, so this is likely fine, but verify with a test against a known-good
  token.

## 9. Verification plan

- Unit test: sign a fixed message with a fixed key. Compare the token to a
  known-good token, or verify it with ed25519_orlp's verify function.
- `meshfan --check`: validate config plus key without connecting.
- Live test: publish a test message to the source. Confirm it arrives at each
  target (no auth rejection).
- Grep the logs for the key and the JWT. Confirm no secret leaks.
