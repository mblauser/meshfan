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

Done (delegated to subagents, committed at 61cc651):

- [x] Security review (free model): 8 major + 16 minor findings, all applied
  (strict booleans, key whitelists, numeric ranges, plaintext opt-in, publish
  race, backoff cap, live-connection token renewal, graceful shutdown, key-file
  permission check, RLIMIT_CORE=0, keypair probe in --check, log sanitation).
- [x] age-encrypted key file support + `meshfan key encrypt` helper (age-sctl,
  passphrase via a 0600 temp file, never in argv).

Follow-ups from the security+age task:
- age-sctl CLI is unverified (not installed on the dev machine); the contract
  is isolated in key.py:_age_argv for a one-line fix. Verify against the real
  tool before release.
- ed25519-orlp 0.1.3 fails to import on Python 3.9 (PEP 604); floor
  requires-python to >=3.10.

Done (delegated to subagents):

- [x] Reusability / API review re-run on deepseek-v4.1-flash-free against the
  settled tree (commit 61cc651). 17 major + 11 minor findings; report in
  docs/REVIEW-reusability-api-61cc651.md. Notable new findings: main()
  irreversibly zeroes the host core-dump hard limit even on --check; the
  config object stores and reprs the resolved password (secret leak); pip
  install is not runnable (CWD-relative config, nothing shipped); key loading
  is non-idempotent (env pop).

Done (delegated to subagents):

- [x] Apply the reusability review (top-5). NOTE: the free-model daily quota
  was exhausted mid-dispatch, so this pass ran on the current model
  (Qwen3.8-27B on Neuronic); a first attempt left partial changes and the
  tree was reverted to the clean 61cc651 state before re-dispatch. Result:
  public surface (__all__ + re-exports, errors.py MeshfanError, py.typed,
  lazy YAML, loads/from_dict), secret handling (frozen Config, repr=False,
  ResolvedSecrets, idempotent key loaders), test seam (MqttClient Protocol,
  client_factory, injected clocks/RNG), 155 passing tests (incl. the JWT
  known-answer test), MeshfanApp/run() with no process-global side effects
  (RLIMIT/signals/logging in cli.py), packaging (dep split, single-source
  version, SPDX MIT, README, --init-config, jwt sign, key generate, CI
  matrix 3.10-3.14, requires-python >=3.10).

(First-pass reusability review, 13 major + 20 minor, is in
docs/REVIEW-reusability-api.md; it ran on a moving tree and a non-preferred
model, so the 61cc651 re-run above supersedes it. Key recurring themes (several overlap with the security
findings already being applied): no tests (incl. the mandated JWT known-answer
test), no README, no public API surface / exception hierarchy, no client-factory
test seam, file-only config loading, unknown keys silently ignored, ValueError
tracebacks instead of ConfigError, unenforced chmod-600 claim, dependencies not
split, jwt.py missing length validation and a verify() helper.

Done:

- [x] Tests (JWT known-answer, config validation, key loading, sink
  renewal/backoff, fanout, app, cli exit codes): 155 passing.
- [x] docs/ARCHITECTURE.md, docs/SECURITY.md, docs/CONFIGURATION.md,
  docs/DEPLOYMENT.md.
- [x] README.md, CHANGELOG.md, CONTRIBUTING.md, top-level SECURITY.md.
- [x] contrib/systemd/meshfan.service (sets LimitCORE=0 per the security
  review).
- [x] .github/workflows/ci.yml (matrix 3.10-3.14).

Done:

- [x] Release: repo `mblauser/meshfan` created (public), branch `main`
  pushed, tag `v0.1.0` pushed, release published from
  docs/RELEASE-v0.1.0.md
  (https://github.com/mblauser/meshfan/releases/tag/v0.1.0).

Not done:

- [ ] Verify the `age-sctl` CLI contract on a machine that has it.
  Neither the dev machine nor PXEpi has `age-sctl` or `age` installed,
  and there is no public `age-sctl` repository, so it cannot be verified
  from here. The contract is isolated in `key.py:_age_argv` (a one-line
  fix) and a verification snippet is in docs/DEPLOYMENT.md.
- [x] PXEpi deploy (complete, verified, end-to-end confirmed). CPython
  3.11.9 built into `/opt/python3.11` (system `python3.7` untouched);
  `meshfan` system user; venv at `/opt/meshfan/venv`; `meshfan[full]`
  installed from `requirements.lock` (ed25519-orlp from the piwheels
  armv7l wheel, no sdist build); config + 0600 `EnvironmentFile`
  (env-var key); `--check` passed (keypair verified); systemd unit
  enabled and running; source connected and the MeshOMatic sink
  connected (signed JWT accepted by the broker); stable with no
  reconnects. **End-to-end confirmed:** a real advert published to the
  local relay was relayed to MeshOMatic and appeared on the MeshOMatic
  map (the sink log shows published messages accumulating,
  `connected=True`). Build artifacts cleaned up (306 MB freed). Back-out:
  `systemctl disable --now meshfan`, remove `/opt/meshfan`,
  `/opt/python3.11`, `/etc/meshfan`, the `meshfan` user, and
  `libffi-dev`.

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
