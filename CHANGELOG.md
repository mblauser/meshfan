# Changelog

All notable changes to meshfan are listed here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-06

First release.

### Added

- The MQTT fan-out relay: one source, many WSS sinks, per-sink
  threads, exponential backoff with jitter, per-sink queue caps.
- Ed25519 device JWT signing for MeshCore MQTT-over-WebSocket
  brokers: byte-exact wire format (header `alg: Ed25519`, UPPERCASE
  hex signature, no-whitespace JSON), short-lived tokens renewed
  before expiry, on the live connection.
- Key handling: env var (consumed after reading), 0600 file (symlink
  and mode checks, race-closed), age-encrypted file (passphrase via a
  0600 temp file, never argv, redacted on failure); keypair probe at
  startup and in `--check`.
- Strict config validation: unknown keys rejected, strict booleans,
  numeric ranges, duplicate broker names rejected; `Config` is frozen
  and its `repr()` never contains a secret.
- CLI: `--config`, `--check`, `--init-config`, `key encrypt`,
  `key generate`, `jwt sign`.
- Embeddable `MeshfanApp` with no process-global side effects;
  `MqttClient` Protocol and injected clocks/RNG as test seams.
- 155 tests, including the JWT known-answer test that pins the wire
  format.
- CI matrix 3.10 to 3.14.
- Documentation: SPEC, JWT, RESEARCH, ARCHITECTURE, SECURITY,
  CONFIGURATION, DEPLOYMENT.
