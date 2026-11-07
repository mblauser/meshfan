# meshfan v0.1.0

First release.

meshfan is an MQTT fan-out relay that signs Ed25519 device JWTs for
MeshCore MQTT-over-WebSocket (WSS) brokers. It subscribes to one MQTT
source and republishes every message to a list of WSS brokers, each
authenticated with a short-lived Ed25519 device JWT signed with the
node's private key. No broker can sign that JWT itself; that is the
gap meshfan fills.

## What is in this release

- The relay: one source, many WSS sinks, per-sink threads, exponential
  backoff with jitter, per-sink queue caps, graceful shutdown.
- Ed25519 device JWT signing with the byte-exact wire format (header
  `alg: Ed25519`, UPPERCASE hex signature, no-whitespace JSON),
  short-lived tokens renewed before expiry on the live connection.
- Key handling: env var (consumed after reading), 0600 file (symlink
  and mode checks, race-closed), age-encrypted file (passphrase via a
  0600 temp file, never argv, redacted on failure); keypair probe at
  startup and in `--check`.
- Strict config validation: unknown keys rejected, strict booleans,
  numeric ranges, duplicate broker names rejected; `Config` is frozen
  and its `repr()` never contains a secret.
- CLI: `--config`, `--check`, `--init-config`, `key encrypt`,
  `key generate`, `jwt sign`.
- Embeddable `MeshfanApp` with no process-global side effects, plus
  `MqttClient` Protocol and injected clocks/RNG as test seams.
- 155 tests, including the JWT known-answer test that pins the wire
  format. CI matrix 3.10 to 3.14.
- A systemd unit (`contrib/systemd/meshfan.service`) with `LimitCORE=0`.

## Install

```sh
pip install "meshfan[full]"     # Python 3.10+
```

Requires Python 3.10 or newer. On armv7l (for example a Raspberry Pi
on Debian buster) `ed25519-orlp` has no wheel, so it is built from
the sdist and needs `gcc`.

## Quick start

```sh
meshfan --init-config /etc/meshfan/meshfan.yaml
meshfan key generate --out /etc/meshfan/key.plain --pub-out /etc/meshfan/key.pub
# edit the config (key.public_key, source, brokers), then:
meshfan --config /etc/meshfan/meshfan.yaml --check
meshfan --config /etc/meshfan/meshfan.yaml
```

## Notes

- The token is not a standard RFC 7519 JWT and is not PyJWT-compatible.
  See `docs/JWT.md` for the exact wire format.
- Logging defaults to stdout only (SD-wear clean); file and syslog
  output are explicit config choices.
- See `docs/DEPLOYMENT.md` for the systemd unit and the PXEpi
  (armv7l) deploy notes.
