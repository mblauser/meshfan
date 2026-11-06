# meshfan specification

Version 0.1.0 (draft). Last updated 2026-11-06.

## Why this exists

MeshCore's packet analyzers and coverage platforms (MeshOMatic, MeshMapper,
LetsMesh, rflab, and others) all use the same login: device signing. The
MQTT username is `v1_<PUBLIC_KEY>` and the password is a short-lived JWT
signed by the node's Ed25519 private key.

That login is a hard wall for every standard tool:

1. No MQTT broker can sign the JWT. The password is a signature that changes
   over time (its `iat` and `exp` move). A broker's `password` field is a
   static string.
2. No MQTT broker does an outgoing WebSocket bridge. These platforms expose
   MQTT over WebSockets (WSS) on 443, but Mosquitto's `address` is
   TCP/TLS only, and EMQX says flat out that an MQTT-over-WebSocket bridge
   is not in their plan.
3. Observers are slot limited. A no-PSRAM observer holds at most 2 TLS/WSS
   connections. Pointing a slot at each broker does not scale, and the
   operator does not want to spend a slot.

So a 2-slot observer cannot report to multiple device-signing brokers, and
the plain-MQTT fan-out relay (Mosquitto) only reaches brokers that accept
static credentials. Never a broker that needs a signed JWT.

## What meshfan does

meshfan is a small, single-purpose userland process that:

1. Subscribes to one MQTT source (for example the local relay's
   `meshcore/#`).
2. Fans each message out to N target brokers, each over MQTT-over-WebSocket
   (WSS).
3. Signs a fresh Ed25519 device JWT per target (with the node's private key)
   and uses it as the MQTT password.
4. Renews the JWT before it expires and reconnects with backoff.
5. Uses no observer slot. It runs on a server (for example the relay host).
6. Holds no persistent state (in-memory only).

One process, one config file, N brokers. That is the whole product.

## What it is not

- Not a general-purpose MQTT broker. Use Mosquitto or EMQX for that.
- Not a radio receiver or packet-capture tool. Use meshcore-packet-capture.
- Not a replacement for the observer's own direct JWT connection.
- Not bidirectional. It is a publish-only fan-out (the source is read, the
  targets are written).
- No persistent state, no database, no retention.

## Architecture

```
                         +------------------------------+
  MQTT source           |           meshfan            |        WSS target 1
  (e.g. 127.0.0.1:     |                              |  +----------------------+
   1883, meshcore/#)    |  +---------+   +---------+  |  | host:port, path,    |
  +----------------+--> |  | source  |-->| fan-out |--+->| audience, iata, ... |
   subscribe           |  +---------+   +---------+  |  +----------------------+
                         |                    ^      |  +----------------------+
                         |  +---------+       |      |  | WSS target 2         |
                         |  | sink 1  |<------+-----+->| host:port, path, ...  |
                         |  +---------+  (sign JWT  |  +----------------------+
                         |  +---------+  per target)|  +----------------------+
                         |  | sink 2  |<-------------+->| WSS target 3         |
                         |  +---------+               |  +----------------------+
                         |  +---------+               |
                         |  |  ...    |               |
                         |  +---------+               |
                         +------------------------------+
```

- Source: a single MQTT subscription (paho-mqtt, plain TCP or TLS).
- Fan-out: an in-memory message bus. Each message goes to every target.
- Sinks: one per target broker. Each sink signs a fresh JWT (Ed25519) with
  the target's audience, opens a WSS connection (paho-mqtt plus
  websocket-client, TLS verified), publishes the message, renews the JWT
  before `exp`, and reconnects with exponential backoff plus jitter.
- Key store: the Ed25519 private key is loaded once (env var or a chmod 600
  file), held in memory, and never written to logs or disk.

## Configuration (one file)

One YAML file (`config/meshfan.yaml`, gitignored. The committed
`config/meshfan.example.yaml` uses placeholders only) defines all parameters:
the source, the key, an enumerated list of target brokers, token lifetime,
reconnect policy, and debug flags. Design rules:

- Every tunable lives in the config file (or an env var it names). No
  hard-coded values, no CLI flags for configuration.
- The target list is a flat, enumerable sequence. Add or remove a broker by
  adding or removing a list item.
- Secrets (the private key) are referenced by env-var name or file path,
  never inlined.

## Security model

- Key handling: the private key is loaded from an env var (preferred) or a
  chmod 600 file, held in memory only, and never logged, written to disk, or
  included in crash dumps.
- TLS: certificate verification is on by default. Skipping it requires an
  explicit `tls.insecure: true`, which logs a loud warning.
- No secret logging: the private key, the full JWT, and the password are
  never logged. Only non-sensitive status is.
- Least privilege: the process needs only outbound network to the source and
  targets, plus read access to the key.
- No telemetry, no phone-home.

## Operational requirements

- Runs as a systemd service (unit provided).
- Logging: stdout only by default (journald). Nothing is written to disk, to
  avoid SD wear. The config can switch the output to a file or to syslog if
  desired.
- In-memory only. No state directory.
- Graceful shutdown on SIGTERM (close connections, no partial writes).
- A `--check` flag validates config plus key without connecting.

## Verification and acceptance criteria

- [ ] `meshfan --check` validates the config and key.
- [ ] A test message published to the source arrives at each target.
- [ ] The JWT is accepted by the target (no auth rejection).
- [ ] The JWT is renewed before expiry (visible in debug logs).
- [ ] Reconnection works when a target is restarted.
- [ ] No secret appears in the logs (grep the logs for the key or JWT).
- [ ] The config file with real secrets is gitignored.
