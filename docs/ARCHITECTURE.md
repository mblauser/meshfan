# Architecture

meshfan is one process with a fixed shape:

```
MQTT source  ->  Fanout  ->  Sink 1  (WSS broker, signed JWT)
                 (in-process) ->  Sink 2  (WSS broker, signed JWT)
                                   ...
```

The source subscribes to one topic. Every message is fanned out to every
sink. Each sink owns one target broker, its token, and its connection.
A sink failing never affects the others.

## Modules

| Module | Responsibility |
| --- | --- |
| `config.py` | Parse + validate the config. Strict: unknown keys rejected, strict booleans, numeric ranges, duplicate broker names rejected. Exposes `load()`, `loads()`, `from_dict()`. |
| `key.py` | Load the private key (env var, 0600 file, or age-encrypted file) and the public key; verify the keypair with a fixed probe. |
| `jwt.py` | The Ed25519 device JWT: sign, verify, decode. No I/O, no YAML dependency. The wire format is byte-exact (see [JWT.md](JWT.md)). |
| `source.py` | The MQTT source client (paho), one thread. Subscribes and hands messages to the fanout. |
| `fanout.py` | In-process dispatch: for each message, push to every sink queue. Drops and counts when a sink queue is full. |
| `sink.py` | One WSS sink: one thread, one broker. Signs/renews the JWT, connects with verified TLS, publishes, reconnects with backoff + jitter. |
| `tls.py` | Build and validate the SSL contexts once, at startup (and in `--check`), so a bad CA file is a clear exit 2, not a reconnect loop. |
| `transport.py` | The `MqttClient` Protocol and the `client_factory` seam (tests inject a fake client). |
| `app.py` | `MeshfanApp`: start/stop the relay in-process. No signal handlers, no RLIMIT changes, no global logging. `prepare()` resolves secrets into `ResolvedSecrets` without touching the (frozen) `Config`. |
| `cli.py` | The standalone process: argparse, exit codes, and the process-global side effects (RLIMIT_CORE, signal handlers, logging setup). |
| `log.py` | Logging setup (stdout by default, optional file/syslog) and `sanitize()` for untrusted strings. |
| `errors.py` | `MeshfanError` base; `ConfigError` and `KeyLoadError` under it. |

## Threading model

- One thread per sink, plus one for the source. No shared mutable state
  between them: the fanout hands each message to each sink's own
  `queue.Queue`.
- The sink thread is the only thing that touches its paho client.
- `MeshfanApp.stop()` stops the source first, then the sinks, and waits
  `runtime.shutdown_timeout` for each to finish.

## Token lifecycle (per sink)

1. Sign a fresh JWT at connect. The username is
   `<username_prefix><public key hex, uppercase>`; the password is the
   token.
2. Renewal is scheduled on `time.monotonic()`; only `iat`/`exp` use the
   wall clock.
3. Every `runtime.token_check_seconds`, a live sink re-checks its token.
   When it is within `token.renew_before_seconds` of expiry, the sink
   drops the connection and reconnects with a freshly signed token.
4. A CONNACK with code 4 or 5 (bad credentials / not authorized) is
   treated the same way: reconnect with a fresh token.
5. Reconnects use exponential backoff (`reconnect.*`) with jitter,
   capped at `reconnect.max_delay`.

## Library vs. process

The library (`meshfan.app`, `meshfan.config`, `meshfan.jwt`, ...) never
touches process-global state. `RLIMIT_CORE=0`, SIGTERM/SIGINT handlers,
and the global logging configuration live in `meshfan.cli`, which is a
standalone process and may own the process. That is what makes
`MeshfanApp` safe to embed in a host that runs other things.

## Test seams

- `MqttClient` (a `Protocol`) + `client_factory` on `Source` and `Sink`:
  tests inject a fake client, so no test needs a broker.
- Injected `wall_clock`, `mono_clock`, and `rng` on `Sink`: renewal,
  backoff, and jitter are tested deterministically.
- `prepare()` / `load_private_key()` take an `env` mapping and a
  `consume` flag, so library use is idempotent (reload, retry, two
  relays in one process).
- The JWT known-answer test pins the wire format byte for byte.

## Exit codes (CLI)

| Code | Meaning |
| --- | --- |
| 0 | OK (including `--check` success) |
| 2 | Config, key, logging, TLS, or usage error |

`--check` validates the config, the keypair (signs a fixed probe and
verifies it), the TLS material, and the log path, then exits without
touching the network.
