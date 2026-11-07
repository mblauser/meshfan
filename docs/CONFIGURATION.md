# Configuration

meshfan reads one YAML file. Create a starter from the packaged
example:

```sh
meshfan --init-config /etc/meshfan/meshfan.yaml
```

The file is written with mode 0600. It may contain hostnames and
credentials, so keep it at 0600 (or 0640 group-readable). meshfan
warns at startup if it is wider.

Two rules apply to the whole file:

- **Unknown keys are rejected** in every section. A typo is a config
  error, never silently ignored.
- **Secrets are referenced, never inlined.** By environment variable
  name or by a 0600 file path. The one deprecated exception is
  `source.password`, which warns on every start.

Validate without touching the network:

```sh
meshfan --config /etc/meshfan/meshfan.yaml --check
```

## Top level

Required: `source`, `key`, `brokers`. Optional: `token`, `reconnect`,
`runtime`, `logging`, `debug`.

## source

The MQTT source (the local relay).

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `host` | str | required | |
| `port` | int | required | 1..65535 |
| `topic` | str | required | e.g. `meshcore/#` |
| `username` | str | none | if the source broker requires it |
| `password` | str | none | **deprecated**: inline, warns every start |
| `password_env` | str | none | env var name (preferred). Use only one of `password`, `password_env`, `password_file` |
| `password_file` | str | none | 0600 file (symlinks refused). Use only one of the three |
| `client_id` | str | `meshfan-<hostname>-<pid>` | resolved at startup; the config stays deterministic |
| `keepalive` | int | 30 | >= 1 |
| `qos` | int | 0 | 0, 1, or 2 |
| `tls` | mapping | see below | |

## key

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `public_key` | str | required | 64 hex chars, uppercase or lowercase. Must match the private key; verified by a fixed probe at startup and in `--check` |
| `private_key_env` | str | none | env var holding the 128-hex key. Preferred. The variable is removed from the environment after reading |
| `private_key_file` | str | none | 0600 regular file holding the 128-hex key (or the age ciphertext with `encryption: age`) |
| `encryption` | str | `none` | `none` or `age`. With `age`, `private_key_file` is the ciphertext and `passphrase_env` is required |
| `passphrase_env` | str | none | env var holding the age passphrase. Handed to age through a 0600 file, never argv |
| `age_command` | str | `age-sctl` | the age binary (configurable for wrappers) |
| `age_timeout_seconds` | float | 30 | > 0 |

With `encryption: none`, set exactly one of `private_key_env` or
`private_key_file` (setting both works, the env var wins, and a
warning is printed). Create an age-encrypted key with:

```sh
export MESHFAN_AGE_PASSPHRASE=...
meshfan key encrypt --in key.plain --out key.age --passphrase-env MESHFAN_AGE_PASSPHRASE
```

## brokers

A non-empty list. Each item:

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | str | required | unique within the list |
| `host` | str | required | |
| `port` | int | required | 1..65535 |
| `path` | str | required | the broker-specific WebSocket path, e.g. `/mqtt` |
| `audience` | str | required | the broker-specific JWT `aud`, e.g. `map.meshomatic.net` |
| `client` | str | `meshfan-<name>` | the MQTT client id (the `client` claim). Make it unique if two relays share this broker |
| `keepalive` | int | 30 | >= 1 |
| `tls` | mapping | enabled, verified | see below |

## tls (source and each broker)

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | bool | true | |
| `plaintext` | bool | false | required `true` when `enabled` is `false`; the second explicit opt-in |
| `insecure` | bool | false | `true` disables certificate verification; loud warning |
| `ca_file` | str | none | a CA bundle to load; must exist and load, checked at startup |

`enabled: false` + `plaintext: true` is accepted with a loud warning.
`enabled: true` + `plaintext: true` is a config error.

## token

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `ttl_seconds` | int | 3600 | 1..86400 |
| `renew_before_seconds` | int | 360 | 0 <= value < ttl. The sink drops the connection and reconnects with a fresh token here |

## reconnect

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `base_delay` | float | 1.0 | 0 < base <= max |
| `max_delay` | float | 60.0 | the backoff cap |
| `multiplier` | float | 2.0 | >= 1.0 |
| `jitter` | float | 0.5 | 0.0 <= jitter < 1.0 |

## runtime

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `max_queued_messages` | int | 1000 | per-sink outgoing queue cap; 0 = unlimited |
| `shutdown_timeout` | float | 5.0 | seconds to wait for a sink to stop; > 0 |
| `username_prefix` | str | `v1_` | the device-signing username prefix; printable ASCII |
| `token_check_seconds` | float | 30 | live-connection token/renewal check period; > 0 |
| `connect_timeout_seconds` | float | 10 | TCP connect + CONNACK deadline per attempt; > 0 |
| `summary_interval_seconds` | float | 300 | per-sink published/dropped summary; 0 = off |

## logging

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `level` | str | `INFO` | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `output` | str | `stdout` | `stdout`, `file`, or `syslog`. stdout by default (SD-wear clean) |
| `file_path` | str | none | required when `output` is `file`; created 0600, rotated |
| `max_bytes` | int | 10485760 | rotate at 10 MiB |
| `backup_count` | int | 5 | rotated files to keep |

## debug

| Key | Type | Default | Notes |
| --- | --- | --- | --- |
| `messages` | bool | false | log each dispatched topic (not payloads) |
| `tokens` | bool | false | log token renewal events (no secrets) |
| `paho` | bool | false | let paho log at DEBUG (very noisy) |

## Startup warnings

These print on every start (and in `--check`), and are not errors:

- `source.password` is inline and deprecated.
- An endpoint is plaintext (`tls.enabled: false, tls.plaintext: true`).
- An endpoint has certificate verification disabled (`tls.insecure: true`).
- `key`: both `private_key_env` and `private_key_file` are set (the
  env var wins).
- `key.passphrase_env` is set but `encryption` is `none` (ignored).
