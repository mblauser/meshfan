# Security

The one secret meshfan holds is the MeshCore Ed25519 private key
(64 bytes, 128 hex chars, the expanded `[scalar][filler]` form).
Everything below is about keeping that key out of logs, files,
process listings, and core dumps, and about keeping the connection to
the target broker trustworthy.

## Key handling

- **Where the key comes from**, in order of preference:
  1. `key.private_key_env`: the name of an environment variable.
  2. `key.private_key_file`: a regular file, mode 0600.
  3. `key.encryption: age`: the file is age-encrypted and the passphrase
     comes from `key.passphrase_env`.
- **The env var is consumed.** After the daemon reads it, the variable
  is removed from the process environment, so a later crash dump, a
  `/proc/<pid>/environ` read, or a child process cannot pick it up.
  Library callers can pass `consume=False` to keep it set.
- **Key files are checked, not trusted.** Before a key file is read:
  it must be a regular file (symlinks are refused, `O_NOFOLLOW` on
  open), owned by the running user or root, and mode 0600 or stricter.
  The check is repeated on the opened descriptor (`fstat`), which closes
  the stat/open race.
- **age is run with the passphrase out of argv.** The passphrase is
  written to a 0600 file in a 0700 temp directory, handed to
  `age-sctl` as `--passphrase-file`, and the directory is removed
  afterwards. The key file is never on the command line. If the age
  command fails, any occurrence of the passphrase in its stderr is
  redacted before the message is shown or logged.
- **The keypair is verified at startup.** meshfan signs a fixed probe
  and verifies it with the configured public key. A public key that
  does not match the private key is a startup error, not a runtime
  surprise. `--check` runs the same probe.
- **The key stays in memory.** It is held as bytes for the life of the
  process and never written back to disk. Core dumps are disabled in
  the CLI process (`RLIMIT_CORE=0`) and the systemd unit must set
  `LimitCORE=0`. `mlock` is intentionally out of scope.

## TLS

- TLS is on by default for every endpoint, and certificates are
  verified by default (hostname + chain).
- `tls.insecure: true` disables verification. It is accepted, but it
  produces a loud startup warning on every start and in `--check`.
- `tls.enabled: false` requires a second explicit opt-in:
  `tls.plaintext: true`. Without it the config is rejected. This is
  deliberate: a sink that sends a signed JWT in the clear is a
  decision, not a typo.
- The SSL contexts are built once at startup (and in `--check`). A
  missing or malformed `ca_file` is a clear exit 2, not an endless
  transient reconnect loop.

## Secrets in the config object

- `Config` is frozen and never carries a resolved secret. Secrets are
  resolved by `prepare()` into a separate `ResolvedSecrets` value.
- `repr()` of `Config` and `ResolvedSecrets` never contains a secret
  (the password and the private key are redacted).
- The inline `source.password` is deprecated. It works, but every start
  prints a loud warning. Use `password_env` or `password_file`.

## Logging

- **Default is stdout only** (journald). Nothing is written to disk by
  default, to avoid SD wear on small devices. File and syslog output
  are explicit config choices.
- The private key, the full JWT, and the password are never logged.
  Token events log only the fact of renewal, not the token.
- Untrusted strings (topics, broker reason strings, error text) go
  through `sanitize()`: control characters are dropped (so a topic or a
  reason string cannot forge a log line) and the length is capped.
- A log file, when used, is created with mode 0600 (never briefly
  world-readable) and rotated (`max_bytes`, `backup_count`).

## Config validation

- Unknown keys are rejected in every section: a typo is a config error,
  never silently ignored.
- Booleans must be real booleans; strings must be strings. No
  truthy-falsy guessing.
- Numeric ranges are enforced (ports 1..65535, QoS 0..2, token TTL
  1..86400, `renew_before < ttl`, backoff `0 < base <= max`, jitter
  `0 <= jitter < 1`, and so on).
- Broker names must be unique; `path` and `audience` are checked
  against a strict allowlist of characters.
- Key formats are validated: 128 hex chars (private), 64 hex chars
  (public), uppercase or lowercase.

## What the token protects

The signed JWT authenticates the relay to the broker, not the other way
around. The `aud` claim is broker-specific, so a token signed for one
broker is not accepted by another. The token is short-lived (default
1 h, renewed before expiry) and carries a `client` claim per broker.
The private key never leaves the process; only its signatures travel.

## Known limits (accepted)

- The age passphrase is read from an environment variable. Prefer a
  systemd `EnvironmentFile` (mode 0600) over `Environment=` in the unit
  file, so it is not visible in `systemctl show`.
- The inline `source.password` (deprecated) is visible in the config
  file. It is kept for compatibility and warns on every start.
- `mlock` on the key is not done. The mitigations are the disabled
  core dumps and the in-memory-only handling.
