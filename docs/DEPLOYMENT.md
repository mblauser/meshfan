# Deployment

## Requirements

- Python 3.10 or newer. (3.9 is out: `ed25519-orlp` 0.1.3 does not
  import on 3.9, its own source uses `bytes | None` annotations at
  runtime. Verified by installing 0.1.3 into a 3.9 venv and a 3.10
  venv.)
- `ed25519-orlp` 0.1.x. Wheels exist for macOS arm64 and x86_64
  Linux. **There is no armv7l wheel in 0.1.3**, so on an armv7l
  machine (like PXEpi) the sdist must be built, which needs `gcc`.
- `age-sctl` (the age CLI) if you use an age-encrypted key file.

## Install (a normal machine)

```sh
python3 -m venv /opt/meshfan/venv
/opt/meshfan/venv/bin/pip install "meshfan[full]"
# or, from a source checkout:
/opt/meshfan/venv/bin/pip install -e ".[full]"
```

`[full]` is the daemon (paho-mqtt) plus YAML config parsing (PyYAML).
The pure signer needs only `meshfan` (ed25519-orlp).

## Set up

1. Create a starter config (mode 0600):

   ```sh
   meshfan --init-config /etc/meshfan/meshfan.yaml
   ```

2. Generate a keypair (or use your existing one):

   ```sh
   meshfan key generate --out /etc/meshfan/key.plain --pub-out /etc/meshfan/key.pub
   ```

   Put the printed 64-hex public key into `key.public_key`.

3. Encrypt the key with age (recommended; the passphrase is read from
   an env var, never from argv):

   ```sh
   export MESHFAN_AGE_PASSPHRASE=...
   meshfan key encrypt --in /etc/meshfan/key.plain \
       --out /etc/meshfan/key.age --passphrase-env MESHFAN_AGE_PASSPHRASE
   ```

   Then set `key.encryption: age`, `key.private_key_file:
   /etc/meshfan/key.age`, `key.passphrase_env: MESHFAN_AGE_PASSPHRASE`.

4. Fill in the config, then validate without touching the network:

   ```sh
   meshfan --config /etc/meshfan/meshfan.yaml --check
   ```

5. Run it:

   ```sh
   meshfan --config /etc/meshfan/meshfan.yaml
   ```

## systemd

A unit file is in `contrib/systemd/meshfan.service`. The important
lines:

- `LimitCORE=0`: the key must not reach a core dump. (The CLI process
  also zeroes `RLIMIT_CORE` itself; the unit is the second,
  independent layer.)
- `EnvironmentFile=` (mode 0600) for the key and passphrase variables,
  not `Environment=`: the variables are then not visible in
  `systemctl show`. meshfan removes the key variable from its
  environment after reading it.
- Logging to stdout by default goes to journald; nothing is written to
  disk (SD-wear clean).

```ini
[Unit]
Description=meshfan MQTT fan-out relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshfan
EnvironmentFile=/etc/meshfan/env
ExecStart=/opt/meshfan/venv/bin/meshfan --config /etc/meshfan/meshfan.yaml
Restart=on-failure
RestartSec=5
LimitCORE=0
UMask=0077
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`/etc/meshfan/env` (mode 0600) holds the variable names, for example:

```
MESHFAN_PRIVATE_KEY=<128-hex key>
MESHFAN_AGE_PASSPHRASE=<passphrase>
```

(Use either the plain-key env var or the age passphrase, matching the
config's `key` section.)

## PXEpi (armv7l, Debian buster)

PXEpi-specific rules for the deploy:

- **No reboot.** The box serves NFS; a reboot is not acceptable.
- **No package upgrades** other than what the deploy itself needs.
- **SD-wear clean**: keep logging on stdout (journald); do not switch
  to file logging on the SD.
- **Test every fix with a back-out plan.**

### What the box has (verified)

- `gcc` is present. `ed25519-orlp` has no armv7l wheel in 0.1.3, so
  it is built from the sdist with gcc.
- **The system Python is 3.7.3, and buster's apt only offers 3.7.3.**
  meshfan needs 3.10+. A newer CPython (3.11) must be built from
  source into its own prefix (for example `/usr/local` or
  `/opt/python3.11`), leaving the system `python3.7` untouched. This
  is a new package, not an upgrade of an existing one.
- **`age-sctl` and `age` are not installed.** The age-encrypted key
  path therefore cannot be used on this box. Use the env-var key
  (`key.private_key_env`) or a plain 0600 file (`key.private_key_file`)
  instead. The age path is for machines that have `age-sctl`.

### Deploy steps (with back-out)

1. Build CPython 3.11 from source into its own prefix. Back-out:
   remove the prefix; the system `python3.7` is never touched.
2. Create the venv from the new Python and install:

   ```sh
   /opt/python3.11/bin/python3.11 -m venv /opt/meshfan/venv
   /opt/meshfan/venv/bin/pip install "meshfan[full]"
   # pip downloads the ed25519-orlp sdist and builds it with gcc
   /opt/meshfan/venv/bin/meshfan --version
   ```

3. Set up the config and key (env var or 0600 file, not age), then
   `--check`.
4. Run the systemd unit (point `ExecStart` at the venv's `meshfan`).
   Verify with `--check` before enabling, and confirm the relay is
   publishing before removing the manual run. Back-out: disable the
   unit and remove `/opt/meshfan`; the relay is the only new thing.

## age-sctl

meshfan shells out to `age-sctl` with the contract:

```
age-sctl <encrypt|decrypt> --passphrase-file <path> <file>
```

The plaintext or ciphertext comes back on stdout; the passphrase is
only ever in the 0600 file, never in argv. If the installed
`age-sctl` uses different flags, the single place to adapt is
`meshfan.key._age_argv` (and `key.age_command` selects the binary).
Verify the contract on a machine that has it before relying on it:

```sh
echo "test" > plain.txt
age-sctl encrypt --passphrase-file pass.txt plain.txt > enc.txt
age-sctl decrypt --passphrase-file pass.txt enc.txt   # -> "test"
```
