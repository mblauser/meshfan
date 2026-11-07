# Contributing

Thanks for helping with meshfan.

## Development setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

`[dev]` pulls in pytest, ruff, mypy, paho-mqtt, and PyYAML.

## Run the checks

```sh
.venv/bin/pytest -q          # the test suite (155 tests)
.venv/bin/ruff check meshfan tests
.venv/bin/mypy meshfan
```

The test suite is network-isolated: no test needs a broker (the
`MqttClient` Protocol seam) or a real clock (injected clocks and RNG).

## Rules that matter here

- **The JWT wire format is byte-exact.** Do not change the signing
  logic in `meshfan/jwt.py`. The known-answer test pins it; a change
  that breaks the test is a bug, not a test to fix.
- **No hardcoded tunables.** Every variable belongs in the config.
  If you find a constant that should be adjustable, add a config key
  (with a default and validation) instead.
- **No secrets in code.** Env var name or 0600 file path, never
  inlined. The config object must stay secret-free in its `repr()`.
- **Docs are human and simple.** Short sentences, no em dashes, no
  filler. Every file containing hostnames, keys, or IPs is
  git-ignored; only `*.example.*` files are committed.
- **New code gets tests.** Match the existing style: no network, no
  real time, injected seams.
- **Dependency changes update the locks.** If you change a constraint
  in `pyproject.toml`, also update `requirements.in` /
  `requirements-dev.in` and regenerate the locks (`pip-compile`, see
  the README). CI verifies the locks install cleanly on every supported Python.

## Pull requests

1. Fork and branch from `main`.
2. Keep the diff small and focused; one concern per PR.
3. All checks green: `pytest`, `ruff`, `mypy`.
4. Update the docs if behavior or the config changes, and add an
   entry to `CHANGELOG.md`.
5. Describe what changed and why, and how you tested it.

## Reporting problems

See [SECURITY.md](SECURITY.md) for security issues. For everything
else, open an issue with: the meshfan version, the Python version,
the OS, and the smallest config (secrets removed) that reproduces it.
