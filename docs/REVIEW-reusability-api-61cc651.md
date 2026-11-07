# meshfan review: reusability and API design (current tree)

Reviewer: architecture peer-review subagent. Date: 2026-11-06.
Target: `61cc651e8e4866cdc7d5f1d9339b773c33d23b04` ("harden: apply security
review (8 major + minors) + age-encrypted key support"), branch `main`, clean
worktree, single worktree. Prior review: `docs/REVIEW-reusability-api.md`
(33 findings, target `bacfdf0` + uncommitted tree).

This is a re-review, not a first pass. Every one of the 33 prior findings was
re-checked against this commit; 7 are verified fixed, 4 are partial, 22 remain
open. New findings are marked NEW. All line numbers below refer to `61cc651`.

## Build identity (verified vs unverified)

- Commit: `61cc651e8e4866cdc7d5f1d9339b773c33d23b04` (verified, `git rev-parse HEAD`).
- Branch/worktree: `main`, clean, one worktree (verified).
- Interpreter used: CPython 3.14.10 in `/.venv` (verified).
- Dependency metadata: `ed25519-orlp 0.1.3` installed; its METADATA says
  `Requires-Python: >=3.9` and its wheel is platform-specific
  (`py3-none-macosx_26_0_arm64`, a C extension). The review brief's premise
  that 0.1.3 requires `>=3.10` is **not supported by the installed artifact**.
- Artifact fingerprint: **unverified**. `pip wheel`/`pip download` could not
  complete (network-bound; two 120 s timeouts). Local `build/lib/meshfan/`
  differs from source for 7 of 8 modules, and `meshfan.egg-info/PKG-INFO`
  lists only `paho-mqtt` of the three declared deps. Treat both as stale
  build residue, not as build identity. `build/`, `*.egg-info/` and `.venv/`
  are gitignored and untracked.
- Segment/junction counts: N/A (not a graph-segment project).

## Verification performed (executable, not just reading)

1. `import meshfan.jwt` in the venv: pulls stdlib only (`threading` via the
   interpreter); no `paho`, no `yaml`. Confirms the JWT module is standalone.
2. `from meshfan import sign_jwt` and `from meshfan import Config` →
   `ImportError`; `meshfan.__all__` is `None`.
3. `inspect.signature(sign_jwt)` → all six parameters are positional-or-keyword;
   no `*`.
4. `sign_jwt(b"\x01"*32, b"\x02"*64, ...)` succeeds (no length validation).
   `sign_jwt(private_key, public_key, ...)` (swapped) returns a 427-char token
   with no error.
5. Generated a real keypair with `ed25519_create_keypair`, signed with
   `sign_jwt`, and verified manually with `ed25519_verify`: True. The wire
   format is self-consistent; there is simply no `verify()` helper.
6. `repr(meshfan.jwt.Token(...))` → `<meshfan.jwt.Token object at 0x...>`.
7. `meshfan.config` import pulls `yaml`; `meshfan.key` pulls `yaml` (via
   `config`) but not `paho`; `meshfan.sink` pulls `paho`.
8. `ConfigError.__mro__` and `KeyLoadError.__mro__` both derive from
   `Exception` directly; no common base; `errors.py` does not exist.
9. `dataclasses` introspection: `Config` is not frozen and requires all eight
   sections; `SourceConfig` has a `password` field included in `repr`.
   Setting `cfg.source.password = "SUPERSECRET"` (exactly what
   `__main__._load_everything` does) makes `"SUPERSECRET" in repr(cfg)` True.
10. `main(["--check", ...])` with a real keypair and the example config exits
    0 offline (no DNS), proving prior finding 5 is fixed.
11. `main(["--check", ...])` with `port: abc` prints
    `config error: source: 'port' must be an integer`, exit 2, proving prior
    finding 4 is fixed.
12. `main()` called from a non-main thread raises
    `ValueError: signal only works in main thread` (after logging is already
    reconfigured).
13. `main()` sets `RLIMIT_CORE` from `(0, unlimited)` to `(0, 0)` — the hard
    limit is irreversibly zeroed for the hosting process.
14. `config.load("config/meshfan.example.yaml")` returns one warning (file mode
    0644) and a non-deterministic `client_id` derived from hostname + pid.

## Data flow and stages (where the public boundary should be)

```
config.load(path) -> Config
  -> key.load_private_key / load_public_key / verify_keypair
  -> tls.build_ssl_context (source + per broker)
  -> Sink(broker, keys, TokenConfig, ReconnectConfig, RuntimeConfig, DebugConfig, ctx)
       _ensure_token -> jwt.sign_jwt -> Token(value, exp)
       _make_client -> paho.Client(websockets) -> connect/loop_start
  -> Fanout(sinks, DebugConfig).dispatch(topic, payload, qos)
  -> Source(SourceConfig, fanout.dispatch, ctx).start()
  -> signal handlers + stop Event (all in __main__)
```

Stages: (1) parse/validate config; (2) load/verify key material; (3) build TLS;
(4) construct sinks/fanout/source; (5) run + signal lifecycle. Only stage 1 has
a library entry point (`config.load`); stages 2-5 are private functions in the
CLI module. `jwt.sign_jwt` is a separate, acyclic leaf that does not depend on
stages 1-5.

## What the public surface actually is today

- `meshfan.__init__`: `__version__` only. No `__all__`, no re-exports.
- `meshfan.jwt`: `sign_jwt`, `Token` (no `verify`).
- `meshfan.config`: `load`, `Config`, `ConfigError`, plus eight section
  dataclasses and four `DEFAULT_*` constants.
- `meshfan.key`: `KeyLoadError`, `load_private_key`, `load_public_key`,
  `load_secret`, `verify_keypair`, `encrypt_key_file`, `KEYPAIR_PROBE`.
- `meshfan.log`: `sanitize`, `setup_logging`, `file_handler`,
  `validate_file_path`, `warn`.
- `meshfan.tls`: `build_ssl_context`.
- `meshfan.sink` / `source` / `fanout`: classes plus paho import side effects.
- `meshfan.__main__`: `main`, argparse, and the whole daemon.

## Findings

### Major

1. **MAJOR | `meshfan/__init__.py:10`** — No public API surface. The package
   exports only `__version__`; there is no `__all__`, no aliasing, no
   re-export. Verified `from meshfan import sign_jwt` and
   `from meshfan import Config` both raise `ImportError`. A consumer must know
   the internal module layout, which freezes that layout as de-facto API.
   **Fix:** re-export the supported surface and declare `__all__`:
   `sign_jwt`, `verify`, `Token`, `load_config` (alias of `config.load`),
   `loads`, `from_dict`, `Config`, `ConfigError`, `KeyLoadError`,
   `MeshfanError`, `__version__`. Keep everything else private.
   *Prior #3 — still open.*

2. **MAJOR | `meshfan/config.py:29`, `meshfan/key.py:35`, `meshfan/sink.py:56-63`,
   `meshfan/source.py:23-26`, `meshfan/log.py:36`** — No exception hierarchy and
   no normalized boundary errors. `ConfigError` and `KeyLoadError` derive from
   `Exception` directly (verified `__mro__`); `errors.py` does not exist.
   The constructors raise bare `ValueError`, `file_handler` raises `OSError`,
   and importing `meshfan.config` without PyYAML raises `ModuleNotFoundError`.
   A library caller cannot write one `except MeshfanError`.
   **Fix:** add `meshfan/errors.py` with `class MeshfanError(Exception)`;
   derive `ConfigError` and `KeyLoadError` from it; convert the TLS-mismatch
   `ValueError`s to `ConfigError`; wrap the YAML import failure in a
   `MeshfanError` subclass (or make YAML optional). *Prior #7 — still open,
   extended with the non-hierarchy raises.*

3. **MAJOR | `meshfan/__main__.py:221-325`** — The entire daemon assembly and
   lifecycle (key loading, TLS contexts, Sink/Fanout/Source wiring, signal
   handlers, stop event) lives in the CLI module. There is no library-level
   `run()`/`App`, so an embedder must copy `_cmd_run`, and `main()` cannot be
   called from a worker thread: verified
   `ValueError: signal only works in main thread` after `setup_logging` has
   already mutated global logging. There is no way to run two relays in one
   process. **Fix:** extract `meshfan/app.py` with
   `class MeshfanApp: start()/stop()/run_forever()` or `run(cfg, *, install_signal_handlers=False)`;
   leave `__main__`/`cli.py` as argparse + exit codes. *Prior #2 — still open.*

4. **MAJOR (NEW) | `meshfan/__main__.py:91-104, 316-319`** — `main()` has
   irreversible process-global side effects, so even `main(["--check", ...])`
   is unsafe to call from a host program. `_disable_core_dumps()` runs before
   argument parsing and sets **both** `RLIMIT_CORE` soft and hard to 0
   (verified: `(0, unlimited)` → `(0, 0)`; a hard limit cannot be raised back
   without privileges). `_cmd_run` also reconfigures the global `meshfan` and
   `paho` loggers. This is not just finding 3's thread problem; it is a
   one-way process mutation. **Fix:** move `_disable_core_dumps`,
   `setup_logging`, and `signal.signal` into `cli.main()` only; make
   `run(cfg)`/`MeshfanApp` free of process-global state and accept a
   `stop_event`/`logger`. *NEW.*

5. **MAJOR (NEW) | `meshfan/config.py:213-214`; `meshfan/__main__.py:123-128`** —
   The config object holds the resolved source password and is a plain
   (non-frozen, repr-enabled) dataclass. `_load_everything` writes
   `cfg.source.password = load_secret(...)`, so the long-lived config now
   contains a live secret; verified `"SUPERSECRET" in repr(cfg)` is True.
   Any embedder that logs `cfg`, includes it in an exception, or dumps it in a
   crash report leaks the password, contradicting SPEC.md's "no secret
   logging". It also mutates the caller's config, so the same `Config` object
   changes meaning across calls. **Fix:** stop mutating `Config`. Return a
   separate `ResolvedSecrets(source_password, private_key, public_key)` from a
   `prepare(cfg)` function; keep `Config` frozen and mark any residual secret
   field `field(repr=False)`. *NEW.*

6. **MAJOR | `meshfan/sink.py:117-131`, `meshfan/source.py:31-43`** — No
   client-factory seam. `_make_client` hardcodes `mqtt.Client(...)` in both
   classes, so Sink/Source cannot be constructed against a fake without
   monkeypatching `paho.mqtt.client.Client`. This directly contradicts
   docs/RESEARCH.md §5, which adopts "ABC boundaries for testability
   (AuthProvider, BrokerClient). Inject fakes in tests"; the package contains
   zero `Protocol`/`ABC`/factory (grep verified). **Fix:** define a small
   `MqttClient` Protocol (`connect`, `loop_start`, `loop_stop`, `disconnect`,
   `publish`, `username_pw_set`, `tls_set_context`, `ws_set_options`,
   `max_queued_messages_set`, callback attributes) and accept
   `client_factory: Callable[[], MqttClient]` in `Sink.__init__` and
   `Source.__init__`, defaulting to the paho factory. *Prior #1 — still open.*

7. **MAJOR (NEW) | `meshfan/sink.py:80, 88, 114, 182`** — Even with a fake
   client, the core scheduling logic is not deterministically testable:
   `_ensure_token` calls `time.time()`, `_renew_at` uses `time.monotonic()`,
   `_last_summary` uses `time.monotonic()`, and `_backoff` calls
   `random.uniform`. Tests of renewal-before-expiry and backoff bounds must
   sleep or monkeypatch three stdlib modules. **Fix:** inject
   `wall_clock: Callable[[], int] = lambda: int(time.time())`,
   `mono_clock: Callable[[], float] = time.monotonic`, and
   `rng: random.Random = random.Random()` into `Sink.__init__` (store them);
   then a fake clock can drive `_serve`/`_ensure_token` without sleeping.
   *NEW (extends prior #1's testability gap beyond client creation).*

8. **MAJOR | `meshfan/config.py:643, 676`** — Config entry point is file-only.
   `load(path)` is the sole public loader and `_build(raw)` is private, so an
   embedder whose config comes from env vars, Vault, or a k8s Secret must write
   a temp file and re-run file-mode checks. `load` is also an ambiguous public
   name (load what?). **Fix:** add `loads(text: str) -> Config` (YAML string,
   same validation) and `from_dict(raw: Mapping[str, Any]) -> Config` (rename
   `_build`), keep `load(path)` as the file wrapper that adds the mode warning,
   and export `load_config` as the documented alias. *Prior #9 — still open.*

9. **MAJOR | `meshfan/config.py:199-300`** — `Config` and its sections are
   mutable, have no defaults, and enforce their invariants only inside `_build`.
   A library embedder who constructs `Config(source=..., key=..., ...)`
   directly bypasses every range/security check (e.g.
   `TokenConfig(ttl_seconds=0)`, `TlsConfig(enabled=False)` with no
   `plaintext=True`) and produces a config the daemon will misbehave on.
   `warnings` is an out-parameter list carried inside the config object.
   **Fix:** make the section dataclasses `frozen=True`; add a validated
   constructor path (`from_dict`/`__post_init__`) so direct construction is
   also checked; give optional sections defaults; return warnings separately
   (`(cfg, warnings)` from `load`, or log them) instead of storing them on
   `Config`. *Prior #32 (mutable/no defaults) plus NEW (constructor bypasses
   validation; warnings out-param).*

10. **MAJOR | `pyproject.toml:38-42`; `meshfan/key.py:25`; `meshfan/config.py:26`**
    — Dependencies are not split. `paho-mqtt`, `ed25519-orlp`, and `PyYAML` are
    all hard runtime deps, so a JWT-only embedder installs a network client and
    a YAML parser it never uses. Worse, the obvious `meshfan.key.load_public_key`
    helper lives in a module that imports `config`, which imports `yaml`
    (verified: `import meshfan.key` pulls `yaml`), so even "just parse the
    public key" pulls PyYAML. **Fix:** core = `ed25519-orlp` only; extras
    `[daemon] = paho-mqtt` and `[config] = PyYAML`; make `config.py` import
    YAML lazily inside `load`/`loads`; move pure `parse_private_key` /
    `parse_public_key` (hex validation + decode) into a YAML-free module (or
    `jwt.py`) and let `key.py` keep only the I/O wrappers. *Prior #8 — still
    open, extended with the `key → config → yaml` coupling.*

11. **MAJOR | `pyproject.toml:70-71`** — Zero tests. `testpaths = ["tests"]`
    points at a directory that does not exist. There is no JWT known-answer
    test, no config-validation table, no key-loading test, no fake-client Sink
    test. For a package whose value is a byte-exact non-standard wire format,
    this is the largest evidence gap. **Fix:** create `tests/` with at minimum:
    (a) known-answer `sign_jwt` with a fixed seed/keypair, asserting exact
    header/payload bytes and `ed25519_verify`; (b) one test per `ConfigError`
    branch; (c) key env/file/empty/malformed/wrong-owner tests; (d) Sink
    renewal/backoff with the injected clocks + fake client; (e) Fanout with
    fake sinks; (f) `--check` exit-code test. *Prior #6 — still open.*

12. **MAJOR | `pyproject.toml:9`** — `readme = "README.md"` but README.md does
    not exist (verified: absent from the tree and from `SOURCES.txt`). The
    generated `PKG-INFO` has no long description. A second user, including the
    rflab operator, has no install, config walkthrough, "point it at rflab"
    section, or "use the signer without the daemon" snippet. **Fix:** write
    README.md with install (`pip install meshfan[daemon]`), a minimal config,
    the `key encrypt` flow, the standalone signer snippet, and links to
    `docs/`. *Prior #12 — still open.*

13. **MAJOR (NEW) | `meshfan/__main__.py:51-55`; `pyproject.toml:59-61`** — A
    pip-installed meshfan is not runnable out of the box. The default config
    path is CWD-relative (`config/meshfan.yaml`), no config file is shipped in
    the wheel (`SOURCES.txt` contains no `config/` or `docs/`), and there is no
    `--init-config`. `meshfan` with no arguments fails with "config file not
    found" in every directory that is not a source checkout; the `jwt.py`
    docstring also points at `docs/JWT.md`, which the wheel does not contain.
    **Fix:** ship `meshfan/config/meshfan.example.yaml` (and optionally
    `docs/JWT.md`) as package data via
    `[tool.setuptools.package-data]`; add `meshfan --init-config PATH` that
    writes the packaged example with mode 0600; keep the CWD default only as a
    developer convenience and document it. *NEW.*

14. **MAJOR | `meshfan/jwt.py:45-85`** — `sign_jwt` performs no argument
    validation: 32-byte public / 64-byte private lengths are not checked,
    `ttl_seconds` can be zero/negative, and `audience`/`client` can be empty.
    All six parameters are positional-or-keyword, so
    `sign_jwt(private_key, public_key, ...)` silently returns a well-formed
    427-char token that no broker will accept (verified). Given the MeshCore
    expanded-key gotcha documented in RESEARCH.md and the fact that the failure
    is silent rather than an exception, I rate this above the prior review's
    minor. **Fix:** make the key arguments keyword-only
    (`def sign_jwt(*, public_key, private_key, audience, client, ...)`), then
    raise `ValueError` naming the expected format:
    `len(public_key) == 32`, `len(private_key) == 64`, `ttl_seconds > 0`,
    non-empty `audience`/`client`. *Prior #14 — still open; severity raised
    from minor to major.*

15. **MAJOR | `meshfan/jwt.py` (absent)** — No `verify(token, public_key) -> bool`
    helper. I verified the signature round-trip manually with
    `ed25519_orlp.ed25519_verify`, so the primitive exists; an embedder must
    re-implement the split, base64url decode, and hex decode to self-check a
    token, and the planned known-answer test has nothing to call. **Fix:** add
    `verify(token: str, public_key: bytes) -> bool` (and perhaps
    `decode(token) -> tuple[dict, dict]`) using `ed25519_verify`; raise
    `ValueError` on structural malformation, return False on bad signature.
    *Prior #15 — still open.*

16. **MAJOR (NEW) | `meshfan/key.py:44-56, 205-223`** — `_read_env` pops the
    variable from `os.environ`, so `load_private_key(cfg)` and
    `load_secret(...)` are non-idempotent: a second call in the same process
    raises "environment variable X is not set". This is correct for a
    one-shot daemon but wrong for a library (a host that reloads config,
    retries startup, or runs two relays in one process fails on the second
    call), and it makes tests mutate global `os.environ`. **Fix:** add
    `env: Mapping[str, str] = os.environ` and `consume: bool = True`
    parameters; default keeps today's daemon behavior, embedders pass a dict
    and `consume=False`. Keep the pop in the CLI layer, not the loader.
    *NEW.*

17. **MAJOR | `meshfan/log.py:67-106`** — `setup_logging` remains
    library-hostile: it removes and closes **all** handlers on the `meshfan`
    logger (an embedding app's handlers get wiped), unconditionally re-levels
    and re-handlers the third-party `paho` logger, and uses
    `getattr(logging, cfg.level, logging.INFO)`, which silently downgrades a
    typo to INFO for a directly constructed `LoggingConfig`. Config validation
    now rejects bad levels coming through `config.load` (prior part fixed), but
    the global mutation is unchanged. **Fix:** `setup_logging(cfg, debug, *,
    logger_name="meshfan", manage_paho=False)`; track and close only handlers
    this function created; make paho management opt-in; raise `ConfigError` on
    an unknown level. *Prior #13 — partial (level validation fixed; handler
    clearing and paho global still open).*

### Minor

18. **MINOR | `meshfan/jwt.py:1, 45`; `meshfan/config.py:676`;
    `meshfan/key.py:39`; `meshfan/fanout.py:16-17`** — Naming batch:
    module `jwt` + `sign_jwt` invite PyJWT confusion (the token is deliberately
    non-standard: alg `Ed25519`, hex signature); `config.load` is ambiguous as
    a public name; `_clean` is vague; `Fanout.delivered` overpromises (it counts
    client-accepted publishes, not broker-acked deliveries). **Fix:** keep the
    wire format, add `sign_device_token = sign_jwt` and a "not PyJWT-compatible"
    note in README; export `load_config`; rename `_clean` to
    `_strip_hex_whitespace`; rename `delivered` to `accepted`. *Prior #16, #20,
    #22 — still open.*

19. **MINOR | `meshfan/jwt.py:31-42`** — `Token` is mutable, has
    `__slots__` but no `__repr__`/`__eq__`/`__hash__`, and carries no `iat`.
    Verified `repr()` is `<meshfan.jwt.Token object at ...>`. **Fix:** make it a
    frozen `@dataclass(slots=True)` on 3.10+ (or keep `__slots__` with explicit
    `__repr__`/`__eq__` for 3.9) and add `iat` so renewal math does not need to
    re-derive it. *Prior #17 — still open.*

20. **MINOR | `meshfan/config.py:190-193, 217`; `config/meshfan.example.yaml:62`** —
    `Config` values are not deterministic: `_default_client_id()` reads
    `socket.gethostname()` and `os.getpid()`, so two loads of the same file
    differ and reproducibility tests cannot compare configs. Separately, the
    example still gives every broker `client: meshfan`, and `client` is
    required per broker even though docs/JWT.md calls the claim optional, so
    two deployments on the same broker kick each other. **Fix:** make the
    default an explicit documented value or derive it in `run`, not in a
    dataclass factory; default `client` to `meshfan-<broker.name>`, make it
    optional, and warn on duplicates across configs only where detectable.
    *Prior #27 — partial (source client_id default fixed; broker client still
    open), plus NEW determinism note.*

21. **MINOR | `meshfan/fanout.py:13, 24-29`; `meshfan/source.py:20`; `meshfan/sink.py:348-353, 128`** —
    Observability/typing batch: `sinks: list` is unparameterized (the only
    contract is `publish(topic, payload, qos) -> bool`, which should be a
    `SinkLike` Protocol); `on_message` and the paho callbacks are unannotated;
    `Fanout.dropped` double-counts a drop that `Sink.publish` already counted;
    `max_queued_messages_set` is mostly inert because `publish()` refuses to
    call paho while not connected, so the queue-vs-drop policy is undocumented.
    **Fix:** add `SinkLike` and `Callable[[str, bytes, int], None]`; either
    drop the fanout counters or derive them from sinks; document (and test) the
    chosen queue-vs-drop behavior. *Prior #21, #22, #26 — still open.*

22. **MINOR | `pyproject.toml:7; meshfan/__init__.py:10`** — Version is
    duplicated (`0.1.0` in two places) and will drift. **Fix:**
    `dynamic = ["version"]` with
    `[tool.setuptools.dynamic] version = {attr = "meshfan.__version__"}`.
    *Prior #28 — still open.*

23. **MINOR | `pyproject.toml:11, 24-36, 55-57`** — `license = { text = "MIT" }`
    is the deprecated TOML-table form; the `License ::` classifier is also
    deprecated; `Homepage`/`Documentation`/`Changelog` point at
    `github.com/USER/meshfan` and a nonexistent CHANGELOG.md. **Fix:** use the
    SPDX string `license = "MIT"`, drop the classifier, set real URLs or remove
    them, and add CHANGELOG.md or remove that URL. *Prior #29 — still open.*

24. **MINOR | `pyproject.toml:59-61`; `meshfan/`** — No `meshfan/py.typed`
    marker, so downstream type checkers ignore every annotation despite the
    package being fully annotated. **Fix:** add an empty `meshfan/py.typed` and
    `[tool.setuptools.package-data] meshfan = ["py.typed"]`. *Prior #30 — still
    open.*

25. **MINOR | `pyproject.toml:52`; `meshfan/__main__.py:316-329`** — The console
    entry point targets `meshfan.__main__:main`, making the `__main__` module
    de-facto public and duplicating the `SystemExit` guard. **Fix:** move
    `main` to `meshfan/cli.py`, point the script there, and leave
    `__main__.py` a two-line shim (`from .cli import main; raise
    SystemExit(main())`). *Prior #31 — still open.*

26. **MINOR (NEW/correction) | `pyproject.toml:10, 30-33`** — The review brief's
    premise does not hold: installed `ed25519-orlp 0.1.3` metadata says
    `Requires-Python: >=3.9`, so `requires-python = ">=3.9"` is not wrong on
    that basis, and the code is 3.9-syntax-compatible (all `X | None` uses are
    under `from __future__ import annotations`). The real gaps are that 3.9 is
    untested (no CI, only 3.14 was exercised), and classifiers stop at 3.12
    while the verified interpreter is 3.14. **Fix:** either add a 3.9/3.10 CI
    matrix and keep the claim, or raise `requires-python` to the oldest
    version you actually test; add 3.13/3.14 classifiers. *NEW.*

27. **MINOR (NEW) | `meshfan/__main__.py:67-88`** — There is no CLI path for the
    two most common second-user tasks: signing a token for a broker by hand
    (`meshfan jwt sign --aud ... --client ...`) and generating a MeshCore
    keypair (`meshfan key generate`, using the already-present
    `ed25519_create_keypair`). Today both require writing Python, which makes
    rflab onboarding and wire-format debugging harder than necessary.
    **Fix:** add `meshfan jwt sign` (prints the token and `exp`; never logs the
    key) and `meshfan key generate --out` (mode 0600). *NEW.*

28. **MINOR | `meshfan/log.py:33-52, 69`; `meshfan/jwt.py:10`** — Residual
    polish: a directly constructed `LoggingConfig(output="file",
    file_path=None)` now raises `OSError` (not `ConfigError`) from
    `file_handler`; `getattr(logging, cfg.level, logging.INFO)` silently
    downgrades; and the `jwt.py` docstring's "See docs/JWT.md" dangles for
    wheel users because docs are not shipped. **Fix:** raise `ConfigError`
    from `file_handler`; validate levels at construction; point the docstring
    at a URL or ship the doc (see finding 13). *Prior #33 (partial) and #18
    (open).*

## Prior findings verified fixed (so they are not re-opened)

- **#4** — `_int`/`_float` helpers raise `ConfigError`; `load` catches
  `OSError`/`UnicodeDecodeError`. Verified: `port: abc` → `config error: ...`,
  exit 2.
- **#5** — DNS resolution removed; `_host` is syntax-only (`inet_pton` for
  IPv6). Verified: `--check` completes offline against the example host.
- **#10** — Every section calls `_unknown`; `debug` is a typed `DebugConfig`
  including `paho`. Unknown keys now raise.
- **#11** — `key._check_file_security` enforces owner, regular-file, no-symlink,
  and `mode & 0o077 == 0`; the docstring claim is now true.
- **#19** — `_read_env` distinguishes "not set" from "empty".
- **#24** — Sink now calls `loop_start()` in `_connect_and_serve`, so the
  `loop_stop()` in teardown is correct rather than dead code.
- **#25** — `_serve` checks `_stop` before waiting and `_connect_and_serve`
  disconnects in `finally`, so a SIGTERM during connect no longer leaks a
  `loop_forever` connection.
- **#13 (partial)** — config now validates `logging.level`; the remaining
  handler-clearing/paho mutation is finding 17.
- **#23 (partial)** — the per-sink guard now logs at DEBUG; still invisible at
  default level.
- **#27 (partial)** — source `client_id` now defaults to
  `meshfan-<hostname>-<pid>`; broker `client` is still required.
- **#33 (partial)** — `file_handler` guards a missing `file_path` with `OSError`
  instead of reaching `FileHandler(None)`; not yet a `ConfigError`.

## Clean notes (no finding)

- `meshfan/jwt.py` imports only stdlib + `ed25519_orlp`; `import meshfan.jwt`
  does not pull paho, yaml, socket, or ssl (verified). `sign_jwt` is a pure
  function with injectable `now` and no hidden globals; the produced bytes are
  self-consistent (verified round-trip with a real keypair). The structural
  design is right; findings 14-15 are hardening.
- `meshfan/tls.py:14-38` is clean: no network, injectable inputs, raises
  `ConfigError`, and sets `check_hostname` before `verify_mode` (the correct
  order for `insecure`).
- `meshfan/fanout.py` is network-free and fake-injectable by duck typing; the
  per-sink guard is correct (findings 18/21 are typing/observability only).
- `meshfan/config.py`'s `_unknown`/`_bool`/range checks are strict and
  well-messaged; the file/daemon boundary is genuinely clean on the read side.
- `meshfan/key.py`'s file-security and age-passphrase handling is careful
  (0600 temp dir+file, no argv secret, stderr redaction, fsync+0600 output).

## Alternatives considered

- **Keep one `meshfan` package and add extras** (recommended) vs. split
  `meshfan-jwt` into a second distribution. The split gives the strongest
  dependency guarantee but doubles release/versioning overhead for a 2 kLOC
  project; lazy YAML + extras achieves the same install footprint with one
  artifact.
- **Freeze dataclasses and move secrets out** vs. `field(repr=False)` only.
  Freezing is the cleaner API but breaks the current `_load_everything`
  mutation; a `ResolvedSecrets` value object is the migration.
- **Client Protocol + factory** vs. subclass-and-override `_make_client`.
  The Protocol is testable without inheritance and matches RESEARCH §5;
  subclassing keeps paho types in the public signature.
- **`loads`/`from_dict`** vs. a generic `load(source: str | TextIO | Mapping)`.
  Two explicit functions are easier to type and document than overloads.
- **Keyword-only `sign_jwt`** is a breaking change, but the package is 0.1.0
  and the silent-swap failure justifies doing it now.

## Risks

- Freezing `Config` while `__main__` mutates it will break startup unless the
  secret-resolution refactor lands in the same commit.
- Splitting deps changes the install command; existing users doing
  `pip install meshfan` would lose the daemon. Mitigate with a minor version
  bump, README migration note, and a deprecation extra (or keep a `full` extra).
- A `verify()` helper that parses untrusted tokens must bound input size and
  avoid `json.loads` on attacker-sized strings; return False/raise a
  `MeshfanError` rather than leaking parser exceptions.
- Shipping the example config as package data must not ship a real config;
  keep the `!config/meshfan.example.yaml` gitignore exception and assert in a
  test that only placeholders are present.
- Raising `requires-python` drops 3.9 users; keeping it without CI risks
  shipping broken 3.9 support. Prefer CI over a guess.

## Tests / acceptance gates

1. `python -c "from meshfan import sign_jwt, verify, Token, Config, ConfigError, MeshfanError"` exits 0.
2. In a venv with only `ed25519-orlp` installed, `import meshfan.jwt` and
   `sign_jwt(...)` succeed (no paho/yaml).
3. `sign_jwt` raises `ValueError` for a 32-byte private key, a 64-byte public
   key, `ttl_seconds <= 0`, and empty `aud`/`client`; the swapped-key call is
   no longer possible positionally.
4. `verify(sign_jwt(...).value, public_key)` is True; wrong key is False;
   malformed token raises `MeshfanError`.
5. `loads(text)` and `from_dict(raw)` return a `Config` equal to `load(path)`
   for the same input; unknown keys still raise `ConfigError`.
6. `cfg.source.password = ...` raises `FrozenInstanceError`; `repr(cfg)` never
   contains a resolved secret.
7. `main()` in a worker thread either works or is not the supported entry;
   `run(cfg)` can start/stop twice in one process and leaves `RLIMIT_CORE`
   untouched.
8. Wheel contains `meshfan/py.typed`, the example config, and a README long
   description; `pip install meshfan[daemon]` then `meshfan --init-config` and
   `meshfan --check` succeed outside the repo.
9. `pip install meshfan` installs only `ed25519-orlp`;
   `pip install meshfan[daemon]` adds paho; `[config]` adds PyYAML.
10. `pytest` passes in a network-isolated environment; the JWT known-answer
    test is byte-exact.

## Migration and rollback

- **Errors:** adding `MeshfanError` and re-parenting is backward compatible
  (`except Exception` still catches). Rollback: revert `errors.py` and the two
  base classes.
- **Frozen config + secret resolution:** introduce `ResolvedSecrets` and change
  `_load_everything` to return it; keep `cfg.source.password` as a deprecated
  read-only field for one release or remove it in 0.2. Rollback: restore the
  mutable dataclass and the assignment; no on-disk state to migrate.
- **Deps split:** `meshfan[daemon]` becomes the documented install; keep a
  `full` extra alias during the transition. Rollback: restore the flat
  `dependencies` list and bump the patch version.
- **`main` → `cli.main`:** keep `meshfan.__main__:main` as a shim so the
  console script and any caller keep working. Rollback: point the script back.
- **Package data:** adding files to the wheel is additive; rollback removes the
  `package-data` entry.
- No database, no state directory, no persisted tokens: all rollbacks are
  code-only.

## Decisions needed

1. Is the JWT signer a semver-stable public API, or an internal detail with a
   convenience export? This decides whether `sign_jwt`/`Token`/`verify` get
   keyword-only signatures now and a stability promise.
2. Is Python 3.9 supported? If yes, add CI; if no, raise `requires-python` and
   drop the classifier.
3. Do we accept a breaking install-command change to `meshfan[daemon]` at 0.1.0,
   or keep the fat install until 0.2?
4. Do we freeze `Config` now (requires the `ResolvedSecrets` refactor) or only
   add `repr=False` as a stopgap?
5. Is the shipped config example expected to be editable in place, or should
   `--init-config` be the only supported path?

## Efficiency / process review

- **Observed discovery overhead.** 14 files / ~2,130 LOC of Python plus
  `pyproject.toml`, the example YAML, SPEC, JWT.md, RESEARCH §5, and the prior
  review. The whole tree had to be re-read because the prior review's line
  numbers target an uncommitted `bacfdf0` tree and the hardening commit moved
  or rewrote 7 of 8 modules. That is unavoidable for a re-review, but it is
  avoidable *next* time.
- **Duplicated measurement.** 33/33 prior findings re-checked: 11 confirmed by
  execution (imports, signature, token swap, repr leak, CLI exit codes,
  offline `--check`, thread `ValueError`, RLIMIT, module pull-in, keypair
  round-trip, frozen/introspection), 22 by source diff. Two `pip` network
  probes (wheel/download) each burned the full 120 s timeout and produced
  nothing; local `METADATA`/`WHEEL`/`SOURCES.txt` inspection answered the same
  question in under a second. That is ~240 s of pure waste.
- **Rework.** The previous review's "7 concurrent fixes" were re-derived from
  scratch; this time the hardening commit fixed 7 prior findings outright and
  4 partially, so a disposition checklist would have cut the diff work roughly
  in half. Finding 14 was re-graded (minor → major) because the silent-swap
  behavior is worse than the prior review assumed; that is a judgment change,
  not duplicated work.
- **Safe faster method.** (a) Pin the commit before dispatch (done here).
  (b) Require the hardening commit message or `docs/` to carry a
  `prior-finding disposition` table: `# | status | file:line | note`.
  (c) Re-review only the delta plus the public boundary, not every internal
  line. (d) Never use network `pip` probes in an offline review; read
  `.dist-info/METADATA` and `WHEEL`. (e) Ignore `build/lib` and `*.egg-info`
  as identity sources; they are stale here (7/8 modules differ; PKG-INFO lists
  1 of 3 deps).
- **Write-back numbers.** Prior: 33 findings (13 major, 20 minor). Now:
  7 fixed, 4 partial, 22 open; new: 9 major/minor findings (5 major, 4 minor)
  plus one grading correction and one brief-premise correction. The report is
  durable at `docs/REVIEW-reusability-api-61cc651.md`; the next reviewer should
  start from its disposition table rather than re-reading the tree.

## Next safe action

Commit A (no behavior change, highest value): add `meshfan/errors.py` with
`MeshfanError`; re-parent `ConfigError`/`KeyLoadError`; add `__all__` and
re-exports in `__init__.py`; add `meshfan/py.typed`; make the `yaml` import
lazy; add `loads`/`from_dict` as thin wrappers over the existing `_build`.
Gate it with acceptance test 1, 3, 5 and 8. Then commit B (test seam):
`MqttClient` Protocol + `client_factory` + injected clocks, with the first
fake-client Sink test; then commit C (packaging): extras split, README,
packaged example config, version single-source. Do not freeze `Config` until
the `ResolvedSecrets` refactor is ready, or the daemon will not start.

## Overall verdict

The internals are better than the public surface. `jwt.sign_jwt` is genuinely
standalone (stdlib + ed25519 only, pure, clock-injectable) and the hardening
pass fixed the worst config/key failure modes: unknown keys are rejected, bad
numbers raise `ConfigError`, key files are owner/mode checked, DNS is out of
`--check`, and the sink reconnect path is no longer leaky. What still keeps
this from being a publishable library is almost entirely surface and evidence:
no `__all__` or re-exports, no `MeshfanError`, no `App`/`run`, a CLI module
that irreversibly zeroes the host's core-dump limit and wipes logger handlers,
a config object that stores and `repr`s the resolved password, a file-only
loader, no client-factory/clock seam, unsplit dependencies with a
`key → config → yaml` edge, and zero tests for a byte-exact wire format. The
good news is that these are bounded and mechanical: the prior review's
"major" set is now 7 fixed and 4 partial, and the remaining work is additive
API plus one secret-handling refactor. A second user pointing at rflab would
today struggle most with the missing README/example config and the required
per-broker `client`/`audience` values, not with the signing code.

## Top 5 highest-value fixes

1. Public surface: `errors.py` + `MeshfanError`, `__all__`, re-exports,
   `py.typed`, lazy YAML, `loads`/`from_dict` (findings 1, 2, 8, 24).
2. Secret handling: stop mutating `Config`; introduce `ResolvedSecrets` and
   freeze the config, with `repr=False` as the immediate stopgap (finding 5).
3. Test seam: `MqttClient` Protocol + `client_factory` + injected
   wall/monotonic clocks and RNG, then the JWT known-answer test (findings 6,
   7, 11).
4. Embeddable lifecycle: `meshfan/app.py` `MeshfanApp`/`run(cfg)` with no
   signal/RLIMIT/logging globals; `main()` becomes CLI-only (findings 3, 4, 17).
5. Packaging for the second user: split `[daemon]`/`[config]` extras, README,
   packaged example config + `--init-config`, single-source version
   (findings 10, 12, 13, 22).
