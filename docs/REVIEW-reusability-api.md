# meshfan peer review: reusability and API design

Reviewer: architecture peer-review subagent. Date: 2026-11-06.
Target state: working tree on `main` at commit `bacfdf0` (scaffold + docs); all
implementation files are uncommitted. **The tree was edited concurrently during
this review** — `config.py`, `sink.py`, `source.py`, `fanout.py` changed between
the first and second read — so every line number below refers to the second
(read-final) pass. Seven issues that this review had initially drafted were
fixed concurrently before finalization (fanout per-sink isolation, sink publish
race, sink stop disconnect-first, source stop ordering, `RuntimeConfig` +
`source.client_id`/`keepalive` wiring, jitter validation, backoff exponent cap);
they are not repeated here.

Verification performed (not just static reading):

- setuptools metadata build against this `pyproject.toml` with `README.md`
  absent: emits `SetuptoolsWarning: File 'README.md' cannot be found`, build
  does NOT fail, long description falls back to `description` — so this is a
  PyPI-rendering/UX defect, not an install blocker.
- setuptools also warns: `project.license` TOML table deprecated (must change
  by 2027-02-18) and `License ::` classifier deprecated.
- paho-mqtt 2.x source inspected: `Client.loop_stop()` returns
  `MQTT_ERR_INVAL` immediately when no `loop_start()` thread exists; it joins
  the network thread otherwise. `Client.disconnect()` with `_sock is None`
  just sets state and returns `MQTT_ERR_NO_CONN`.
- `pip install .` in a clean venv: succeeds (wheel `meshfan-0.1.0-py3-none-any.whl`
  built, all deps resolved incl. `ed25519_orlp-0.1.3` py3-none arm64 wheel —
  no C build needed on this platform); installed entry point `meshfan
  --version` works.
- Live repro through the *installed* entry point: `meshfan --config
  <bad.yaml> --check` with `port: abc` prints a raw Python traceback
  (`ValueError: invalid literal for int()...`, exit 1) instead of
  `config error: ...` (exit 2). Confirms finding 4 end-to-end.

## Findings

1. MAJOR | meshfan/sink.py:86-100, meshfan/source.py:36-48 | No test seam:
   `_make_client` hardcodes `mqtt.Client(...)` in both classes. Token renewal
   (`_ensure_token`), backoff (`_backoff`), publish gating and the reconnect
   loop cannot be tested without monkeypatching `paho.mqtt.client.Client` or a
   live broker. This directly contradicts docs/RESEARCH.md:111-114, which
   adopts "ABC boundaries for testability (AuthProvider, BrokerClient). Inject
   fakes in tests" — the codebase contains zero ABCs or Protocols. | Fix: add
   a `MqttClient` Protocol (connect, loop_forever, publish, disconnect,
   loop_stop, ws_set_options, username_pw_set, tls_set_context,
   max_queued_messages_set) and a `client_factory: Callable[[], MqttClient]`
   constructor parameter defaulting to the paho factory; tests inject fakes.

2. MAJOR | meshfan/__main__.py:47-116 | The entire daemon assembly and
   lifecycle (key loading, DNS preflight, logging setup, Sink/Source/Fanout
   wiring at lines 90-95, signal handlers at 103-104, run loop) lives in the
   CLI module. There is no library-level `run()`/`App`, so an embedder must
   reimplement `main()`, and `signal.signal` (main-thread-only) makes calling
   `main()` from a thread raise `ValueError`. This is the load-config vs
   run-daemon boundary the review asked about: `config.load()` is cleanly
   separated, but "run" is not. | Fix: extract `meshfan/app.py` with
   `class MeshfanApp: start()/stop()` (or `run(cfg) -> int`); leave
   `__main__.py` as argparse + exit codes only.

3. MAJOR | meshfan/__init__.py:10 | No public API surface: the package
   exports only `__version__`; there is no `__all__`. `from meshfan import
   sign_jwt, Config, ConfigError` fails — every consumer must know submodule
   layout. | Fix: re-export the supported surface (`sign_jwt`, `Token`,
   `load_config` alias of `config.load`, `Config`, `ConfigError`,
   `KeyLoadError`, `__version__`) and declare `__all__`; keep everything else
   private.

4. MAJOR | meshfan/config.py:129,134,168-173,183-184,194-197,211-212;
   meshfan/__main__.py:50-69 | Verified live: `int()`/`float()` coercion of a
   bad YAML value raises `ValueError`, not `ConfigError`, so `main()`'s
   `except ConfigError` misses it and the user gets a raw traceback for a
   plain typo (`port: abc`). Same class of problem: `load()` (config.py:95-101)
   catches `FileNotFoundError` and `YAMLError` only — `PermissionError`,
   `IsADirectoryError`, `UnicodeDecodeError` also escape. | Fix: wrap every
   coercion in a `_int(raw, key, section)` / `_float(...)` helper that raises
   `ConfigError`; broaden `load()`'s `except` to `OSError` and
   `UnicodeDecodeError`.

5. MAJOR | meshfan/config.py:255-260; meshfan/__main__.py:37,56-62 |
   `resolve_hostname` performs live DNS (`socket.getaddrinfo`) inside the
   config module, and the CLI runs it before `--check` — despite `--check`'s
   help text "no connections" (line 37) and SPEC.md:120 ("without
   connecting"). Consequences: `--check` fails offline/in CI/pre-DNS, and the
   function is untestable without monkeypatching `socket`. "Load config" and
   "preflight network" are conflated. | Fix: move it to a `preflight` module
   (or drop it from `--check` and make it an explicit opt-in), take an
   injectable `resolver` callable, and correct the help text.

6. MAJOR | pyproject.toml:71-72 | Zero tests. `testpaths = ["tests"]` points
   at a directory that does not exist, and docs/RESEARCH.md:175-178's
   acceptance plan requires a JWT known-answer test (sign a fixed message with
   a fixed key, verify with `ed25519_verify`) that does not exist. For a
   publishable library this is the largest gap: the wire-format code
   (base64url/compact-JSON/hex-sig) is exactly the part that silently breaks.
   | Fix: create `tests/` with at least: JWT known-answer test, config
   validation table test (one per `ConfigError` branch), key-loading tests
   (env/file/malformed/empty), a fake-client `Sink` renewal test, a fake-sink
   `Fanout` test.

7. MAJOR | meshfan/config.py:16; meshfan/key.py:18 | No exception hierarchy:
   `ConfigError` and `KeyLoadError` are unrelated `Exception` subclasses, and
   there is no package-level base, so a library caller cannot write one
   `except MeshfanError`. | Fix: add `class MeshfanError(Exception)` (new
   `meshfan/errors.py` or in `__init__.py`), derive both from it, export it.

8. MAJOR | pyproject.toml:38-43 | Dependencies are not split: a user who
   only wants `meshfan.jwt.sign_jwt` (the second-user scenario in the review
   brief) must still install `paho-mqtt`, `websocket-client` and `PyYAML`.
   | Fix: core = `ed25519-orlp`; extras `[daemon] = paho-mqtt, websocket-client`
   and `[config] = PyYAML` (or make the CLI entry point depend on `[daemon]`).

9. MAJOR | meshfan/config.py:93-104,122 | Config loading is file-only:
   `load(path)` is the sole public entry and `_build(raw)` is private, so an
   embedder whose config comes from env vars, a vault, or a k8s Secret must
   write a temp file. | Fix: expose `loads(text: str) -> Config` and
   `from_dict(raw: dict) -> Config` (rename `_build`), keep `load()` as the
   file wrapper.

10. MAJOR | meshfan/config.py:122-252,235-239 | Unknown keys are silently
    ignored — no section checks its key set. A typo (`reconnnect:`,
    `source.keepalive_s`) silently falls back to defaults and `--check` still
    says OK. The `debug` map accepts literally any key while the only valid
    keys (`messages`, `tokens`) are documented nowhere in code (just
    config/meshfan.example.yaml:65-67) — `debug.mesages: true` silently does
    nothing (consumed at fanout.py:27, sink.py:68). | Fix: strict parsing —
    reject unknown keys per section with the offending path in the error; type
    `debug` as a `DebugFlags(messages: bool, tokens: bool)` dataclass.

11. MAJOR | meshfan/key.py:3-4,27-48 | The module docstring (and
    SPEC.md:102) claim the private key file is "chmod-600", but no permission
    check exists anywhere — a world-readable key file loads silently. A
    docstring that states a security property the code does not enforce is
    worse than saying nothing. | Fix: `os.stat` the file, raise `KeyLoadError`
    (or at minimum `log.warning`) when `mode & 0o077 != 0`; keep the docstring
    truthful either way.

12. MAJOR | pyproject.toml:9 | `readme = "README.md"` but README.md does not
    exist (verified: setuptools emits `SetuptoolsWarning: File 'README.md'
    cannot be found`; build succeeds with an empty long description). PyPI
    would render no description, and a second user has no install/quickstart
    at all — the "how do I point this at rflab" answer exists nowhere. |
    Fix: write README.md (install, config walkthrough, JWT-signing-only
    usage snippet, link to docs/).

13. MAJOR | meshfan/log.py:18-43 | `setup_logging` is library-hostile global
    mutation: it clears handlers on the `"meshfan"` logger (line 23 — an
    embedding app's handlers get wiped) and unconditionally relevels the
    third-party `paho` logger (lines 41-43). Also `getattr(logging, cfg.level,
    logging.INFO)` (line 20) silently downgrades a typo'd level to INFO —
    compounded by config.py:228 never validating `level` against known names.
    | Fix: give `setup_logging` a `logger_name` parameter and only touch
    handlers it created (close them before clearing); make the paho-quieting
    opt-in; validate `level` in `config._build` and raise `ConfigError` on an
    unknown name.

14. MINOR | meshfan/jwt.py:45-82 | `sign_jwt` does no length validation:
    a 32-byte seed where the 64-byte expanded key belongs, or the arguments
    swapped, reaches `ed25519_sign` unchecked — it either raises an opaque
    ctypes error or (worse) emits a signature no broker will accept, with no
    hint about the MeshCore expanded-key gotcha (docs/RESEARCH.md:65-86).
    Also `audience`/`client` are signed even when empty. | Fix: validate
    `len(public_key) == 32`, `len(private_key) == 64`, non-empty `aud`/`client`,
    raising `ValueError` with a message that names the expected key format.

15. MINOR | meshfan/jwt.py:45 | No `verify(token, public_key) -> bool`
    helper, though docs/RESEARCH.md:175-178 plans a verification round-trip
    test and embedders (the "embed the signer in another tool" user) need one
    to self-check tokens. | Fix: add `verify()` using
    `ed25519_orlp.ed25519_verify` over `HEADER.PAYLOAD` with the uppercase-hex
    signature decoded.

16. MINOR | meshfan/jwt.py:1,45 | Naming: module `jwt` + `sign_jwt` invite
    confusion with PyJWT (`import jwt` vs `meshfan.jwt`), and the produced
    token is deliberately non-standard (alg `Ed25519`, hex signature — the
    docstring at lines 1-11 is admirably honest about this). A second user
    pasting these tokens into a standard JWT library will be confused. |
    Fix: keep the wire format, but add an alias `sign_device_token = sign_jwt`
    and state "not PyJWT-compatible" in the README.

17. MINOR | meshfan/jwt.py:31-42 | `Token` is mutable, has no default
    `__repr__` (debugging prints `<meshfan.jwt.Token object>`), and `exp`
    semantics are documented only on `should_renew`. | Fix: make it a frozen
    `@dataclass(slots=True)`-style class (keep `__slots__` on 3.9) with a
    `__repr__` showing `exp`.

18. MINOR | meshfan/jwt.py:10 | "See docs/JWT.md" — docs/ are not shipped in
    the wheel (`packages.find` only includes code), so an installed user sees
    a dangling reference. | Fix: point at the URL from `project.urls`, or ship
    docs as package data.

19. MINOR | meshfan/key.py:32-35 | An env var set to the empty string
    bypasses the `raw is None` check and fails with the misleading
    "private key must be 128 hex characters" instead of "environment variable
    X is empty". | Fix: check `not raw` after retrieval and raise the specific
    message.

20. MINOR | meshfan/key.py:22-24,27-48 | `_clean` is a vague name, and there
    is no pure `parse_private_key(hex_str)` / `parse_public_key(hex_str)`:
    the validation core is fused to `os.environ`/file I/O, so a user holding
    the key in a vault must materialize env or file first. | Fix: split pure
    `parse_*` functions (validation + hex decode) from thin I/O wrappers;
    optionally accept `env: Mapping[str, str] = os.environ`.

21. MINOR | meshfan/fanout.py:10; meshfan/source.py:20 | Typing gaps in an
    otherwise fully annotated package: `sinks: list` is unparameterized (the
    only structural contract is `publish(...) -> bool`, which should be a
    named `SinkLike` Protocol), and `on_message` has no
    `Callable[[str, bytes, int], None]` annotation. paho callback signatures
    (sink.py:102,110; source.py:50,58,62) are also unannotated. | Fix: add
    the Protocol and the Callable annotation; annotate callbacks with paho's
    VERSION2 types.

22. MINOR | meshfan/fanout.py:13-14,22; meshfan/source.py:24 | Dead /
    misleading state: `Fanout.delivered` counts messages *accepted by the paho
    client*, not broker-acked deliveries — the name overpromises; both
    `delivered`/`dropped` are written but never read or logged anywhere, and
    `Source.connected` is likewise never read. | Fix: rename to
    `accepted`/`rejected` (or document), add a `Fanout.stats() -> tuple` or
    periodic stats log line, drop `Source.connected` or use it.

23. MINOR | meshfan/fanout.py:25-26 | The new per-sink guard swallows
    exceptions silently — no log line, so a persistently failing sink is
    invisible except through the never-read `dropped` counter. | Fix:
    `log.warning("%s: publish failed", ..., exc_info=True)` inside the
    `except`.

24. MINOR | meshfan/sink.py:123-129 | `_teardown_client` calls
    `client.loop_stop()`, but `Sink` never calls `loop_start()` — verified in
    paho 2.x: `loop_stop()` returns `MQTT_ERR_INVAL` immediately when
    `_thread is None`, so this is dead code wrapped in a bare
    `except Exception: pass` that would hide real errors if it ever did work.
    | Fix: delete the `loop_stop()` call (the loop already exited via
    `loop_forever()`), or document why it is there.

25. MINOR | meshfan/sink.py:136-144,174-186 | Narrow shutdown window:
    `stop()` snapshots and disconnects, but `disconnect()` on a client whose
    `_sock is None` (verified: paho just returns `MQTT_ERR_NO_CONN`) is a
    no-op, and `_run` has no stop-check between `connect()` and
    `loop_forever()`. If SIGTERM lands during the TCP/WS handshake, the sink
    thread connects, runs `loop_forever()` forever, misses the clean
    DISCONNECT, and is killed at process exit — violating SPEC.md:119
    ("Graceful shutdown ... close connections"). | Fix: after `connect()`
    succeeds, check `self._stop.is_set()` and disconnect before
    `loop_forever()`.

26. MINOR | meshfan/sink.py:97,158-172 | `max_queued_messages_set` queues
    messages, but `publish()` refuses to call paho at all while
    `not self.connected`, so during reconnects messages are dropped, not
    queued — the queue setting is mostly inert on the main path and the
    queue-vs-drop policy is undocumented. | Fix: decide (queue during
    transient reconnect with the configured cap, or drop) and document it in
    the module docstring and README.

27. MINOR | meshfan/config.py:34,172; config/meshfan.example.yaml:15,38 |
    Client-id collision hazards are now configurable but still defaulted:
    two default-config instances share source `client_id: "meshfan-source"`
    (broker kicks one), and the example gives every broker `client: meshfan`,
    so two deployments targeting the same broker with the same audience will
    kick each other. Also `client` is *required* per broker even though
    docs/JWT.md:43 says the claim is optional — a user pointing at a broker
    that ignores it must invent a value. | Fix: derive a default `client`
    (e.g. `meshfan-<broker.name>`), make it optional per the JWT contract,
    and document the collision rule.

28. MINOR | pyproject.toml:7; meshfan/__init__.py:10 | Version is duplicated
    (`0.1.0` in two places) and will drift. | Fix: single source —
    `dynamic = ["version"]` + `[tool.setuptools.dynamic]
    version = {attr = "meshfan.__version__"}`.

29. MINOR | pyproject.toml:11,27,56-58 | Packaging metadata cleanup, all
    verified or observed: `license = { text = "MIT" }` is a deprecated TOML
    table (setuptools warns; removal required by 2027-02-18 — switch to
    `license = "MIT"` SPDX string), the `License ::` classifier is likewise
    deprecated, and `Homepage`/`Documentation`/`Changelog` URLs are
    `github.com/USER/meshfan` placeholders pointing at a nonexistent
    CHANGELOG.md. | Fix: SPDX license string, drop the classifier, real URLs
    (or remove the entries until the repo exists).

30. MINOR | pyproject.toml:60-62 | Fully annotated package without a
    `meshfan/py.typed` marker, so downstream type checkers ignore all the
    hints. | Fix: add `meshfan/py.typed` and
    `[tool.setuptools.package-data] meshfan = ["py.typed"]`.

31. MINOR | pyproject.toml:53; meshfan/__main__.py:119-120 | The console
    entry point imports the `__main__` module (conventionally reserved for
    `python -m`). Works, but it makes `meshfan.__main__` a de-facto public
    module and duplicates the `SystemExit` guard. | Fix: move `main()` to
    `meshfan/cli.py`, point the script there, leave `__main__.py` a 2-line
    shim.

32. MINOR | meshfan/config.py:79-90 | Dataclasses are mutable with no
    defaults on `Config`, so test fixtures must pass all ten fields and
    callers can mutate a config mid-run. | Fix: `@dataclasses.dataclass(frozen=True)`
    on the config types (3.9-safe; skip `slots=True` which needs 3.10).

33. MINOR | meshfan/log.py:33 | `LoggingConfig(output="file")` constructed
    directly (bypassing `config.load`'s validation at config.py:232-233)
    reaches `logging.FileHandler(None)` → `TypeError`, not a meshfan error. |
    Fix: guard in `setup_logging` and raise `ConfigError`/`ValueError`.

Clean notes (no finding needed):

- `meshfan/jwt.py` module imports are clean: stdlib + `ed25519_orlp` only,
  and `meshfan/__init__.py` imports nothing — `import meshfan.jwt` standalone
  does NOT pull in the daemon, paho, or YAML. `sign_jwt` is a pure function
  with an injectable `now` and no hidden globals; the API shape is right
  (findings 14-18 are hardening/polish, not structure).
- `meshfan/fanout.py` is network-free and fake-injectable by duck typing —
  trivially testable as-is.
- The argparse layer (`meshfan/__main__.py:24-44`) is clean: parser, exit
  codes, `--version`, `--check` flag all properly isolated from config
  parsing.

## Efficiency / process note

Discovery overhead: the full 10-file set was read twice (20 reads) because
the tree changed mid-review — a concurrency hazard, not a tooling one. Safe
faster method for the parent: pin a commit (or run the review in a worktree)
before dispatching reviewers, and batch fixes after review rather than during.
Duplicated measurement: the seven concurrent fixes listed at the top had to be
re-verified against fresh reads instead of being reviewed once. Write-back:
all findings above are against the second-pass tree; re-run this review after
the tree settles at a commit.

## Overall verdict

The structure is sound and the concurrent fixes during review show the design
is converging: `jwt.sign_jwt` is genuinely standalone, pure, and
clock-injectable; config dataclasses are plain and readable; fanout is
fake-injectable; CLI exit codes are clean. What separates this from a
publishable library is not architecture but surface and evidence: no public
exports or exception hierarchy, no tests (including the JWT known-answer test
its own research plan mandates), no README, file-only config loading, no
client-factory seam so the core renewal/backoff logic stays untestable
off-network, and a handful of silent-failure paths (unknown config keys,
ValueError tracebacks, unvalidated key lengths, an unenforced chmod-600
claim). Fixing findings 1-13 is a bounded, mechanical pass — roughly a day of
work — after which the project matches the quality bar its SPEC and RESEARCH
documents already set for it.
