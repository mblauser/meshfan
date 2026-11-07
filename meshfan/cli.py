"""The meshfan command line: argparse + exit codes only.

Process-global side effects (RLIMIT_CORE, signal handlers, global logging)
belong here, in the standalone process, not in the library
(meshfan.app), so `python -m meshfan` and the `meshfan` console script
behave exactly as before:

    meshfan --config config/meshfan.yaml
    meshfan --config config/meshfan.yaml --check
    meshfan --init-config /etc/meshfan/meshfan.yaml
    meshfan key encrypt --in key.plain --out key.age
    meshfan key generate --out key.plain --pub-out key.pub
    meshfan jwt sign --aud map.example.net --client meshfan-1
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__
from .app import MeshfanApp, install_signal_handlers, prepare, startup_warnings
from .config import (
    DEFAULT_AGE_COMMAND,
    DEFAULT_AGE_TIMEOUT,
    DEFAULT_PASSPHRASE_ENV,
    Config,
    ConfigError,
    load,
)
from .jwt import sign_jwt
from .key import KeyLoadError, encrypt_key_file
from .log import sanitize, setup_logging, validate_file_path
from .tls import build_ssl_context


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meshfan",
        description="MQTT fan-out relay that signs Ed25519 device JWTs",
    )
    p.add_argument(
        "--config",
        default="config/meshfan.yaml",
        help="path to the config file (default: config/meshfan.yaml)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="validate the config, key, TLS material, and log path, then exit",
    )
    p.add_argument(
        "--init-config",
        metavar="PATH",
        default=None,
        help="write the packaged example config to PATH (mode 0600), then exit",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"meshfan {__version__}",
    )

    sub = p.add_subparsers(dest="command")

    key = sub.add_parser("key", help="key management helpers")
    key_sub = key.add_subparsers(dest="key_command")
    encrypt = key_sub.add_parser(
        "encrypt", help="encrypt a plaintext key file with age"
    )
    encrypt.add_argument("--in", dest="in_path", required=True, help="plaintext key file")
    encrypt.add_argument("--out", dest="out_path", required=True, help="age output file")
    encrypt.add_argument(
        "--passphrase-env",
        default=None,
        help=(
            "env var holding the age passphrase "
            f"(default: the config's key.passphrase_env, else {DEFAULT_PASSPHRASE_ENV})"
        ),
    )
    encrypt.add_argument(
        "--force",
        action="store_true",
        help="replace the output file if it already exists",
    )
    generate = key_sub.add_parser(
        "generate", help="generate a MeshCore Ed25519 keypair"
    )
    generate.add_argument(
        "--out",
        dest="out_path",
        required=True,
        help="where to write the 128-hex private key (mode 0600)",
    )
    generate.add_argument(
        "--pub-out",
        dest="pub_out_path",
        required=True,
        help="where to write the 64-hex public key (mode 0600)",
    )

    jwt = sub.add_parser("jwt", help="device JWT helpers")
    jwt_sub = jwt.add_subparsers(dest="jwt_command")
    sign = jwt_sub.add_parser(
        "sign", help="sign a device JWT using the config's key (prints token + exp)"
    )
    sign.add_argument("--aud", dest="audience", required=True, help="the `aud` claim")
    sign.add_argument(
        "--client", dest="client", required=True, help="the `client` claim"
    )
    sign.add_argument(
        "--ttl",
        dest="ttl",
        type=int,
        default=None,
        help="token lifetime in seconds (default: the config's token.ttl_seconds)",
    )
    return p


def _disable_core_dumps() -> None:
    """Keep the private key out of core dumps.

    CLI process only: this zeroes RLIMIT_CORE for the process, so it must
    not run in a library host. The systemd unit must also set
    LimitCORE=0 (the unit file is a separate task); mlock is
    intentionally out of scope.
    """
    try:
        import resource
    except ImportError:  # pragma: no cover - non-Unix
        return
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as e:
        print(f"warning: could not disable core dumps: {e}", file=sys.stderr)


def _fail(prefix: str, exc: BaseException) -> int:
    print(f"{prefix}: {sanitize(exc, 400)}", file=sys.stderr)
    return 2


def _check_log_path(cfg: Config) -> None:
    if cfg.logging.output == "file":
        assert cfg.logging.file_path is not None
        validate_file_path(cfg.logging)


def _load_example_config() -> str | None:
    """The packaged example config, or the repo copy in a source checkout."""
    try:
        from importlib.resources import files

        return (
            files("meshfan")
            .joinpath("data", "meshfan.example.yaml")
            .read_text(encoding="utf-8")
        )
    except Exception:
        pass
    fallback = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "config",
        "meshfan.example.yaml",
    )
    try:
        with open(fallback, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _write_mode_600(path: str, data: str) -> None:
    """Write a file that is never briefly world-readable (O_EXCL, 0600)."""
    if os.path.exists(path):
        raise OSError(f"file already exists: {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def _cmd_init_config(path: str) -> int:
    example = _load_example_config()
    if example is None:
        print(
            "error: the packaged example config was not found", file=sys.stderr
        )
        return 2
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            return _fail("config error", e)
    try:
        _write_mode_600(path, example)
    except OSError as e:
        return _fail("config error", e)
    print(f"OK: wrote starter config to {path} (mode 0600)")
    print(f"Next: edit {path}, then run `meshfan --config {path} --check`")
    return 0


def _cmd_key_encrypt(args) -> int:
    """Encrypt a plaintext key file with age.

    The passphrase is read from an env var and handed to age through a 0600
    passphrase file; it is never placed on the command line and never echoed.
    """
    age_command = DEFAULT_AGE_COMMAND
    timeout = DEFAULT_AGE_TIMEOUT
    default_env = DEFAULT_PASSPHRASE_ENV
    try:
        cfg = load(args.config)
    except ConfigError as e:
        # Key management still works without a config; warn only if a file
        # was actually present (so a bad config is not silently ignored).
        if os.path.exists(args.config):
            print(
                f"warning: {sanitize(args.config, 200)} is not usable "
                f"({sanitize(e, 200)}); using built-in defaults",
                file=sys.stderr,
            )
        cfg = None
    if cfg is not None:
        age_command = cfg.key.age_command
        timeout = cfg.key.age_timeout_seconds
        default_env = cfg.key.passphrase_env or default_env

    env_name = args.passphrase_env or default_env
    passphrase = os.environ.pop(env_name, None)
    if not passphrase:
        print(
            f"key error: environment variable {env_name} is "
            f"{'empty' if passphrase == '' else 'not set'}; "
            "export a non-empty passphrase or pass --passphrase-env",
            file=sys.stderr,
        )
        return 2

    try:
        encrypt_key_file(
            args.in_path,
            args.out_path,
            passphrase,
            age_command,
            timeout,
            force=args.force,
        )
    except KeyLoadError as e:
        return _fail("key error", e)

    print(f"OK: encrypted {args.in_path} -> {args.out_path} with {age_command}")
    return 0


def _cmd_key_generate(args) -> int:
    """Generate a MeshCore Ed25519 keypair and write it with mode 0600."""
    try:
        from ed25519_orlp import ed25519_create_keypair

        public_key, private_key, _seed = ed25519_create_keypair()
    except Exception as e:  # the C extension raises ValueError on bad input
        return _fail("key error", e)
    try:
        _write_mode_600(args.out_path, private_key.hex())
        _write_mode_600(args.pub_out_path, public_key.hex())
    except OSError as e:
        return _fail("key error", e)
    print(f"public key: {public_key.hex()}")
    print(f"OK: private key written to {args.out_path} (mode 0600)")
    print(f"OK: public key written to {args.pub_out_path} (mode 0600)")
    return 0


def _cmd_jwt_sign(args) -> int:
    """Sign a device JWT with the config's key; prints token + exp, never the key."""
    try:
        cfg = load(args.config)
    except ConfigError as e:
        return _fail("config error", e)
    try:
        secrets = prepare(cfg)
    except KeyLoadError as e:
        return _fail("key error", e)
    ttl = args.ttl if args.ttl is not None else cfg.token.ttl_seconds
    try:
        tok = sign_jwt(
            public_key=secrets.public_key,
            private_key=secrets.private_key,
            audience=args.audience,
            client=args.client,
            ttl_seconds=ttl,
        )
    except ValueError as e:
        return _fail("sign error", e)
    print(f"token: {tok.value}")
    print(f"exp: {tok.exp}")
    return 0


def _cmd_run(args) -> int:
    try:
        cfg = load(args.config)
    except ConfigError as e:
        return _fail("config error", e)

    # The inline (deprecated) password, captured before resolution.
    inline_password = cfg.source.password is not None

    try:
        secrets = prepare(cfg)
        build_ssl_context(cfg.source.tls, "source.tls")
        for i, b in enumerate(cfg.brokers):
            build_ssl_context(b.tls, f"brokers[{i}].tls ({b.name})")
    except KeyLoadError as e:
        return _fail("key error", e)
    except ConfigError as e:
        return _fail("config error", e)

    if args.check:
        try:
            _check_log_path(cfg)
        except OSError as e:
            return _fail("logging error", e)
        for w in list(cfg.warnings) + startup_warnings(
            cfg, inline_password=inline_password
        ):
            print(f"warning: {w}", file=sys.stderr)
        print(
            f"OK: config valid, keypair verified, TLS material valid, "
            f"{len(cfg.brokers)} broker(s)"
        )
        return 0

    try:
        setup_logging(cfg.logging, cfg.debug)
    except (OSError, ConfigError) as e:
        return _fail("logging error", e)

    log = logging.getLogger("meshfan")
    if cfg.logging.output != "stdout":
        log.info("logging to %s", cfg.logging.output)

    app = MeshfanApp(cfg, secrets=secrets)
    install_signal_handlers(app)
    app.start()
    app.stop_event.wait()
    app.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    # Do this before any secret is loaded. CLI process only.
    _disable_core_dumps()
    args = _build_parser().parse_args(argv)
    if args.init_config:
        return _cmd_init_config(args.init_config)
    if args.command == "key":
        if args.key_command == "encrypt":
            return _cmd_key_encrypt(args)
        if args.key_command == "generate":
            return _cmd_key_generate(args)
        _build_parser().print_help(sys.stderr)
        return 2
    if args.command == "jwt":
        if args.jwt_command == "sign":
            return _cmd_jwt_sign(args)
        _build_parser().print_help(sys.stderr)
        return 2
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
