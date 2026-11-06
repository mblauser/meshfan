"""meshfan entry point.

Usage:
    meshfan --config config/meshfan.yaml
    meshfan --config config/meshfan.yaml --check
    meshfan key encrypt --in key.plain --out key.age
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time

from . import __version__
from .config import (
    DEFAULT_AGE_COMMAND,
    DEFAULT_AGE_TIMEOUT,
    DEFAULT_PASSPHRASE_ENV,
    Config,
    ConfigError,
    load,
)
from .fanout import Fanout
from .key import (
    KeyLoadError,
    encrypt_key_file,
    load_private_key,
    load_public_key,
    load_secret,
    verify_keypair,
)
from .log import sanitize, setup_logging, validate_file_path
from .sink import Sink
from .source import Source
from .tls import build_ssl_context

#: A clock earlier than this is almost certainly wrong (2020-09-13), and
#: would make every signed JWT look expired/not-yet-valid.
_MIN_PLAUSIBLE_EPOCH = 1_600_000_000


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
    return p


def _disable_core_dumps() -> None:
    """Keep the private key out of core dumps.

    The systemd unit must also set LimitCORE=0 (the unit file is a separate
    task); mlock is intentionally out of scope.
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


def _load_everything(cfg: Config):
    """Load secrets, verify the keypair, and build TLS contexts."""
    private_key = load_private_key(cfg.key)
    public_key = load_public_key(cfg.key.public_key)
    verify_keypair(public_key, private_key)
    cfg.source.password = load_secret(
        cfg.source.password_env,
        cfg.source.password_file,
        cfg.source.password,
        "source password",
    )
    source_ctx = build_ssl_context(cfg.source.tls, "source.tls")
    sink_ctxs = [
        build_ssl_context(b.tls, f"brokers[{i}].tls ({b.name})")
        for i, b in enumerate(cfg.brokers)
    ]
    return private_key, public_key, source_ctx, sink_ctxs


def _startup_warnings(cfg: Config, *, inline_password: bool) -> list[str]:
    warnings = list(cfg.warnings)
    if inline_password:
        warnings.append(
            "source.password is inline and deprecated; use password_env "
            "(preferred) or password_file"
        )
    if not cfg.source.tls.enabled:
        warnings.append(
            f"source {sanitize(cfg.source.host, 80)}:{cfg.source.port} is "
            "PLAINTEXT (tls.enabled=false, tls.plaintext=true): MQTT "
            "credentials and traffic are not protected"
        )
    if cfg.source.tls.enabled and cfg.source.tls.insecure:
        warnings.append(
            "source: TLS certificate verification DISABLED (tls.insecure=true)"
        )
    for b in cfg.brokers:
        if not b.tls.enabled:
            warnings.append(
                f"{b.name}: PLAINTEXT (tls.enabled=false, tls.plaintext=true): "
                "the signed JWT and every message are sent in the clear"
            )
        elif b.tls.insecure:
            warnings.append(
                f"{b.name}: TLS certificate verification DISABLED "
                "(tls.insecure=true)"
            )
    return warnings


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


def _cmd_run(args) -> int:
    try:
        cfg = load(args.config)
    except ConfigError as e:
        return _fail("config error", e)

    # Capture before resolution overwrites the field with the resolved value.
    inline_password = cfg.source.password is not None

    try:
        private_key, public_key, source_ctx, sink_ctxs = _load_everything(cfg)
    except KeyLoadError as e:
        return _fail("key error", e)
    except ConfigError as e:
        return _fail("config error", e)

    warnings = _startup_warnings(cfg, inline_password=inline_password)

    if args.check:
        try:
            _check_log_path(cfg)
        except OSError as e:
            return _fail("logging error", e)
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        print(
            f"OK: config valid, keypair verified, TLS material valid, "
            f"{len(cfg.brokers)} broker(s)"
        )
        return 0

    try:
        setup_logging(cfg.logging, cfg.debug)
    except OSError as e:
        return _fail("logging error", e)

    log = logging.getLogger("meshfan")
    log.info(
        "meshfan %s starting: source %s:%s %s -> %d broker(s)",
        __version__,
        sanitize(cfg.source.host, 80),
        cfg.source.port,
        sanitize(cfg.source.topic, 200),
        len(cfg.brokers),
    )
    if cfg.logging.output != "stdout":
        log.info("logging to %s", cfg.logging.output)

    if time.time() < _MIN_PLAUSIBLE_EPOCH:
        log.warning(
            "system clock looks implausibly early (%s); signed JWTs use "
            "iat/exp from the wall clock and will likely be rejected",
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
    for w in warnings:
        log.warning("%s", sanitize(w, 500))

    sinks = [
        Sink(
            b,
            public_key,
            private_key,
            cfg.token,
            cfg.reconnect,
            cfg.runtime,
            cfg.debug,
            sink_ctxs[i],
        )
        for i, b in enumerate(cfg.brokers)
    ]
    fanout = Fanout(sinks, cfg.debug)
    source = Source(cfg.source, fanout.dispatch, source_ctx)

    stop = threading.Event()

    def _sig(signum, _frame) -> None:
        log.info("received signal %s, shutting down", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    for s in sinks:
        s.start()
    source.start()

    stop.wait()

    source.stop()
    for s in sinks:
        s.stop()
    log.info("meshfan stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Do this before any secret is loaded.
    _disable_core_dumps()
    args = _build_parser().parse_args(argv)
    if args.command == "key":
        if args.key_command == "encrypt":
            return _cmd_key_encrypt(args)
        _build_parser().print_help(sys.stderr)
        return 2
    return _cmd_run(args)


if __name__ == "__main__":
    raise SystemExit(main())
