"""Embeddable meshfan lifecycle.

MeshfanApp runs one relay (source -> fanout -> sinks) in-process with no
process-global side effects: no signal handlers, no RLIMIT changes, no
global logging reconfiguration. Those belong to the CLI (meshfan.cli),
which is a standalone process and may own the process.

Embed by hand:

    app = meshfan.app.MeshfanApp(cfg)
    app.start()
    ... later, from another thread:
    app.stop()

or the blocking one-shot:

    meshfan.app.run(cfg)

Secrets are resolved by prepare() into a ResolvedSecrets value object and
never written back onto the (frozen) Config, so repr(cfg) is safe to log
and the same Config can be started twice in one process.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import signal
import threading
import time
from typing import Mapping

from .config import Config, default_client_id
from .errors import MeshfanError
from .fanout import Fanout
from .key import (
    KeyLoadError,
    load_private_key,
    load_public_key,
    load_secret,
    verify_keypair,
)
from .log import sanitize
from .sink import Sink
from .source import Source
from .tls import build_ssl_context

#: A clock earlier than this is almost certainly wrong (2020-09-13), and
#: would make every signed JWT look expired/not-yet-valid.
MIN_PLAUSIBLE_EPOCH = 1_600_000_000


class ResolvedSecrets:
    """The resolved secrets for a Config.

    Kept separate from the (frozen) Config so the config object never
    carries a live secret. The repr redacts both secrets.
    """

    __slots__ = ("source_password", "private_key", "public_key")

    def __init__(
        self,
        source_password: str | None,
        private_key: bytes,
        public_key: bytes,
    ) -> None:
        self.source_password = source_password
        self.private_key = private_key
        self.public_key = public_key

    def __repr__(self) -> str:
        return (
            "ResolvedSecrets(source_password=<redacted>, "
            "private_key=<redacted>, public_key=<not a secret>)"
        )


def prepare(
    cfg: Config,
    *,
    env: Mapping[str, str] = os.environ,
    consume: bool = True,
) -> ResolvedSecrets:
    """Load and verify the secrets for a config without mutating it.

    Args:
        cfg: a validated config (frozen; this function does not touch it).
        env: the mapping to read env-var secrets from (default: os.environ).
        consume: remove read variables from `env` afterwards (default: True,
            the daemon behavior). Pass consume=False for idempotent library
            use (reload, retry, two relays in one process).
    """
    private_key = load_private_key(cfg.key, env=env, consume=consume)
    public_key = load_public_key(cfg.key.public_key)
    verify_keypair(public_key, private_key)
    source_password = load_secret(
        cfg.source.password_env,
        cfg.source.password_file,
        cfg.source.password,
        "source password",
        env=env,
        consume=consume,
    )
    return ResolvedSecrets(source_password, private_key, public_key)


def startup_warnings(cfg: Config, *, inline_password: bool) -> list[str]:
    """The loud startup warnings for a config (plaintext, insecure TLS)."""
    warnings: list[str] = []
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


class MeshfanApp:
    """Run one relay (source -> fanout -> sinks) in-process.

    No signal handlers, no RLIMIT changes, no global logging setup: the
    host process keeps full control. Call start() then stop(), or use
    run() for a blocking one-shot.
    """

    def __init__(
        self,
        cfg: Config,
        *,
        env: Mapping[str, str] = os.environ,
        consume: bool = True,
        logger: logging.Logger | None = None,
        secrets: ResolvedSecrets | None = None,
    ) -> None:
        self.cfg = cfg
        self._env = env
        self._consume = consume
        self._secrets = secrets
        self._logger = logger if logger is not None else logging.getLogger("meshfan")
        self._stop = threading.Event()
        self._sinks: list[Sink] = []
        self._source: Source | None = None
        self._started = False

    @property
    def stop_event(self) -> threading.Event:
        """The event set when the app should stop (signals, host threads)."""
        return self._stop

    def start(self) -> None:
        """Resolve secrets (if not given), build, and start the relay."""
        if self._started:
            raise MeshfanError("app already started")
        self._started = True
        if self._secrets is None:
            self._secrets = prepare(
                self.cfg, env=self._env, consume=self._consume
            )
        secrets = self._secrets

        source_ctx = build_ssl_context(self.cfg.source.tls, "source.tls")
        sink_ctxs = [
            build_ssl_context(b.tls, f"brokers[{i}].tls ({b.name})")
            for i, b in enumerate(self.cfg.brokers)
        ]
        self._sinks = [
            Sink(
                b,
                secrets.public_key,
                secrets.private_key,
                self.cfg.token,
                self.cfg.reconnect,
                self.cfg.runtime,
                self.cfg.debug,
                sink_ctxs[i],
            )
            for i, b in enumerate(self.cfg.brokers)
        ]
        fanout = Fanout(self._sinks, self.cfg.debug)
        # The resolved password and the resolved client id go onto a copy of
        # the source config; the Config itself stays frozen and unchanged.
        source_cfg = dataclasses.replace(
            self.cfg.source,
            password=secrets.source_password,
            client_id=self.cfg.source.client_id or default_client_id(),
        )
        self._source = Source(source_cfg, fanout.dispatch, source_ctx)

        self._logger.info(
            "meshfan starting: source %s:%s %s -> %d broker(s)",
            sanitize(self.cfg.source.host, 80),
            self.cfg.source.port,
            sanitize(self.cfg.source.topic, 200),
            len(self.cfg.brokers),
        )
        if time.time() < MIN_PLAUSIBLE_EPOCH:
            self._logger.warning(
                "system clock looks implausibly early (%s); signed JWTs use "
                "iat/exp from the wall clock and will likely be rejected",
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            )
        for w in list(self.cfg.warnings) + startup_warnings(
            self.cfg, inline_password=self.cfg.source.password is not None
        ):
            self._logger.warning("%s", sanitize(w, 500))

        for s in self._sinks:
            s.start()
        self._source.start()

    def stop(self) -> None:
        """Stop the source and all sinks (idempotent)."""
        if self._source is not None:
            self._source.stop()
            self._source = None
        for s in self._sinks:
            s.stop()
        self._sinks = []
        self._logger.info("meshfan stopped")


def install_signal_handlers(app: MeshfanApp) -> None:
    """Install SIGTERM/SIGINT handlers that stop the app (main thread only)."""
    if threading.current_thread() is not threading.main_thread():
        raise MeshfanError(
            "signal handlers can only be installed in the main thread"
        )

    def _sig(signum, _frame) -> None:
        app._logger.info("received signal %s, shutting down", signum)
        app.stop_event.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)


def run(
    cfg: Config,
    *,
    install_signal_handlers: bool = False,
    stop_event: threading.Event | None = None,
    env: Mapping[str, str] = os.environ,
    consume: bool = True,
    logger: logging.Logger | None = None,
) -> None:
    """Run the relay until stopped. Blocks the calling thread.

    Args:
        cfg: a validated config.
        install_signal_handlers: install SIGTERM/SIGINT handlers that stop
            the app (main thread only).
        stop_event: an external event that stops the run when set.
        env / consume: passed to prepare() for idempotent library use.
        logger: the logger to use (default: the "meshfan" logger).
    """
    app = MeshfanApp(cfg, env=env, consume=consume, logger=logger)
    if install_signal_handlers:
        install_signal_handlers(app)
    app.start()
    (stop_event if stop_event is not None else app.stop_event).wait()
    app.stop()
