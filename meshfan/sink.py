"""A single WSS sink: one target broker, with JWT renewal and reconnect.

Each sink signs a fresh Ed25519 device JWT (cached with a TTL, renewed
before expiry), opens a WSS connection (TLS verified), publishes messages,
and reconnects with exponential backoff plus jitter. Runs its own thread.

Renewal is scheduled on time.monotonic(); only the token's iat/exp use the
wall clock. A token that is close to expiry makes the sink drop the
connection and reconnect with a freshly signed one.
"""
from __future__ import annotations

import logging
import random
import ssl
import threading
import time

from typing import Callable

import paho.mqtt.client as mqtt

from . import jwt as jwtmod
from .config import (
    BrokerConfig,
    ConfigError,
    DebugConfig,
    ReconnectConfig,
    RuntimeConfig,
    TokenConfig,
)
from .log import sanitize
from .transport import MqttClient, MqttClientFactory

log = logging.getLogger("meshfan.sink")

# paho MQTT 3.1.1 CONNACK codes: 4 = bad user name/password, 5 = not authorized.
_AUTH_CODES = (4, 5)


class Sink:
    def __init__(
        self,
        broker: BrokerConfig,
        public_key: bytes,
        private_key: bytes,
        token_cfg: TokenConfig,
        reconnect_cfg: ReconnectConfig,
        runtime: RuntimeConfig,
        debug: DebugConfig,
        ssl_ctx: ssl.SSLContext | None,
        *,
        client_factory: MqttClientFactory | None = None,
        wall_clock: Callable[[], int] | None = None,
        mono_clock: Callable[[], float] | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self.broker = broker
        self.public_key = public_key
        self.private_key = private_key
        self.token_cfg = token_cfg
        self.reconnect_cfg = reconnect_cfg
        self.runtime = runtime
        self.debug = debug
        if broker.tls.enabled and ssl_ctx is None:
            raise ConfigError(
                f"{broker.name}: TLS is enabled but no SSL context was supplied"
            )
        if not broker.tls.enabled and ssl_ctx is not None:
            raise ConfigError(
                f"{broker.name}: TLS is disabled but an SSL context was supplied"
            )
        self._ssl_ctx = ssl_ctx

        # Test seams: injectable clocks and RNG so renewal and backoff are
        # deterministically testable without sleeping or monkeypatching.
        self._client_factory = (
            client_factory if client_factory is not None else self._make_paho_client
        )
        self._wall_clock = wall_clock if wall_clock is not None else (
            lambda: int(time.time())
        )
        self._mono_clock = mono_clock if mono_clock is not None else time.monotonic
        self._rng = rng if rng is not None else random.Random()

        self._token: jwtmod.Token | None = None
        self._renew_at: float | None = None  # mono_clock() deadline
        self._client: MqttClient | None = None
        self._client_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._auth_failed = False
        self._attempts = 0

        self.connected = False
        self.published = 0
        self.dropped = 0
        self._drop_warned = False
        self._last_summary = self._mono_clock()
        self._published_mark = 0
        self._dropped_mark = 0

        self._username = runtime.username_prefix + public_key.hex().upper()

    # -- token management --
    def _ensure_token(self) -> jwtmod.Token:
        now = self._wall_clock()
        if (
            self._token is not None
            and not self._token.should_renew(now, self.token_cfg.renew_before_seconds)
        ):
            return self._token
        tok = jwtmod.sign_jwt(
            public_key=self.public_key,
            private_key=self.private_key,
            audience=self.broker.audience,
            client=self.broker.client,
            ttl_seconds=self.token_cfg.ttl_seconds,
            now=now,
        )
        if self.debug.tokens:
            log.info(
                "%s: signed new token (exp=%s, renew_in=%ss)",
                self.broker.name,
                tok.exp,
                max(0, tok.exp - now - self.token_cfg.renew_before_seconds),
            )
        self._token = tok
        # Schedule the reconnect on the monotonic clock: remaining wall-clock
        # lifetime minus the renewal lead, from now.
        remaining = max(0.0, float(tok.exp - now))
        lead = min(float(self.token_cfg.renew_before_seconds), remaining)
        self._renew_at = self._mono_clock() + max(0.0, remaining - lead)
        return tok

    def _make_paho_client(self) -> MqttClient:
        c = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.broker.client,
            transport="websockets",
            reconnect_on_failure=False,
        )
        c.ws_set_options(path=self.broker.path)
        c.username_pw_set(self._username, self._ensure_token().value)
        if self._ssl_ctx is not None:
            c.tls_set_context(self._ssl_ctx)
        c.max_queued_messages_set(self.runtime.max_queued_messages)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        return c

    # -- callbacks (paho network thread) --
    def _on_connect(self, client, userdata, connect_flags, reason_code, properties) -> None:
        rc = getattr(reason_code, "value", reason_code)
        if rc == 0:
            self.connected = True
            self._attempts = 0
            self._auth_failed = False
            self._drop_warned = False
            log.info("%s: connected", self.broker.name)
        else:
            self.connected = False
            text = sanitize(reason_code, 120)
            if rc in _AUTH_CODES or any(
                word in text.lower()
                for word in ("not authori", "bad user", "bad username", "credential")
            ):
                # Force a fresh signature on the next attempt instead of
                # retrying the same rejected token.
                self._token = None
                self._auth_failed = True
                log.error(
                    "%s: authentication rejected (%s); will re-sign the token",
                    self.broker.name,
                    text,
                )
            else:
                log.error("%s: connect failed: %s", self.broker.name, text)
        self._wake.set()

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties) -> None:
        self.connected = False
        if self._stop.is_set():
            log.debug("%s: disconnected during shutdown", self.broker.name)
        else:
            log.warning(
                "%s: disconnected: %s", self.broker.name, sanitize(reason_code, 120)
            )
        self._wake.set()

    # -- reconnect policy --
    def _backoff(self) -> float:
        r = self.reconnect_cfg
        # Cap the exponent so a long outage cannot overflow float pow.
        exponent = min(max(self._attempts, 0), 60)
        try:
            delay = r.base_delay * (r.multiplier ** exponent)
        except OverflowError:
            delay = r.max_delay
        delay = min(delay, r.max_delay)
        delay *= 1.0 - self._rng.uniform(0, r.jitter)
        return max(delay, 0.0)

    # -- client lifecycle --
    def _teardown_client(self) -> None:
        # First statement: a publish() must immediately see "not connected".
        self.connected = False
        with self._client_lock:
            client = self._client
            self._client = None
        if client is not None:
            try:
                client.loop_stop()
            except Exception:
                log.debug("%s: loop_stop failed", self.broker.name, exc_info=True)

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"sink-{self.broker.name}", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        # Outer guard: no exception may ever kill the sink thread.
        while not self._stop.is_set():
            try:
                self._run_once()
            except Exception:
                log.exception(
                    "%s: unexpected sink loop error; continuing", self.broker.name
                )
                self._stop.wait(self.reconnect_cfg.base_delay)

    def _run_once(self) -> None:
        reason = "error"
        try:
            reason = self._connect_and_serve()
        except Exception as e:
            log.warning(
                "%s: connection error: %s", self.broker.name, sanitize(e, 200)
            )
            log.debug("%s: traceback", self.broker.name, exc_info=True)
        finally:
            try:
                self._teardown_client()
            except Exception:
                log.debug("%s: teardown failed", self.broker.name, exc_info=True)
        if self._stop.is_set():
            return

        if reason == "renew":
            # A planned renewal reconnects at once; no backoff.
            return
        # Compute the delay from the current attempt count (0 on the first
        # failure), then increment, so the first retry is base_delay.
        try:
            delay = self._backoff()
            self._attempts += 1
            log.debug("%s: reconnecting in %.1fs", self.broker.name, delay)
        except Exception:
            log.exception("%s: backoff failed", self.broker.name)
            delay = self.reconnect_cfg.base_delay
        self._wait_with_summary(delay)

    def _wait_with_summary(self, delay: float) -> None:
        """Sleep before a retry in slices, keeping the drop summary alive."""
        end = self._mono_clock() + delay
        slice_ = self.runtime.token_check_seconds
        if self.runtime.summary_interval_seconds > 0:
            slice_ = min(slice_, self.runtime.summary_interval_seconds)
        while not self._stop.is_set():
            now = self._mono_clock()
            if now >= end:
                return
            self._maybe_summary(now)
            self._stop.wait(min(slice_, end - now))

    def _connect_and_serve(self) -> str:
        self._auth_failed = False
        client = self._client_factory()
        with self._client_lock:
            self._client = client
        client.connect(
            self.broker.host,
            self.broker.port,
            keepalive=self.broker.keepalive,
        )
        client.loop_start()
        try:
            return self._serve(client)
        finally:
            try:
                client.disconnect()
            except Exception:
                log.debug(
                    "%s: disconnect failed", self.broker.name, exc_info=True
                )

    def _serve(self, client: MqttClient) -> str:
        """Wait on a live connection; return why it ended."""
        connected_once = self.connected
        deadline = self._mono_clock() + self.runtime.connect_timeout_seconds
        while not self._stop.is_set():
            now = self._mono_clock()
            if self.connected:
                connected_once = True
            elif connected_once:
                log.warning("%s: connection lost", self.broker.name)
                return "lost"
            elif self._auth_failed:
                return "auth"
            elif now >= deadline:
                log.warning(
                    "%s: connect did not complete within %.1fs",
                    self.broker.name,
                    self.runtime.connect_timeout_seconds,
                )
                return "timeout"

            if self._renew_at is not None and now >= self._renew_at:
                # Invalidate now, so the next attempt is guaranteed to sign a
                # fresh token even if the wall clock and monotonic clock have
                # drifted apart. Otherwise a stale token could make this loop
                # reconnect immediately, forever.
                self._token = None
                log.info(
                    "%s: token near expiry; reconnecting with a fresh token",
                    self.broker.name,
                )
                return "renew"

            self._maybe_summary(now)

            wait = self.runtime.token_check_seconds
            if self._renew_at is not None:
                wait = min(wait, max(0.0, self._renew_at - now))
            if not connected_once:
                wait = min(wait, max(0.0, deadline - now))
            self._wake.wait(max(0.01, wait))
            self._wake.clear()

        return "stop"

    def _maybe_summary(self, now: float) -> None:
        interval = self.runtime.summary_interval_seconds
        if interval <= 0 or now - self._last_summary < interval:
            return
        self._last_summary = now
        pub = self.published - self._published_mark
        drop = self.dropped - self._dropped_mark
        self._published_mark = self.published
        self._dropped_mark = self.dropped
        level = logging.WARNING if drop else logging.INFO
        log.log(
            level,
            "%s: published %d, dropped %d since last summary "
            "(totals %d/%d, connected=%s)",
            self.broker.name,
            pub,
            drop,
            self.published,
            self.dropped,
            self.connected,
        )

    # -- publishing (source thread) --
    def publish(self, topic: str, payload: bytes, qos: int = 0) -> bool:
        # Snapshot once: the sink thread may null self._client mid-call.
        client = self._client
        if client is None or not self.connected:
            self._note_drop("not connected")
            return False
        try:
            info = client.publish(topic, payload, qos)
        except Exception as e:
            self._note_drop(f"publish raised: {sanitize(e, 80)}")
            return False
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            self._note_drop(f"publish returned rc={info.rc}")
            return False
        self.published += 1
        return True

    def _note_drop(self, reason: str) -> None:
        self.dropped += 1
        if not self._drop_warned:
            self._drop_warned = True
            log.warning(
                "%s: dropping messages (%s); further drops are counted until "
                "the next summary",
                self.broker.name,
                sanitize(reason, 120),
            )

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        # Disconnect first (paho is thread-safe here): this unblocks the
        # network loop immediately, so the join does not stall for the full
        # timeout on an idle connection, and the broker gets a clean MQTT
        # DISCONNECT.
        client = self._client
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                log.debug("%s: disconnect on stop failed", self.broker.name, exc_info=True)
        if self._thread:
            self._thread.join(timeout=self.runtime.shutdown_timeout)
            if self._thread.is_alive():
                log.error(
                    "%s: sink thread still alive after %.1fs shutdown timeout",
                    self.broker.name,
                    self.runtime.shutdown_timeout,
                )
