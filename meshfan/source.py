"""The MQTT source: subscribe to one topic, dispatch each message.

Plain TCP or TLS. paho auto-reconnects (reconnect_on_failure default), so
no JWT is needed here. Runs on paho's network loop thread.
"""
from __future__ import annotations

import logging
import ssl
from collections.abc import Callable

import paho.mqtt.client as mqtt

from .config import ConfigError, SourceConfig
from .log import sanitize
from .transport import MqttClient, MqttClientFactory

log = logging.getLogger("meshfan.source")


class Source:
    def __init__(
        self,
        cfg: SourceConfig,
        on_message: Callable[[str, bytes, int], None],
        ssl_ctx: ssl.SSLContext | None,
        *,
        client_factory: MqttClientFactory | None = None,
    ) -> None:
        self.cfg = cfg
        self.on_message = on_message
        if cfg.tls.enabled and ssl_ctx is None:
            raise ConfigError("source: TLS is enabled but no SSL context was supplied")
        if not cfg.tls.enabled and ssl_ctx is not None:
            raise ConfigError("source: TLS is disabled but an SSL context was supplied")
        self._ssl_ctx = ssl_ctx
        self._client_factory = (
            client_factory if client_factory is not None else self._make_paho_client
        )
        self._client: MqttClient | None = None
        self.connected = False

    def _make_paho_client(self) -> MqttClient:
        c = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.cfg.client_id,
        )
        if self.cfg.username:
            c.username_pw_set(self.cfg.username, self.cfg.password or None)
        if self._ssl_ctx is not None:
            c.tls_set_context(self._ssl_ctx)
        c.on_connect = self._on_connect
        c.on_disconnect = self._on_disconnect
        c.on_message = self._on_message
        return c

    def _on_connect(self, client, userdata, connect_flags, reason_code, properties) -> None:
        rc = getattr(reason_code, "value", reason_code)
        if rc == 0:
            self.connected = True
            client.subscribe(self.cfg.topic, qos=self.cfg.qos)
            log.info(
                "source: connected, subscribed to %s (qos=%d)",
                sanitize(self.cfg.topic, 200),
                self.cfg.qos,
            )
        else:
            self.connected = False
            log.error("source: connect failed: %s", sanitize(reason_code, 120))

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties) -> None:
        was_connected = self.connected
        self.connected = False
        if was_connected:
            log.warning(
                "source: disconnected: %s", sanitize(reason_code, 120)
            )

    def _on_message(self, client, userdata, msg) -> None:
        self.on_message(msg.topic, msg.payload, msg.qos)

    def start(self) -> None:
        self._client = self._client_factory()
        try:
            self._client.connect(
                self.cfg.host, self.cfg.port, keepalive=self.cfg.keepalive
            )
        except Exception as e:
            # DNS or TCP failures are transient; paho keeps retrying. Never
            # abort startup for them.
            log.warning(
                "source: initial connect failed: %s (will retry)", sanitize(e, 200)
            )
        self._client.loop_start()

    def stop(self) -> None:
        client = self._client
        self._client = None
        if client is None:
            return
        # A clean DISCONNECT: paho sends the packet if still connected.
        try:
            client.disconnect()
        except Exception:
            log.debug("source: disconnect failed", exc_info=True)
        try:
            client.loop_stop()
        except Exception:
            log.debug("source: loop_stop failed", exc_info=True)
        self.connected = False
