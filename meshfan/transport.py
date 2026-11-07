"""The MQTT client boundary.

Sink and Source talk to a small Protocol (MqttClient) instead of paho
directly, so tests can inject a fake client without a network, and the
paho import stays inside the daemon modules. The default factory is the
real paho client; tests pass their own ``client_factory``.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable


@runtime_checkable
class MqttClient(Protocol):
    """The subset of the paho-mqtt 2.x client API that meshfan uses."""

    # paho callback attributes, set by the owner before loop_start().
    on_connect: object
    on_disconnect: object
    on_message: object

    def connect(self, host: str, port: int, keepalive: int = 60) -> None:
        """Initiate the (TCP or WSS) connection."""

    def disconnect(self) -> None:
        """Send a clean MQTT DISCONNECT if still connected."""

    def loop_start(self) -> None:
        """Start the network loop in a background thread."""

    def loop_stop(self) -> None:
        """Stop the network loop."""

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> object:
        """Publish; the return value carries an ``rc`` (0 = success)."""

    def subscribe(self, topic: str, qos: int = 0) -> None:
        """Subscribe (source only)."""

    def username_pw_set(self, username: str, password: str | None = None) -> None:
        """Set the MQTT credentials (the device JWT is the password)."""

    def tls_set_context(self, ctx: object) -> None:
        """Install an ssl.SSLContext."""

    def ws_set_options(self, path: str) -> None:
        """Set the WebSocket path (paho websockets transport)."""

    def max_queued_messages_set(self, limit: int) -> None:
        """Cap the outgoing queue."""


#: A zero-argument callable that constructs a configured MqttClient.
MqttClientFactory = Callable[[], MqttClient]
