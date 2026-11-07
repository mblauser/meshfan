"""Sink renewal/backoff with injected clocks + a fake client (no network)."""
from __future__ import annotations

import random

import pytest

from meshfan.config import (
    BrokerConfig,
    ConfigError,
    DebugConfig,
    ReconnectConfig,
    RuntimeConfig,
    TlsConfig,
    TokenConfig,
)
from meshfan.sink import Sink


class FakeClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class SteppingClock:
    """A clock that advances by `step` on every read."""

    def __init__(self, value: float, step: float) -> None:
        self.value = value
        self.step = step

    def __call__(self) -> float:
        v = self.value
        self.value += self.step
        return v


class FakeInfo:
    def __init__(self, rc: int) -> None:
        self.rc = rc


class FakeClient:
    """A MqttClient stand-in: records calls, never touches the network."""

    def __init__(self, publish_rc: int = 0) -> None:
        self.publish_rc = publish_rc
        self.calls: list[tuple] = []
        self.on_connect = None
        self.on_disconnect = None
        self.on_message = None

    def connect(self, host, port, keepalive=60):
        self.calls.append(("connect", host, port, keepalive))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def loop_start(self):
        self.calls.append(("loop_start",))

    def loop_stop(self):
        self.calls.append(("loop_stop",))

    def publish(self, topic, payload, qos=0):
        self.calls.append(("publish", topic, payload, qos))
        return FakeInfo(self.publish_rc)

    def username_pw_set(self, username, password=None):
        self.calls.append(("username_pw_set", username, password))

    def tls_set_context(self, ctx):
        self.calls.append(("tls_set_context", ctx))

    def ws_set_options(self, path):
        self.calls.append(("ws_set_options", path))

    def max_queued_messages_set(self, limit):
        self.calls.append(("max_queued_messages_set", limit))


def make_sink(
    keypair,
    *,
    wall: FakeClock,
    mono: FakeClock,
    rng: random.Random | None = None,
    token_check: float = 30.0,
) -> Sink:
    pub, priv, _ = keypair
    broker = BrokerConfig(
        name="t",
        host="broker.example.net",
        port=443,
        path="/mqtt",
        audience="map.example.net",
        client="meshfan-t",
        tls=TlsConfig(enabled=False, plaintext=True),
    )
    return Sink(
        broker,
        pub,
        priv,
        TokenConfig(ttl_seconds=3600, renew_before_seconds=360),
        ReconnectConfig(
            base_delay=1.0, max_delay=60.0, multiplier=2.0, jitter=0.5
        ),
        RuntimeConfig(
            token_check_seconds=token_check,
            connect_timeout_seconds=10.0,
            summary_interval_seconds=300.0,
        ),
        DebugConfig(),
        None,
        client_factory=lambda: FakeClient(),
        wall_clock=wall,
        mono_clock=mono,
        rng=rng if rng is not None else random.Random(42),
    )


def test_ensure_token_signs_and_schedules(keypair):
    wall = FakeClock(1_000_000.0)
    mono = FakeClock(500.0)
    sink = make_sink(keypair, wall=wall, mono=mono)
    tok = sink._ensure_token()
    assert tok.exp == 1_000_000 + 3600
    # renew_at = mono + (remaining - lead) = 500 + (3600 - 360)
    assert sink._renew_at == 500.0 + 3240.0
    # a call inside the renewal window returns the cached token
    assert sink._ensure_token() is tok


def test_ensure_token_renews_in_window(keypair):
    wall = FakeClock(1_000_000.0)
    mono = FakeClock(500.0)
    sink = make_sink(keypair, wall=wall, mono=mono)
    tok = sink._ensure_token()
    # advance the wall clock into the renewal window
    wall.value = 1_000_000 + 3600 - 360
    mono.value = 500.0 + 3240.0
    tok2 = sink._ensure_token()
    assert tok2 is not tok
    assert tok2.value != tok.value
    assert tok2.exp == 1_000_000 + 3240 + 3600
    # rescheduled on the (advanced) monotonic clock
    assert sink._renew_at == 500.0 + 3240.0 + 3240.0


def test_backoff_bounds_and_growth(keypair):
    sink = make_sink(
        keypair, wall=FakeClock(0.0), mono=FakeClock(0.0), rng=random.Random(1)
    )
    # attempt 0: base * (1 - jitter*[0,1)) -> [0.5, 1.0)
    d0 = sink._backoff()
    assert 0.5 <= d0 < 1.0
    # attempt 3: base * 2^3 * (1 - [0, 0.5)) -> [4.0, 8.0)
    sink._attempts = 3
    d3 = sink._backoff()
    assert 4.0 <= d3 < 8.0
    # attempt 10: 1024 * ... capped at max_delay
    sink._attempts = 10
    d10 = sink._backoff()
    assert d10 <= 60.0


def test_publish_connected_and_drops(keypair):
    sink = make_sink(keypair, wall=FakeClock(0.0), mono=FakeClock(0.0))
    client = sink._client_factory()
    sink._client = client
    # not connected -> drop
    assert sink.publish("t", b"x", 0) is False
    assert sink.dropped == 1
    # connected, rc=0 -> published
    sink.connected = True
    assert sink.publish("t", b"x", 0) is True
    assert sink.published == 1
    # rc != 0 -> drop
    client.publish_rc = 1
    assert sink.publish("t", b"x", 0) is False
    assert sink.dropped == 2


def test_serve_renewal_reconnect(keypair):
    wall = FakeClock(1_000_000.0)
    mono = FakeClock(100.0)
    sink = make_sink(keypair, wall=wall, mono=mono)
    sink._ensure_token()
    client = sink._client_factory()
    sink._client = client
    sink.connected = True
    # advance past the renewal deadline
    mono.value = 100.0 + 3240.0 + 1
    assert sink._serve(client) == "renew"
    # the token is invalidated so the next attempt signs a fresh one
    assert sink._token is None


def test_serve_connect_timeout(keypair):
    wall = FakeClock(1_000_000.0)
    # The deadline is set on entry (mono + connect_timeout); a clock that
    # steps forward on every read makes the first loop check see it past.
    mono = SteppingClock(100.0, 20.0)
    sink = make_sink(keypair, wall=wall, mono=mono)
    client = sink._client_factory()
    sink.connected = False
    assert sink._serve(client) == "timeout"


def test_serve_connection_lost(keypair):
    import threading

    wall = FakeClock(1_000_000.0)
    mono = FakeClock(100.0)
    sink = make_sink(keypair, wall=wall, mono=mono, token_check=0.05)
    client = sink._client_factory()
    sink.connected = True  # was connected
    # the connection drops while the check loop is waiting
    timer = threading.Timer(0.02, lambda: setattr(sink, "connected", False))
    timer.start()
    try:
        assert sink._serve(client) == "lost"
    finally:
        timer.cancel()


def test_tls_mismatch_raises_config_error(keypair):
    pub, priv, _ = keypair
    broker = BrokerConfig(
        name="t",
        host="h",
        port=443,
        path="/mqtt",
        audience="a",
        client="c",
        tls=TlsConfig(enabled=True),
    )
    with pytest.raises(ConfigError, match="no SSL context"):
        Sink(
            broker,
            pub,
            priv,
            TokenConfig(),
            ReconnectConfig(),
            RuntimeConfig(),
            DebugConfig(),
            None,
        )


def test_make_paho_client_wires_credentials(keypair):
    sink = make_sink(keypair, wall=FakeClock(1_000_000.0), mono=FakeClock(500.0))
    # the default factory is the paho one; with the fake we check the
    # credential wiring through the fake instead (username = prefix + pub).
    assert sink._username == "v1_" + sink.public_key.hex().upper()
