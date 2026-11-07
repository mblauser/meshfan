"""Fanout with fake sinks (no network)."""
from __future__ import annotations

from meshfan.config import DebugConfig
from meshfan.fanout import Fanout, SinkLike


class FakeSink:
    def __init__(self, name: str, ok: bool = True, raise_exc: bool = False) -> None:
        class _B:
            pass

        self.broker = _B()
        self.broker.name = name
        self.ok = ok
        self.raise_exc = raise_exc
        self.published: list[tuple] = []

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> bool:
        self.published.append((topic, payload, qos))
        if self.raise_exc:
            raise RuntimeError("boom")
        return self.ok


def test_dispatch_all_succeed():
    s1, s2 = FakeSink("a"), FakeSink("b")
    f = Fanout([s1, s2], DebugConfig())
    f.dispatch("t", b"x", 1)
    assert f.delivered == 2
    assert f.dropped == 0
    assert s1.published == [("t", b"x", 1)]
    assert s2.published == [("t", b"x", 1)]


def test_dispatch_one_failing_sink_does_not_abort_others():
    s1 = FakeSink("a", ok=True)
    s2 = FakeSink("b", raise_exc=True)
    f = Fanout([s1, s2], DebugConfig())
    f.dispatch("t", b"x", 0)
    assert f.delivered == 1
    assert f.dropped == 1
    # the healthy sink still received the message
    assert s1.published == [("t", b"x", 0)]


def test_dispatch_publish_false_counts_as_drop():
    s1 = FakeSink("a", ok=False)
    f = Fanout([s1], DebugConfig())
    f.dispatch("t", b"x", 0)
    assert f.delivered == 0
    assert f.dropped == 1


def test_fake_sink_satisfies_protocol():
    assert isinstance(FakeSink("a"), SinkLike)
