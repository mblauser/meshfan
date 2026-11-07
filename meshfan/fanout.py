"""Fan-out: deliver each source message to every sink."""
from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from .config import DebugConfig
from .log import sanitize

log = logging.getLogger("meshfan.fanout")


@runtime_checkable
class SinkLike(Protocol):
    """The sink contract Fanout needs: publish + a name for logging."""

    broker: object

    def publish(self, topic: str, payload: bytes, qos: int = 0) -> bool: ...


class Fanout:
    def __init__(self, sinks: list[SinkLike], debug: DebugConfig) -> None:
        self.sinks = sinks
        self.debug = debug
        self.delivered = 0
        self.dropped = 0

    def dispatch(self, topic: str, payload: bytes, qos: int = 0) -> None:
        # Guard each sink so one failure cannot abort delivery to the rest,
        # and cannot propagate into the source's on_message callback.
        for sink in self.sinks:
            try:
                if sink.publish(topic, payload, qos):
                    self.delivered += 1
                else:
                    self.dropped += 1
            except Exception:
                self.dropped += 1
                log.debug("fanout: sink %s raised", sink.broker.name, exc_info=True)
        if self.debug.messages:
            log.debug(
                "dispatched %s to %d sink(s)", sanitize(topic, 200), len(self.sinks)
            )
