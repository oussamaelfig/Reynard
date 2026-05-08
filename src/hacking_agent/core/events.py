"""Runtime event stream for the live dashboard and observability hooks."""
from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuntimeEvent:
    id: int
    type: str
    payload: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "ts": self.ts,
            "payload": self.payload,
        }

    def to_sse(self) -> bytes:
        body = json.dumps(self.to_dict(), ensure_ascii=False)
        return f"id: {self.id}\nevent: {self.type}\ndata: {body}\n\n".encode("utf-8")


class EventBus:
    """Thread-safe pub/sub bus with bounded replay history."""

    def __init__(self, history_limit: int = 2000):
        self._lock = threading.RLock()
        self._history: deque[RuntimeEvent] = deque(maxlen=history_limit)
        self._subscribers: set[queue.Queue[RuntimeEvent]] = set()
        self._next_id = 1

    def emit(self, event_type: str, payload: dict[str, Any] | None = None) -> RuntimeEvent:
        with self._lock:
            event = RuntimeEvent(self._next_id, event_type, payload or {})
            self._next_id += 1
            self._history.append(event)
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                pass
        return event

    def history_since(self, last_id: int = 0) -> list[RuntimeEvent]:
        with self._lock:
            return [event for event in self._history if event.id > last_id]

    def subscribe(self, last_id: int = 0, max_queue: int = 500) -> queue.Queue[RuntimeEvent]:
        q: queue.Queue[RuntimeEvent] = queue.Queue(maxsize=max_queue)
        with self._lock:
            for event in self._history:
                if event.id > last_id:
                    try:
                        q.put_nowait(event)
                    except queue.Full:
                        break
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: queue.Queue[RuntimeEvent]) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            return [event.to_dict() for event in self._history]


GLOBAL_EVENT_BUS = EventBus()


def emit(event_type: str, payload: dict[str, Any] | None = None) -> RuntimeEvent:
    return GLOBAL_EVENT_BUS.emit(event_type, payload)


def get_event_bus() -> EventBus:
    return GLOBAL_EVENT_BUS
