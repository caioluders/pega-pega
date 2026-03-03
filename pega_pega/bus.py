import asyncio

from .models import CapturedRequest


class EventBus:
    """Fan-out async event bus. Producers call publish(), consumers subscribe()."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def publish(self, event: CapturedRequest):
        for q in self._subscribers:
            await q.put(event)
