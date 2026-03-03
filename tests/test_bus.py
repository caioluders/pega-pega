import asyncio

from pega_pega.bus import EventBus
from pega_pega.models import CapturedRequest


async def test_subscribe_returns_queue(event_bus):
    q = event_bus.subscribe()
    assert isinstance(q, asyncio.Queue)


async def test_publish_delivers_to_subscriber(event_bus, sample_request):
    q = event_bus.subscribe()
    await event_bus.publish(sample_request)
    event = q.get_nowait()
    assert event is sample_request


async def test_fan_out_to_multiple(event_bus, sample_request):
    q1 = event_bus.subscribe()
    q2 = event_bus.subscribe()
    await event_bus.publish(sample_request)
    assert q1.get_nowait() is sample_request
    assert q2.get_nowait() is sample_request


async def test_unsubscribe_stops_delivery(event_bus, sample_request):
    q = event_bus.subscribe()
    event_bus.unsubscribe(q)
    await event_bus.publish(sample_request)
    assert q.empty()


async def test_unsubscribe_nonexistent_noop(event_bus):
    event_bus.unsubscribe(asyncio.Queue())  # no exception


async def test_events_ordered(event_bus):
    q = event_bus.subscribe()
    for i in range(5):
        await event_bus.publish(CapturedRequest(id=str(i)))
    ids = [q.get_nowait().id for _ in range(5)]
    assert ids == ["0", "1", "2", "3", "4"]


async def test_publish_no_subscribers(event_bus, sample_request):
    await event_bus.publish(sample_request)  # no exception
