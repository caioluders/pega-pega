import asyncio

from pega_pega.bus import EventBus
from pega_pega.config import Config, ProtocolConfig
from pega_pega.models import CapturedRequest, Protocol
from pega_pega.protocols import HANDLER_REGISTRY
from pega_pega.protocols.http_handler import HttpHandler
from pega_pega.store import Store, store_consumer


async def test_bus_to_store_pipeline(tmp_path):
    bus = EventBus()
    store = Store(tmp_path / "int.db")
    await store.initialize()

    task = asyncio.create_task(store_consumer(bus, store))
    await asyncio.sleep(0)  # let consumer start and subscribe

    for i in range(3):
        await bus.publish(CapturedRequest(id=f"int{i}", protocol=Protocol.HTTP))

    for _ in range(20):
        await asyncio.sleep(0.05)
        if await store.count() == 3:
            break

    assert await store.count() == 3

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await store.close()


async def test_http_handler_to_store(tmp_path):
    bus = EventBus()
    store = Store(tmp_path / "http_int.db")
    await store.initialize()
    config = Config()

    consumer_task = asyncio.create_task(store_consumer(bus, store))
    await asyncio.sleep(0)  # let consumer start and subscribe

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        config,
        bus,
    )

    reader = asyncio.StreamReader()
    reader.feed_data(b"GET /integration HTTP/1.1\r\nHost: test.pega.local\r\nConnection: close\r\n\r\n")
    reader.feed_eof()

    from unittest.mock import MagicMock, AsyncMock
    writer = MagicMock()
    writer.get_extra_info = MagicMock(return_value=("10.0.0.1", 9999))
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    await handler._handle_connection(reader, writer)

    for _ in range(20):
        await asyncio.sleep(0.05)
        rows = await store.query(search="integration")
        if len(rows) == 1:
            break

    rows = await store.query(search="integration")
    assert len(rows) == 1
    assert rows[0]["subdomain"] == "test"

    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    await store.close()


def test_config_roundtrip(tmp_path):
    cfg = Config(domain="round.trip", response_ip="1.2.3.4")
    cfg._source_path = tmp_path / "rt.yaml"
    cfg.save()
    cfg2 = Config.load(tmp_path / "rt.yaml")
    assert cfg2.domain == "round.trip"
    assert cfg2.response_ip == "1.2.3.4"


def test_handler_registry_complete():
    assert len(HANDLER_REGISTRY) == 14
    expected = {
        "http", "https", "dns", "ftp", "smtp", "pop3", "imap",
        "ssh", "telnet", "ldap", "mysql", "raw_tcp", "snmp", "syslog",
    }
    assert set(HANDLER_REGISTRY.keys()) == expected
