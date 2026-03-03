import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from pega_pega.bus import EventBus
from pega_pega.config import Config, ProtocolConfig, LetsEncryptConfig
from pega_pega.models import CapturedRequest, Protocol
from pega_pega.store import Store


@pytest.fixture
def sample_request():
    return CapturedRequest(
        id="abc123",
        timestamp="2025-01-01T00:00:00+00:00",
        protocol=Protocol.HTTP,
        source_ip="192.168.1.100",
        source_port=54321,
        dest_port=80,
        subdomain="test",
        summary="GET /hello",
        details={"method": "GET", "path": "/hello"},
        raw_data=b"GET /hello HTTP/1.1\r\n",
    )


@pytest.fixture
def default_config():
    return Config()


@pytest.fixture
def custom_config(tmp_path):
    cfg = Config(
        domain="test.example.com",
        response_ip="10.0.0.1",
        dashboard_port=9999,
        db_path=str(tmp_path / "test.db"),
    )
    cfg._source_path = tmp_path / "config.yaml"
    return cfg


@pytest.fixture
def event_bus():
    return EventBus()


@pytest_asyncio.fixture
async def store(tmp_path):
    s = Store(tmp_path / "test.db")
    await s.initialize()
    yield s
    await s.close()


@pytest.fixture
def make_stream_pair():
    def _factory(data: bytes = b"", peername=("127.0.0.1", 12345)):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        writer = MagicMock()
        writer.get_extra_info = MagicMock(return_value=peername)
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        return reader, writer

    return _factory
