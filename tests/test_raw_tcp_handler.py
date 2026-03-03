from pega_pega.config import ProtocolConfig
from pega_pega.models import Protocol
from pega_pega.protocols.raw_tcp_handler import RawTcpHandler


async def test_captures_data(make_stream_pair, default_config, event_bus):
    reader, writer = make_stream_pair(b"\xde\xad\xbe\xef")

    handler = RawTcpHandler(
        ProtocolConfig(port=9999, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_client(reader, writer)

    event = q.get_nowait()
    assert event.protocol == Protocol.RAW_TCP
    assert event.raw_data == b"\xde\xad\xbe\xef"
    assert event.details["length"] == 4


async def test_empty_data_no_event(make_stream_pair, default_config, event_bus):
    reader, writer = make_stream_pair(b"")

    handler = RawTcpHandler(
        ProtocolConfig(port=9999, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_client(reader, writer)

    assert q.empty()


async def test_source_ip_extracted(make_stream_pair, default_config, event_bus):
    reader, writer = make_stream_pair(b"data", peername=("10.10.10.10", 5555))

    handler = RawTcpHandler(
        ProtocolConfig(port=9999, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_client(reader, writer)

    event = q.get_nowait()
    assert event.source_ip == "10.10.10.10"
    assert event.source_port == 5555


async def test_hex_preview(make_stream_pair, default_config, event_bus):
    data = bytes(range(256)) * 2  # 512 bytes
    reader, writer = make_stream_pair(data)

    handler = RawTcpHandler(
        ProtocolConfig(port=9999, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_client(reader, writer)

    event = q.get_nowait()
    # hex_preview is first 256 bytes as hex = 512 hex chars
    assert len(event.details["hex_preview"]) == 512
