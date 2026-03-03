from pathlib import Path

from pega_pega.config import ProtocolConfig
from pega_pega.mock import MockMatcher
from pega_pega.models import Protocol
from pega_pega.protocols.http_handler import HttpHandler


def test_build_response_get_html():
    resp = HttpHandler._build_response("GET", "HTTP/1.1", "/")
    assert b"200 OK" in resp
    assert b"text/html" in resp


def test_build_response_post_json():
    resp = HttpHandler._build_response("POST", "HTTP/1.1", "/api")
    assert b"application/json" in resp
    assert b'{"status":"ok"}' in resp


def test_build_response_acme_found(tmp_path, monkeypatch):
    import pega_pega.protocols.http_handler as mod
    monkeypatch.setattr(mod, "ACME_WEBROOT", tmp_path)

    challenge_dir = tmp_path / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "testtoken").write_text("challenge-response-data")

    resp = HttpHandler._build_response("GET", "HTTP/1.1", "/.well-known/acme-challenge/testtoken")
    assert b"200 OK" in resp
    assert b"challenge-response-data" in resp
    assert b"text/plain" in resp


def test_build_response_acme_missing():
    resp = HttpHandler._build_response("GET", "HTTP/1.1", "/.well-known/acme-challenge/missing")
    # Falls through to normal HTML response
    assert b"text/html" in resp


async def test_handle_connection_get(make_stream_pair, default_config, event_bus):
    raw = b"GET /test HTTP/1.1\r\nHost: foo.pega.local\r\nConnection: close\r\n\r\n"
    reader, writer = make_stream_pair(raw)

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_connection(reader, writer)

    event = q.get_nowait()
    assert event.protocol == Protocol.HTTP
    assert event.summary == "GET /test"
    assert event.details["method"] == "GET"
    assert event.subdomain == "foo"


async def test_handle_connection_post_body(make_stream_pair, default_config, event_bus):
    raw = b"POST /data HTTP/1.1\r\nHost: pega.local\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    reader, writer = make_stream_pair(raw)

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_connection(reader, writer)

    event = q.get_nowait()
    assert event.details["body"] == "hello"


async def test_handle_connection_subdomain(make_stream_pair, default_config, event_bus):
    raw = b"GET / HTTP/1.1\r\nHost: sub.domain.pega.local\r\nConnection: close\r\n\r\n"
    reader, writer = make_stream_pair(raw)

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_connection(reader, writer)

    event = q.get_nowait()
    assert event.subdomain == "sub.domain"


async def test_handle_connection_empty_data(make_stream_pair, default_config, event_bus):
    reader, writer = make_stream_pair(b"")

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    q = event_bus.subscribe()
    await handler._handle_connection(reader, writer)

    assert q.empty()


async def test_mock_response_served(make_stream_pair, default_config, event_bus):
    raw = b"GET /api/mock-test HTTP/1.1\r\nHost: pega.local\r\nConnection: close\r\n\r\n"
    reader, writer = make_stream_pair(raw)

    handler = HttpHandler(
        ProtocolConfig(port=80, bind="127.0.0.1"),
        default_config,
        event_bus,
    )
    handler.mock_matcher = MockMatcher([{
        "path": "/api/mock-test",
        "method": "GET",
        "status_code": 418,
        "response_body": '{"tea":"pot"}',
        "content_type": "application/json",
        "headers": {"X-Mock": "true"},
        "enabled": True,
        "priority": 0,
    }])
    q = event_bus.subscribe()
    await handler._handle_connection(reader, writer)

    # Request still captured
    event = q.get_nowait()
    assert event.protocol == Protocol.HTTP
    assert event.summary == "GET /api/mock-test"

    # Mock response served
    written = b"".join(call.args[0] for call in writer.write.call_args_list)
    assert b"418" in written
    assert b'{"tea":"pot"}' in written
    assert b"X-Mock: true" in written


def test_build_mock_response():
    rule = {
        "status_code": 201,
        "response_body": '{"created":true}',
        "content_type": "application/json",
        "headers": {"Location": "/api/items/1"},
    }
    resp = HttpHandler._build_mock_response(rule, "HTTP/1.1")
    assert b"201 Created" in resp
    assert b'{"created":true}' in resp
    assert b"Location: /api/items/1" in resp
