import asyncio

from pega_pega.bus import EventBus
from pega_pega.models import CapturedRequest, MockRule, Protocol
from pega_pega.store import Store, store_consumer


async def test_initialize_creates_table(store):
    count = await store.count()
    assert count == 0


async def test_save_and_get_by_id(store, sample_request):
    await store.save(sample_request)
    row = await store.get_by_id("abc123")
    assert row is not None
    assert row["source_ip"] == "192.168.1.100"
    assert row["protocol"] == "HTTP"


async def test_get_by_id_not_found(store):
    row = await store.get_by_id("nonexistent")
    assert row is None


async def test_details_stored_as_json(store):
    req = CapturedRequest(id="d1", details={"key": "val"})
    await store.save(req)
    row = await store.get_by_id("d1")
    assert row["details"] == {"key": "val"}


async def test_raw_data_stored_as_hex(store):
    req = CapturedRequest(id="r1", raw_data=b"\xca\xfe")
    await store.save(req)
    row = await store.get_by_id("r1")
    assert row["raw_data"] == "cafe"


async def test_query_all(store):
    for i in range(3):
        await store.save(CapturedRequest(id=f"q{i}"))
    rows = await store.query()
    assert len(rows) == 3


async def test_query_by_protocol(store):
    await store.save(CapturedRequest(id="h1", protocol=Protocol.HTTP))
    await store.save(CapturedRequest(id="d1", protocol=Protocol.DNS))
    rows = await store.query(protocol="HTTP")
    assert len(rows) == 1
    assert rows[0]["protocol"] == "HTTP"


async def test_query_with_search(store):
    await store.save(CapturedRequest(id="s1", summary="GET /api/users"))
    await store.save(CapturedRequest(id="s2", summary="POST /login"))
    rows = await store.query(search="users")
    assert len(rows) == 1


async def test_query_limit_offset(store):
    for i in range(10):
        await store.save(CapturedRequest(
            id=f"p{i}",
            timestamp=f"2025-01-{i+1:02d}T00:00:00+00:00",
        ))
    rows = await store.query(limit=3, offset=0)
    assert len(rows) == 3
    rows2 = await store.query(limit=3, offset=3)
    assert len(rows2) == 3
    assert rows[0]["id"] != rows2[0]["id"]


async def test_query_ordered_desc(store):
    await store.save(CapturedRequest(id="t1", timestamp="2025-01-01T00:00:00+00:00"))
    await store.save(CapturedRequest(id="t3", timestamp="2025-01-03T00:00:00+00:00"))
    await store.save(CapturedRequest(id="t2", timestamp="2025-01-02T00:00:00+00:00"))
    rows = await store.query()
    assert rows[0]["id"] == "t3"
    assert rows[1]["id"] == "t2"
    assert rows[2]["id"] == "t1"


async def test_count_total(store):
    for i in range(5):
        await store.save(CapturedRequest(id=f"c{i}"))
    assert await store.count() == 5


async def test_count_by_protocol(store):
    for i in range(3):
        await store.save(CapturedRequest(id=f"h{i}", protocol=Protocol.HTTP))
    for i in range(2):
        await store.save(CapturedRequest(id=f"d{i}", protocol=Protocol.DNS))
    assert await store.count(protocol="HTTP") == 3
    assert await store.count(protocol="DNS") == 2


async def test_store_consumer_saves_events(tmp_path):
    bus = EventBus()
    s = Store(tmp_path / "consumer.db")
    await s.initialize()

    task = asyncio.create_task(store_consumer(bus, s))
    await asyncio.sleep(0)  # let consumer start and subscribe
    req = CapturedRequest(id="sc1", protocol=Protocol.FTP)
    await bus.publish(req)
    # Give the consumer + executor time to process
    for _ in range(20):
        await asyncio.sleep(0.05)
        row = await s.get_by_id("sc1")
        if row is not None:
            break

    row = await s.get_by_id("sc1")
    assert row is not None
    assert row["protocol"] == "FTP"

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await s.close()


# ── Mock rules ────────────────────────────────────────────────────


async def test_save_and_list_mock_rules(store):
    rule = MockRule(id="r1", path="/api/test", method="GET", status_code=200)
    await store.save_mock_rule(rule)
    rules = await store.list_mock_rules()
    assert len(rules) == 1
    assert rules[0]["path"] == "/api/test"


async def test_get_mock_rule(store):
    rule = MockRule(id="r2", path="/api/data", method="POST", status_code=201)
    await store.save_mock_rule(rule)
    r = await store.get_mock_rule("r2")
    assert r is not None
    assert r["method"] == "POST"
    assert r["status_code"] == 201


async def test_get_mock_rule_not_found(store):
    r = await store.get_mock_rule("nonexistent")
    assert r is None


async def test_delete_mock_rule(store):
    rule = MockRule(id="r3", path="/api/x")
    await store.save_mock_rule(rule)
    await store.delete_mock_rule("r3")
    assert await store.get_mock_rule("r3") is None


async def test_mock_rules_ordered_by_priority(store):
    await store.save_mock_rule(MockRule(id="a", path="/a", priority=2))
    await store.save_mock_rule(MockRule(id="b", path="/b", priority=0))
    await store.save_mock_rule(MockRule(id="c", path="/c", priority=1))
    rules = await store.list_mock_rules()
    assert [r["id"] for r in rules] == ["b", "c", "a"]


async def test_mock_rule_headers_stored_as_json(store):
    rule = MockRule(id="h1", path="/h", headers={"X-Custom": "val"})
    await store.save_mock_rule(rule)
    r = await store.get_mock_rule("h1")
    assert r["headers"] == {"X-Custom": "val"}


# ── Delete requests ──────────────────────────────────────────────


async def test_delete_request(store, sample_request):
    await store.save(sample_request)
    assert await store.get_by_id("abc123") is not None
    result = await store.delete_request("abc123")
    assert result is True
    assert await store.get_by_id("abc123") is None


async def test_delete_request_not_found(store):
    result = await store.delete_request("nonexistent")
    assert result is False


async def test_delete_all_requests(store):
    for i in range(5):
        await store.save(CapturedRequest(id=f"del{i}"))
    assert await store.count() == 5
    count = await store.delete_all_requests()
    assert count == 5
    assert await store.count() == 0


# ── Blocked IPs ──────────────────────────────────────────────────


async def test_add_and_list_blocked_ips(store):
    await store.add_blocked_ip("10.0.0.1")
    await store.add_blocked_ip("10.0.0.2")
    ips = await store.list_blocked_ips()
    assert len(ips) == 2
    assert {ip["ip"] for ip in ips} == {"10.0.0.1", "10.0.0.2"}


async def test_is_ip_blocked(store):
    assert await store.is_ip_blocked("10.0.0.1") is False
    await store.add_blocked_ip("10.0.0.1")
    assert await store.is_ip_blocked("10.0.0.1") is True


async def test_remove_blocked_ip(store):
    await store.add_blocked_ip("10.0.0.1")
    result = await store.remove_blocked_ip("10.0.0.1")
    assert result is True
    assert await store.is_ip_blocked("10.0.0.1") is False


async def test_remove_blocked_ip_not_found(store):
    result = await store.remove_blocked_ip("10.0.0.1")
    assert result is False


async def test_blocked_ip_filtered_from_query(store):
    await store.save(CapturedRequest(id="b1", source_ip="10.0.0.1"))
    await store.save(CapturedRequest(id="b2", source_ip="10.0.0.2"))
    await store.add_blocked_ip("10.0.0.1")
    rows = await store.query()
    assert len(rows) == 1
    assert rows[0]["source_ip"] == "10.0.0.2"


async def test_blocked_ip_filtered_from_count(store):
    await store.save(CapturedRequest(id="c1", source_ip="10.0.0.1", protocol=Protocol.HTTP))
    await store.save(CapturedRequest(id="c2", source_ip="10.0.0.2", protocol=Protocol.HTTP))
    await store.add_blocked_ip("10.0.0.1")
    assert await store.count() == 1
    assert await store.count(protocol="HTTP") == 1
