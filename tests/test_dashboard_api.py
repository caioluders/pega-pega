import subprocess

import httpx
import pytest_asyncio

from pega_pega.dashboard.app import create_app
from pega_pega.models import CapturedRequest, Protocol


@pytest_asyncio.fixture
async def client(store, event_bus, custom_config):
    app = create_app(store, event_bus, custom_config)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_index_html(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "PEGA-PEGA" in resp.text


async def test_list_requests_empty(client):
    resp = await client.get("/api/requests")
    data = resp.json()
    assert data["requests"] == []
    assert data["total"] == 0


async def test_list_requests_with_data(client, store, sample_request):
    await store.save(sample_request)
    resp = await client.get("/api/requests")
    assert len(resp.json()["requests"]) == 1


async def test_list_requests_filter_protocol(client, store):
    await store.save(CapturedRequest(id="h1", protocol=Protocol.HTTP))
    await store.save(CapturedRequest(id="d1", protocol=Protocol.DNS))
    resp = await client.get("/api/requests?protocol=HTTP")
    rows = resp.json()["requests"]
    assert len(rows) == 1
    assert rows[0]["protocol"] == "HTTP"


async def test_list_requests_invalid_protocol(client):
    resp = await client.get("/api/requests?protocol=BOGUS")
    assert resp.status_code == 400


async def test_list_requests_search(client, store, sample_request):
    await store.save(sample_request)
    resp = await client.get("/api/requests?search=hello")
    assert len(resp.json()["requests"]) == 1


async def test_list_requests_pagination(client, store):
    for i in range(5):
        await store.save(CapturedRequest(id=f"p{i}"))
    resp = await client.get("/api/requests?limit=2&offset=0")
    assert len(resp.json()["requests"]) == 2


async def test_get_request_by_id(client, store, sample_request):
    await store.save(sample_request)
    resp = await client.get(f"/api/requests/{sample_request.id}")
    assert resp.status_code == 200
    assert resp.json()["source_ip"] == "192.168.1.100"


async def test_get_request_not_found(client):
    resp = await client.get("/api/requests/nonexistent")
    assert resp.status_code == 404


async def test_stats(client, store):
    await store.save(CapturedRequest(id="h1", protocol=Protocol.HTTP))
    await store.save(CapturedRequest(id="h2", protocol=Protocol.HTTP))
    await store.save(CapturedRequest(id="d1", protocol=Protocol.DNS))
    resp = await client.get("/api/stats")
    data = resp.json()
    assert data["total"] == 3
    assert data["protocols"]["HTTP"] == 2


async def test_get_config(client):
    resp = await client.get("/api/config")
    data = resp.json()
    assert data["domain"] == "test.example.com"
    assert "_version" in data


async def test_put_config(client, custom_config, monkeypatch):
    # Mock subprocess to avoid real systemctl call
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 1, "", ""),
    )
    resp = await client.put("/api/config", json={"domain": "new.domain.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "saved"


async def test_letsencrypt_status(client, monkeypatch):
    monkeypatch.setattr("pega_pega.letsencrypt.certbot_available", lambda: False)
    monkeypatch.setattr("pega_pega.letsencrypt.le_certs_exist", lambda d: False)
    monkeypatch.setattr("pega_pega.letsencrypt.get_cert_expiry", lambda d: None)
    resp = await client.get("/api/letsencrypt/status")
    data = resp.json()
    assert data["certbot_available"] is False
    assert data["certificate_exists"] is False
