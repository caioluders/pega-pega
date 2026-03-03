import subprocess

import httpx
import pytest
import pytest_asyncio

from pega_pega.config import Config
from pega_pega.dashboard.app import create_app
from pega_pega.models import CapturedRequest, Protocol


@pytest_asyncio.fixture
async def client(store, event_bus, custom_config):
    app = create_app(store, event_bus, custom_config)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_config(tmp_path):
    cfg = Config(
        domain="test.example.com",
        response_ip="10.0.0.1",
        dashboard_port=9999,
        dashboard_password="s3cret",
        db_path=str(tmp_path / "test.db"),
    )
    cfg._source_path = tmp_path / "config.yaml"
    return cfg


@pytest_asyncio.fixture
async def auth_client(store, event_bus, auth_config):
    app = create_app(store, event_bus, auth_config)
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


async def test_get_config_hides_password(client):
    resp = await client.get("/api/config")
    data = resp.json()
    assert "dashboard_password" not in data
    assert "password_set" in data


# ── Auth tests ────────────────────────────────────────────────────────


async def test_no_password_no_auth_required(client):
    """When dashboard_password is empty, all routes are open."""
    resp = await client.get("/api/requests")
    assert resp.status_code == 200


async def test_auth_api_returns_401(auth_client):
    """When password is set, API calls without session get 401."""
    resp = await auth_client.get("/api/requests")
    assert resp.status_code == 401


async def test_auth_index_redirects_to_login(auth_client):
    """When password is set, GET / redirects to /login."""
    resp = await auth_client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert "/login" in resp.headers["location"]


async def test_login_page_accessible(auth_client):
    """Login page is always accessible even without auth."""
    resp = await auth_client.get("/login")
    assert resp.status_code == 200
    assert "PEGA-PEGA" in resp.text


async def test_login_wrong_password(auth_client):
    resp = await auth_client.post(
        "/api/auth/login", json={"password": "wrong"}
    )
    assert resp.status_code == 401


async def test_login_correct_password(auth_client):
    resp = await auth_client.post(
        "/api/auth/login", json={"password": "s3cret"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert "session" in resp.cookies


async def test_authenticated_request(auth_client):
    """After login, API routes should work with the session cookie."""
    login_resp = await auth_client.post(
        "/api/auth/login", json={"password": "s3cret"}
    )
    session_cookie = login_resp.cookies["session"]

    resp = await auth_client.get(
        "/api/requests",
        cookies={"session": session_cookie},
    )
    assert resp.status_code == 200


async def test_logout_clears_session(auth_client):
    """After logout, session cookie is invalid."""
    login_resp = await auth_client.post(
        "/api/auth/login", json={"password": "s3cret"}
    )
    session_cookie = login_resp.cookies["session"]

    await auth_client.post(
        "/api/auth/logout",
        cookies={"session": session_cookie},
    )

    resp = await auth_client.get(
        "/api/requests",
        cookies={"session": session_cookie},
    )
    assert resp.status_code == 401
