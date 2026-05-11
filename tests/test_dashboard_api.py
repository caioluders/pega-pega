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


# ── Mock rules API tests ─────────────────────────────────────────────


async def test_mock_rules_list_empty(client):
    resp = await client.get("/api/mock-rules")
    assert resp.status_code == 200
    assert resp.json()["rules"] == []


async def test_mock_rules_create(client):
    resp = await client.post("/api/mock-rules", json={
        "path": "/api/test",
        "method": "GET",
        "status_code": 200,
        "response_body": '{"ok":true}',
        "content_type": "application/json",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["path"] == "/api/test"
    assert data["id"]


async def test_mock_rules_create_and_list(client):
    await client.post("/api/mock-rules", json={"path": "/a"})
    await client.post("/api/mock-rules", json={"path": "/b"})
    resp = await client.get("/api/mock-rules")
    assert len(resp.json()["rules"]) == 2


async def test_mock_rules_update(client):
    create_resp = await client.post("/api/mock-rules", json={"path": "/old"})
    rule_id = create_resp.json()["id"]
    resp = await client.put(f"/api/mock-rules/{rule_id}", json={"path": "/new"})
    assert resp.status_code == 200
    assert resp.json()["path"] == "/new"


async def test_mock_rules_update_not_found(client):
    resp = await client.put("/api/mock-rules/nonexistent", json={"path": "/x"})
    assert resp.status_code == 404


async def test_mock_rules_delete(client):
    create_resp = await client.post("/api/mock-rules", json={"path": "/del"})
    rule_id = create_resp.json()["id"]
    resp = await client.delete(f"/api/mock-rules/{rule_id}")
    assert resp.status_code == 200
    # Verify deleted
    list_resp = await client.get("/api/mock-rules")
    assert all(r["id"] != rule_id for r in list_resp.json()["rules"])


async def test_mock_rules_delete_not_found(client):
    resp = await client.delete("/api/mock-rules/nonexistent")
    assert resp.status_code == 404


async def test_mock_rules_reorder(client):
    r1 = (await client.post("/api/mock-rules", json={"path": "/first", "priority": 0})).json()
    r2 = (await client.post("/api/mock-rules", json={"path": "/second", "priority": 1})).json()
    # Reverse order
    resp = await client.post("/api/mock-rules/reorder", json={"order": [r2["id"], r1["id"]]})
    assert resp.status_code == 200
    rules = (await client.get("/api/mock-rules")).json()["rules"]
    assert rules[0]["id"] == r2["id"]
    assert rules[1]["id"] == r1["id"]


async def test_mock_page_accessible(client):
    resp = await client.get("/mock")
    assert resp.status_code == 200
    assert "Mock" in resp.text


# ── Delete request API tests ─────────────────────────────────────


async def test_delete_request(client, store, sample_request):
    await store.save(sample_request)
    resp = await client.delete(f"/api/requests/{sample_request.id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "deleted"
    # Verify deleted
    resp2 = await client.get(f"/api/requests/{sample_request.id}")
    assert resp2.status_code == 404


async def test_delete_request_not_found(client):
    resp = await client.delete("/api/requests/nonexistent")
    assert resp.status_code == 404


async def test_delete_all_requests(client, store):
    for i in range(3):
        await store.save(CapturedRequest(id=f"d{i}"))
    resp = await client.delete("/api/requests")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "deleted"
    assert data["count"] == 3
    # Verify empty
    resp2 = await client.get("/api/requests")
    assert resp2.json()["total"] == 0


# ── Blocked IPs API tests ────────────────────────────────────────


async def test_block_ip(client):
    resp = await client.post("/api/blocked-ips", json={"ip": "10.0.0.1"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "blocked"


async def test_block_ip_missing(client):
    resp = await client.post("/api/blocked-ips", json={})
    assert resp.status_code == 400


async def test_list_blocked_ips(client):
    await client.post("/api/blocked-ips", json={"ip": "10.0.0.1"})
    await client.post("/api/blocked-ips", json={"ip": "10.0.0.2"})
    resp = await client.get("/api/blocked-ips")
    assert resp.status_code == 200
    assert len(resp.json()["blocked_ips"]) == 2


async def test_unblock_ip(client):
    await client.post("/api/blocked-ips", json={"ip": "10.0.0.1"})
    resp = await client.delete("/api/blocked-ips/10.0.0.1")
    assert resp.status_code == 200
    assert resp.json()["status"] == "unblocked"


async def test_unblock_ip_not_found(client):
    resp = await client.delete("/api/blocked-ips/10.0.0.1")
    assert resp.status_code == 404


async def test_blocked_ip_hides_requests(client, store):
    await store.save(CapturedRequest(id="h1", source_ip="10.0.0.1"))
    await store.save(CapturedRequest(id="h2", source_ip="10.0.0.2"))
    await client.post("/api/blocked-ips", json={"ip": "10.0.0.1"})
    resp = await client.get("/api/requests")
    data = resp.json()
    assert data["total"] == 1
    assert data["requests"][0]["source_ip"] == "10.0.0.2"


# ── File upload tests ────────────────────────────────────────────


async def test_upload_file(client):
    content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    resp = await client.post(
        "/api/mock-rules/upload",
        files={"file": ("test.png", content, "image/png")},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["original_name"] == "test.png"
    assert data["size"] == len(content)
    assert "data_b64" in data


async def test_mock_rule_with_file_data(client):
    import base64
    content = b'{"uploaded": true}'
    b64 = base64.b64encode(content).decode()

    resp = await client.post("/api/mock-rules", json={
        "path": "/api/file-test",
        "method": "GET",
        "status_code": 200,
        "content_type": "application/json",
        "response_file": "data.json",
        "response_file_data_b64": b64,
    })
    assert resp.status_code == 200
    assert resp.json()["response_file"] == "data.json"


async def test_mock_rules_list_with_file_data(client):
    import base64
    content = b"\x89PNG\r\n"
    b64 = base64.b64encode(content).decode()

    await client.post("/api/mock-rules", json={
        "path": "/api/file-list",
        "response_file": "image.png",
        "response_file_data_b64": b64,
    })
    resp = await client.get("/api/mock-rules")
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["response_file"] == "image.png"
    assert "response_file_data" not in rule


async def test_serve_file_from_rule(client, store):
    import base64
    content = b"hello world"
    b64 = base64.b64encode(content).decode()

    create_resp = await client.post("/api/mock-rules", json={
        "path": "/api/serve-test",
        "response_file": "test.txt",
        "response_file_data_b64": b64,
        "content_type": "text/plain",
    })
    rule_id = create_resp.json()["id"]
    resp = await client.get(f"/api/mock-rules/uploads/{rule_id}")
    assert resp.status_code == 200
    assert resp.content == content


async def test_serve_upload_not_found(client):
    resp = await client.get("/api/mock-rules/uploads/nonexistent")
    assert resp.status_code == 404
