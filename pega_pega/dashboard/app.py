"""FastAPI web dashboard for pega-pega."""

from __future__ import annotations

import asyncio
import json
import secrets
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, UploadFile, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .. import __version__
from ..bus import EventBus
from ..config import Config
from ..filters import FilterConfig, RequestFilter
from ..mock import MockMatcher
from ..models import MockRule, Protocol
from ..store import Store

# ── Directory resolution (relative to *this* file) ───────────────────
_HERE = Path(__file__).resolve().parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"


def create_app(
    store: Store,
    bus: EventBus,
    config: Config | None = None,
    mock_matcher: MockMatcher | None = None,
    request_filter: RequestFilter | None = None,
) -> FastAPI:
    """Factory that wires the dashboard to a shared Store and EventBus."""

    app = FastAPI(
        title="PEGA-PEGA Dashboard",
        docs_url=None,
        redoc_url=None,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # ── Session store ────────────────────────────────────────────────
    _sessions: set[str] = set()

    def _password_required() -> bool:
        return bool(config and config.dashboard_password)

    def _is_authenticated(request: Request) -> bool:
        token = request.cookies.get("session")
        return token is not None and token in _sessions

    # ── Auth middleware ───────────────────────────────────────────────
    _PUBLIC_PATHS = {"/login", "/api/auth/login"}
    _PUBLIC_PREFIXES = ("/static/",)

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            if not _password_required():
                return await call_next(request)

            path = request.url.path
            if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
                return await call_next(request)

            if _is_authenticated(request):
                return await call_next(request)

            # API calls get 401; browsers get redirected to /login
            if path.startswith("/api/") or path == "/ws":
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
            return RedirectResponse("/login", status_code=302)

    app.add_middleware(AuthMiddleware)

    # Mount static assets ─────────────────────────────────────────────
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Auth endpoints ───────────────────────────────────────────────

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        if not _password_required():
            return RedirectResponse("/", status_code=302)
        return templates.TemplateResponse(request, "login.html")

    @app.post("/api/auth/login")
    async def auth_login(request: Request):
        if not _password_required():
            return {"status": "ok"}

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        password = body.get("password", "")
        if password == config.dashboard_password:
            token = secrets.token_urlsafe(32)
            _sessions.add(token)
            resp = JSONResponse({"status": "ok"})
            resp.set_cookie("session", token, httponly=True, samesite="lax")
            return resp

        return JSONResponse({"error": "Wrong password"}, status_code=401)

    @app.post("/api/auth/logout")
    async def auth_logout(request: Request):
        token = request.cookies.get("session")
        if token:
            _sessions.discard(token)
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie("session")
        return resp

    # ── HTML ─────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse(request, "index.html")

    # ── REST API ─────────────────────────────────────────────────────

    @app.get("/api/requests")
    async def list_requests(
        protocol: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        search: Optional[str] = Query(None),
    ):
        # Validate protocol if provided
        if protocol:
            protocol = protocol.upper()
            valid = {p.value for p in Protocol}
            if protocol not in valid:
                return JSONResponse(
                    {"error": f"Unknown protocol: {protocol}"},
                    status_code=400,
                )

        rows = await store.query(
            protocol=protocol,
            limit=limit,
            offset=offset,
            search=search,
        )
        total = await store.count(protocol=protocol, search=search)
        return {"requests": rows, "total": total}

    @app.get("/api/requests/{request_id}")
    async def get_request(request_id: str):
        row = await store.get_by_id(request_id)
        if row is None:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return row

    @app.delete("/api/requests/{request_id}")
    async def delete_request(request_id: str):
        deleted = await store.delete_request(request_id)
        if not deleted:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return {"status": "deleted"}

    @app.delete("/api/requests")
    async def delete_all_requests():
        count = await store.delete_all_requests()
        return {"status": "deleted", "count": count}

    # ── Blocked IPs API ───────────────────────────────────────────────

    @app.get("/api/blocked-ips")
    async def list_blocked_ips():
        ips = await store.list_blocked_ips()
        return {"blocked_ips": ips}

    @app.post("/api/blocked-ips")
    async def block_ip(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)
        ip = body.get("ip", "").strip()
        if not ip:
            return JSONResponse({"error": "ip is required"}, status_code=400)
        await store.add_blocked_ip(ip)
        return {"status": "blocked", "ip": ip}

    @app.delete("/api/blocked-ips/{ip:path}")
    async def unblock_ip(ip: str):
        removed = await store.remove_blocked_ip(ip)
        if not removed:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return {"status": "unblocked", "ip": ip}

    @app.get("/api/stats")
    async def stats():
        counts = await store.count_by_protocol()
        total = sum(counts.values())
        return {"protocols": counts, "total": total}

    @app.get("/api/recent-activity")
    async def recent_activity(
        minutes: int = Query(10, ge=1, le=60),
        limit: int = Query(1000, ge=1, le=5000),
    ):
        """Lightweight endpoint for sparkline data — only timestamps and protocols."""
        rows = await store.recent_activity(minutes=minutes, limit=limit)
        return {"events": rows}

    # ── Credentials API ────────────────────────────────────────────────

    @app.get("/api/credentials")
    async def list_credentials(limit: int = Query(500, ge=1, le=5000)):
        creds = await store.list_credentials(limit=limit)
        return {"credentials": creds, "total": len(creds)}

    @app.get("/credentials", response_class=HTMLResponse)
    async def credentials_page(request: Request):
        return templates.TemplateResponse(request, "credentials.html")

    # ── Filters API ──────────────────────────────────────────────────

    @app.get("/api/filters")
    async def get_filters():
        cfg = await store.get_filter_config()
        data = cfg.to_dict()
        if request_filter:
            data["auto_blocked_ips"] = request_filter.get_auto_blocked_ips()
        return data

    @app.put("/api/filters")
    async def update_filters(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        cfg = FilterConfig.from_dict(body)
        await store.save_filter_config(cfg)
        if request_filter:
            request_filter.update_config(cfg)
        return cfg.to_dict()

    @app.post("/api/filters/clear-rate-blocks")
    async def clear_rate_blocks(request: Request):
        """Clear all or a specific IP from rate-limit auto-blocks."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        ip = body.get("ip")
        if request_filter:
            request_filter.clear_auto_blocked(ip)
        return {"status": "cleared"}

    # ── Config / Settings API ────────────────────────────────────────

    @app.get("/api/config")
    async def get_config():
        if config is None:
            return JSONResponse({"error": "Config not available"}, status_code=503)
        data = config.to_dict()
        # Don't leak the actual password — just indicate if one is set
        data.pop("dashboard_password", None)
        data["password_set"] = _password_required()
        data["_version"] = __version__
        data["_source_path"] = str(config._source_path) if config._source_path else None
        return data

    @app.put("/api/config")
    async def update_config(request: Request):
        if config is None:
            return JSONResponse({"error": "Config not available"}, status_code=503)

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        save_data = config.to_dict()

        for key in ("bind_ip", "domain", "response_ip", "dashboard_host"):
            if key in body and isinstance(body[key], str):
                save_data[key] = body[key]

        if "dashboard_port" in body:
            try:
                save_data["dashboard_port"] = int(body["dashboard_port"])
            except (ValueError, TypeError):
                pass

        if "dashboard_password" in body and isinstance(body["dashboard_password"], str):
            save_data["dashboard_password"] = body["dashboard_password"]

        if "letsencrypt" in body and isinstance(body["letsencrypt"], dict):
            le = body["letsencrypt"]
            if "enabled" in le:
                save_data["letsencrypt"]["enabled"] = bool(le["enabled"])
            if "email" in le and isinstance(le["email"], str):
                save_data["letsencrypt"]["email"] = le["email"]
            if "agree_tos" in le:
                save_data["letsencrypt"]["agree_tos"] = bool(le["agree_tos"])

        if "protocols" in body and isinstance(body["protocols"], dict):
            for proto_name, proto_data in body["protocols"].items():
                if proto_name in save_data["protocols"] and isinstance(proto_data, dict):
                    if "enabled" in proto_data:
                        save_data["protocols"][proto_name]["enabled"] = bool(proto_data["enabled"])
                    if "port" in proto_data:
                        try:
                            save_data["protocols"][proto_name]["port"] = int(proto_data["port"])
                        except (ValueError, TypeError):
                            pass
                    if "extra_ports" in proto_data and isinstance(proto_data["extra_ports"], list):
                        try:
                            save_data["protocols"][proto_name]["extra_ports"] = [
                                int(p) for p in proto_data["extra_ports"]
                            ]
                        except (ValueError, TypeError):
                            pass

        try:
            save_path = config._source_path or Path("/etc/pega-pega/config.yaml")
            with open(save_path, "w") as f:
                yaml.dump(save_data, f, default_flow_style=False, sort_keys=False)
            # Auto-restart the service if running under systemd
            restarted = False
            try:
                import subprocess
                r = subprocess.run(
                    ["systemctl", "is-enabled", "--quiet", "pega-pega"],
                    capture_output=True, timeout=5,
                )
                if r.returncode == 0:
                    subprocess.Popen(
                        ["systemctl", "restart", "pega-pega"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    )
                    restarted = True
            except Exception:
                pass

            if restarted:
                return {
                    "status": "saved",
                    "path": str(save_path),
                    "message": "Config saved. Service is restarting...",
                    "restarting": True,
                }
            return {
                "status": "saved",
                "path": str(save_path),
                "message": "Config saved. Restart pega-pega for changes to take effect.",
                "restarting": False,
            }
        except PermissionError:
            return JSONResponse(
                {"error": f"Permission denied writing to {save_path}"},
                status_code=403,
            )
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ── Let's Encrypt API ────────────────────────────────────────────

    @app.get("/api/letsencrypt/status")
    async def le_status():
        from ..letsencrypt import certbot_available, le_certs_exist, get_cert_expiry

        domain = config.domain if config else "unknown"
        has_certs = le_certs_exist(domain)
        expiry = get_cert_expiry(domain)
        return {
            "certbot_available": certbot_available(),
            "enabled": config.letsencrypt.enabled if config else False,
            "domain": domain,
            "certificate_exists": has_certs,
            "expiry": expiry.isoformat() if expiry else None,
        }

    @app.post("/api/letsencrypt/obtain")
    async def le_obtain(request: Request):
        from ..letsencrypt import certbot_available, obtain_certificate, le_certs_exist

        if not certbot_available():
            return JSONResponse(
                {"error": "certbot is not installed on this server"},
                status_code=400,
            )

        if config is None:
            return JSONResponse({"error": "Config not available"}, status_code=503)

        try:
            body = await request.json()
        except Exception:
            body = {}

        email = body.get("email", "") or (config.letsencrypt.email if config else "")
        domain = config.domain if config else ""

        if not email:
            return JSONResponse({"error": "Email is required"}, status_code=400)
        if not domain or domain == "pega.local":
            return JSONResponse(
                {"error": "Set a real domain in config before requesting a certificate"},
                status_code=400,
            )

        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(None, obtain_certificate, domain, email)

        if ok and le_certs_exist(domain):
            return {
                "status": "success",
                "message": f"Certificate obtained for {domain}. Restart pega-pega to use it.",
            }
        return JSONResponse(
            {"error": "Certificate request failed. Check server logs for details."},
            status_code=500,
        )

    @app.post("/api/update")
    async def trigger_update():
        from ..updater import perform_update, UpdateError

        loop = asyncio.get_running_loop()
        try:
            result = await loop.run_in_executor(None, perform_update)
            return {
                "status": "success" if not result.already_up_to_date else "up_to_date",
                "old_version": result.old_version,
                "new_version": result.new_version,
                "restarted": result.restarted,
                "message": result.message,
            }
        except UpdateError as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # ── Mock rules API ──────────────────────────────────────────────

    async def _reload_matcher():
        """Reload mock matcher from database."""
        if mock_matcher is not None:
            rules = await store.list_mock_rules()
            mock_matcher.reload(rules)

    @app.get("/mock", response_class=HTMLResponse)
    async def mock_page(request: Request):
        return templates.TemplateResponse(request, "mock.html")

    @app.get("/api/mock-rules")
    async def list_mock_rules():
        rules = await store.list_mock_rules()
        for rule in rules:
            rule.pop("response_file_data", None)
        return {"rules": rules}

    @app.post("/api/mock-rules")
    async def create_mock_rule(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        file_data = None
        if body.get("response_file_data_b64"):
            import base64
            file_data = base64.b64decode(body["response_file_data_b64"])

        rule = MockRule(
            path=body.get("path", "/"),
            method=body.get("method", "ANY").upper(),
            status_code=int(body.get("status_code", 200)),
            response_body=body.get("response_body", ""),
            content_type=body.get("content_type", "application/json"),
            headers=body.get("headers", {}),
            enabled=body.get("enabled", True),
            priority=int(body.get("priority", 0)),
            response_file=body.get("response_file", ""),
            response_file_data=file_data,
            ntlm_capture=bool(body.get("ntlm_capture", False)),
            basic_auth_capture=bool(body.get("basic_auth_capture", False)),
        )
        await store.save_mock_rule(rule)
        await _reload_matcher()
        return rule.to_dict()

    @app.put("/api/mock-rules/{rule_id}")
    async def update_mock_rule(rule_id: str, request: Request):
        existing = await store.get_mock_rule(rule_id)
        if not existing:
            return JSONResponse({"error": "Not found"}, status_code=404)

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        file_data = existing.get("response_file_data")
        if body.get("response_file_data_b64"):
            import base64
            file_data = base64.b64decode(body["response_file_data_b64"])
        elif "response_file" in body and not body["response_file"]:
            # File was cleared
            file_data = None

        rule = MockRule(
            id=rule_id,
            path=body.get("path", existing["path"]),
            method=body.get("method", existing["method"]).upper(),
            status_code=int(body.get("status_code", existing["status_code"])),
            response_body=body.get("response_body", existing["response_body"]),
            content_type=body.get("content_type", existing["content_type"]),
            headers=body.get("headers", existing["headers"]),
            enabled=body.get("enabled", existing["enabled"]),
            priority=int(body.get("priority", existing["priority"])),
            response_file=body.get("response_file", existing.get("response_file", "")),
            response_file_data=file_data,
            ntlm_capture=bool(body.get("ntlm_capture", existing.get("ntlm_capture", False))),
            basic_auth_capture=bool(body.get("basic_auth_capture", existing.get("basic_auth_capture", False))),
            created_at=existing["created_at"],
        )
        await store.save_mock_rule(rule)
        await _reload_matcher()
        return rule.to_dict()

    @app.delete("/api/mock-rules/{rule_id}")
    async def delete_mock_rule(rule_id: str):
        existing = await store.get_mock_rule(rule_id)
        if not existing:
            return JSONResponse({"error": "Not found"}, status_code=404)
        await store.delete_mock_rule(rule_id)
        await _reload_matcher()
        return {"status": "deleted"}

    @app.post("/api/mock-rules/reorder")
    async def reorder_mock_rules(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON"}, status_code=400)

        order = body.get("order", [])
        if not isinstance(order, list):
            return JSONResponse({"error": "order must be a list of rule IDs"}, status_code=400)

        for i, rule_id in enumerate(order):
            existing = await store.get_mock_rule(rule_id)
            if existing:
                rule = MockRule(
                    id=rule_id,
                    path=existing["path"],
                    method=existing["method"],
                    status_code=existing["status_code"],
                    response_body=existing["response_body"],
                    content_type=existing["content_type"],
                    headers=existing["headers"],
                    enabled=existing["enabled"],
                    priority=i,
                    response_file=existing.get("response_file", ""),
                    response_file_data=existing.get("response_file_data"),
                    ntlm_capture=bool(existing.get("ntlm_capture", False)),
                    basic_auth_capture=bool(existing.get("basic_auth_capture", False)),
                    created_at=existing["created_at"],
                )
                await store.save_mock_rule(rule)

        await _reload_matcher()
        return {"status": "ok"}

    @app.post("/api/mock-rules/upload")
    async def upload_mock_file(file: UploadFile):
        if not file.filename:
            return JSONResponse({"error": "No file provided"}, status_code=400)
        contents = await file.read()
        if len(contents) > 10 * 1024 * 1024:
            return JSONResponse({"error": "File too large (max 10MB)"}, status_code=400)
        # Return file info — actual data is stored when the rule is saved
        import base64
        return {
            "original_name": file.filename,
            "size": len(contents),
            "data_b64": base64.b64encode(contents).decode(),
        }

    @app.get("/api/mock-rules/uploads/{rule_id}")
    async def serve_upload(rule_id: str):
        rule = await store.get_mock_rule(rule_id)
        if not rule or not rule.get("response_file_data"):
            return JSONResponse({"error": "Not found"}, status_code=404)
        from starlette.responses import Response
        return Response(
            content=rule["response_file_data"],
            media_type=rule.get("content_type", "application/octet-stream"),
        )

    # ── WebSocket (live feed) ────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        if _password_required():
            token = ws.cookies.get("session")
            if not token or token not in _sessions:
                await ws.close(code=4001)
                return
        await ws.accept()
        queue = bus.subscribe()
        try:
            while True:
                event = await queue.get()
                try:
                    await ws.send_text(event.to_json())
                except (WebSocketDisconnect, RuntimeError):
                    break
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        finally:
            bus.unsubscribe(queue)

    return app
