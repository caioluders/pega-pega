"""FastAPI web dashboard for pega-pega."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from .. import __version__
from ..bus import EventBus
from ..config import Config
from ..models import Protocol
from ..store import Store

# ── Directory resolution (relative to *this* file) ───────────────────
_HERE = Path(__file__).resolve().parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"


def create_app(store: Store, bus: EventBus, config: Config | None = None) -> FastAPI:
    """Factory that wires the dashboard to a shared Store and EventBus."""

    app = FastAPI(
        title="PEGA-PEGA Dashboard",
        docs_url=None,
        redoc_url=None,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Mount static assets ─────────────────────────────────────────────
    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── HTML ─────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse("index.html", {"request": request})

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
        total = await store.count(protocol=protocol)
        return {"requests": rows, "total": total}

    @app.get("/api/requests/{request_id}")
    async def get_request(request_id: str):
        row = await store.get_by_id(request_id)
        if row is None:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return row

    @app.get("/api/stats")
    async def stats():
        counts: dict[str, int] = {}
        for proto in Protocol:
            c = await store.count(protocol=proto.value)
            counts[proto.value] = c
        total = await store.count()
        return {"protocols": counts, "total": total}

    # ── Config / Settings API ────────────────────────────────────────

    @app.get("/api/config")
    async def get_config():
        if config is None:
            return JSONResponse({"error": "Config not available"}, status_code=503)
        data = config.to_dict()
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
            return {
                "status": "saved",
                "path": str(save_path),
                "message": "Config saved. Restart pega-pega for changes to take effect.",
            }
        except PermissionError:
            return JSONResponse(
                {"error": f"Permission denied writing to {save_path}"},
                status_code=403,
            )
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

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

    # ── WebSocket (live feed) ────────────────────────────────────────

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
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
