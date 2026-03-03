"""FastAPI web dashboard for pega-pega."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from ..bus import EventBus
from ..models import Protocol
from ..store import Store

# ── Directory resolution (relative to *this* file) ───────────────────
_HERE = Path(__file__).resolve().parent
_TEMPLATES_DIR = _HERE / "templates"
_STATIC_DIR = _HERE / "static"


def create_app(store: Store, bus: EventBus) -> FastAPI:
    """Factory that wires the dashboard to a shared Store and EventBus."""

    app = FastAPI(
        title="PEGA-PEGA Dashboard",
        docs_url=None,
        redoc_url=None,
    )

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Mount static assets ─────────────────────────────────────────────
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
