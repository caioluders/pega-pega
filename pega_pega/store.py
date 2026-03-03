import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .bus import EventBus
from .models import CapturedRequest


class Store:
    def __init__(self, db_path: Path):
        self._db_path = db_path
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._conn: sqlite3.Connection | None = None

    async def initialize(self):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._init_db)

    def _init_db(self):
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                protocol TEXT NOT NULL,
                source_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                subdomain TEXT,
                summary TEXT,
                details TEXT,
                raw_data TEXT
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_protocol ON requests(protocol)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_subdomain ON requests(subdomain)"
        )
        self._conn.commit()

    async def save(self, req: CapturedRequest):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._insert, req)

    def _insert(self, req: CapturedRequest):
        self._conn.execute(
            "INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                req.id,
                req.timestamp,
                req.protocol.value,
                req.source_ip,
                req.source_port,
                req.dest_port,
                req.subdomain,
                req.summary,
                json.dumps(req.details, default=str),
                req.raw_data.hex() if req.raw_data else "",
            ),
        )
        self._conn.commit()

    async def query(
        self,
        protocol: str | None = None,
        limit: int = 100,
        offset: int = 0,
        search: str | None = None,
    ) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, self._query, protocol, limit, offset, search
        )

    def _query(
        self,
        protocol: str | None,
        limit: int,
        offset: int,
        search: str | None,
    ) -> list[dict]:
        sql = "SELECT * FROM requests"
        params: list = []
        conditions = []

        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol.upper())
        if search:
            conditions.append(
                "(summary LIKE ? OR subdomain LIKE ? OR source_ip LIKE ? OR details LIKE ?)"
            )
            s = f"%{search}%"
            params.extend([s, s, s, s])

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = self._conn.execute(sql, params)
        columns = [desc[0] for desc in cursor.description]
        rows = []
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            # Parse details back to dict
            if d.get("details"):
                try:
                    d["details"] = json.loads(d["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            rows.append(d)
        return rows

    async def get_by_id(self, request_id: str) -> dict | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._get_by_id, request_id)

    def _get_by_id(self, request_id: str) -> dict | None:
        cursor = self._conn.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in cursor.description]
        d = dict(zip(columns, row))
        if d.get("details"):
            try:
                d["details"] = json.loads(d["details"])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    async def count(self, protocol: str | None = None) -> int:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._count, protocol)

    def _count(self, protocol: str | None) -> int:
        if protocol:
            cursor = self._conn.execute(
                "SELECT COUNT(*) FROM requests WHERE protocol = ?",
                (protocol.upper(),),
            )
        else:
            cursor = self._conn.execute("SELECT COUNT(*) FROM requests")
        return cursor.fetchone()[0]

    async def close(self):
        if self._conn:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(self._executor, self._close_db)

    def _close_db(self):
        if self._conn:
            self._conn.close()
            self._conn = None


async def store_consumer(bus: EventBus, store: Store):
    queue = bus.subscribe()
    while True:
        event = await queue.get()
        await store.save(event)
