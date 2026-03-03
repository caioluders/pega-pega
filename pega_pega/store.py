import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .bus import EventBus
from .models import CapturedRequest, MockRule


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
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                blocked_at TEXT NOT NULL
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS mock_rules (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'ANY',
                status_code INTEGER NOT NULL DEFAULT 200,
                response_body TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT 'application/json',
                headers TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 0,
                response_file TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        # Migration: add response_file column if missing
        try:
            self._conn.execute("SELECT response_file FROM mock_rules LIMIT 0")
        except Exception:
            self._conn.execute(
                "ALTER TABLE mock_rules ADD COLUMN response_file TEXT NOT NULL DEFAULT ''"
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

        # Filter out blocked IPs
        conditions.append(
            "source_ip NOT IN (SELECT ip FROM blocked_ips)"
        )

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
        blocked_filter = "source_ip NOT IN (SELECT ip FROM blocked_ips)"
        if protocol:
            cursor = self._conn.execute(
                f"SELECT COUNT(*) FROM requests WHERE {blocked_filter} AND protocol = ?",
                (protocol.upper(),),
            )
        else:
            cursor = self._conn.execute(
                f"SELECT COUNT(*) FROM requests WHERE {blocked_filter}"
            )
        return cursor.fetchone()[0]

    # ── Delete requests ─────────────────────────────────────────────

    async def delete_request(self, request_id: str) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._delete_request, request_id)

    def _delete_request(self, request_id: str) -> bool:
        cursor = self._conn.execute("DELETE FROM requests WHERE id = ?", (request_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    async def delete_all_requests(self) -> int:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._delete_all_requests)

    def _delete_all_requests(self) -> int:
        cursor = self._conn.execute("DELETE FROM requests")
        self._conn.commit()
        return cursor.rowcount

    # ── Blocked IPs ──────────────────────────────────────────────────

    async def add_blocked_ip(self, ip: str):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._add_blocked_ip, ip)

    def _add_blocked_ip(self, ip: str):
        from datetime import datetime, timezone
        self._conn.execute(
            "INSERT OR REPLACE INTO blocked_ips VALUES (?, ?)",
            (ip, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    async def remove_blocked_ip(self, ip: str) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._remove_blocked_ip, ip)

    def _remove_blocked_ip(self, ip: str) -> bool:
        cursor = self._conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
        self._conn.commit()
        return cursor.rowcount > 0

    async def list_blocked_ips(self) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._list_blocked_ips)

    def _list_blocked_ips(self) -> list[dict]:
        cursor = self._conn.execute("SELECT ip, blocked_at FROM blocked_ips ORDER BY blocked_at DESC")
        return [{"ip": row[0], "blocked_at": row[1]} for row in cursor.fetchall()]

    async def is_ip_blocked(self, ip: str) -> bool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._is_ip_blocked, ip)

    def _is_ip_blocked(self, ip: str) -> bool:
        cursor = self._conn.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
        return cursor.fetchone() is not None

    # ── Mock rules ────────────────────────────────────────────────────

    async def save_mock_rule(self, rule: MockRule):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._insert_mock_rule, rule)

    def _insert_mock_rule(self, rule: MockRule):
        self._conn.execute(
            """INSERT OR REPLACE INTO mock_rules
               (id, path, method, status_code, response_body, content_type,
                headers, enabled, priority, response_file, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rule.id,
                rule.path,
                rule.method,
                rule.status_code,
                rule.response_body,
                rule.content_type,
                json.dumps(rule.headers, default=str),
                1 if rule.enabled else 0,
                rule.priority,
                rule.response_file,
                rule.created_at,
            ),
        )
        self._conn.commit()

    async def list_mock_rules(self) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._list_mock_rules)

    def _list_mock_rules(self) -> list[dict]:
        cursor = self._conn.execute(
            "SELECT * FROM mock_rules ORDER BY priority ASC"
        )
        columns = [desc[0] for desc in cursor.description]
        rows = []
        for row in cursor.fetchall():
            d = dict(zip(columns, row))
            d["enabled"] = bool(d["enabled"])
            if d.get("headers"):
                try:
                    d["headers"] = json.loads(d["headers"])
                except (json.JSONDecodeError, TypeError):
                    d["headers"] = {}
            rows.append(d)
        return rows

    async def get_mock_rule(self, rule_id: str) -> dict | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._get_mock_rule, rule_id)

    def _get_mock_rule(self, rule_id: str) -> dict | None:
        cursor = self._conn.execute(
            "SELECT * FROM mock_rules WHERE id = ?", (rule_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in cursor.description]
        d = dict(zip(columns, row))
        d["enabled"] = bool(d["enabled"])
        if d.get("headers"):
            try:
                d["headers"] = json.loads(d["headers"])
            except (json.JSONDecodeError, TypeError):
                d["headers"] = {}
        return d

    async def delete_mock_rule(self, rule_id: str):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._delete_mock_rule, rule_id)

    def _delete_mock_rule(self, rule_id: str):
        self._conn.execute("DELETE FROM mock_rules WHERE id = ?", (rule_id,))
        self._conn.commit()

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
