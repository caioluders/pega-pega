import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .bus import EventBus
from .filters import FilterConfig
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
                response_file_data BLOB DEFAULT NULL,
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
        # Migration: add response_file_data column (BLOB) if missing
        try:
            self._conn.execute("SELECT response_file_data FROM mock_rules LIMIT 0")
        except Exception:
            self._conn.execute(
                "ALTER TABLE mock_rules ADD COLUMN response_file_data BLOB DEFAULT NULL"
            )
        # Migration: add ntlm_capture column if missing
        try:
            self._conn.execute("SELECT ntlm_capture FROM mock_rules LIMIT 0")
        except Exception:
            self._conn.execute(
                "ALTER TABLE mock_rules ADD COLUMN ntlm_capture INTEGER NOT NULL DEFAULT 0"
            )
        # Migration: add basic_auth_capture column if missing
        try:
            self._conn.execute("SELECT basic_auth_capture FROM mock_rules LIMIT 0")
        except Exception:
            self._conn.execute(
                "ALTER TABLE mock_rules ADD COLUMN basic_auth_capture INTEGER NOT NULL DEFAULT 0"
            )
        # Settings KV store
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
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

    async def count(
        self,
        protocol: str | None = None,
        search: str | None = None,
    ) -> int:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._count, protocol, search)

    def _count(self, protocol: str | None, search: str | None) -> int:
        conditions = ["source_ip NOT IN (SELECT ip FROM blocked_ips)"]
        params: list = []
        if protocol:
            conditions.append("protocol = ?")
            params.append(protocol.upper())
        if search:
            conditions.append(
                "(summary LIKE ? OR subdomain LIKE ? OR source_ip LIKE ? OR details LIKE ?)"
            )
            s = f"%{search}%"
            params.extend([s, s, s, s])

        sql = "SELECT COUNT(*) FROM requests WHERE " + " AND ".join(conditions)
        cursor = self._conn.execute(sql, params)
        return cursor.fetchone()[0]

    async def count_by_protocol(self) -> dict[str, int]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._count_by_protocol)

    def _count_by_protocol(self) -> dict[str, int]:
        cursor = self._conn.execute(
            "SELECT protocol, COUNT(*) FROM requests "
            "WHERE source_ip NOT IN (SELECT ip FROM blocked_ips) "
            "GROUP BY protocol"
        )
        return {row[0]: row[1] for row in cursor.fetchall()}

    async def recent_activity(self, minutes: int = 10, limit: int = 1000) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, self._recent_activity, minutes, limit
        )

    def _recent_activity(self, minutes: int, limit: int) -> list[dict]:
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        cursor = self._conn.execute(
            "SELECT timestamp, protocol FROM requests "
            "WHERE timestamp > ? AND source_ip NOT IN (SELECT ip FROM blocked_ips) "
            "ORDER BY timestamp DESC LIMIT ?",
            (cutoff, limit),
        )
        return [{"timestamp": row[0], "protocol": row[1]} for row in cursor.fetchall()]

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
                headers, enabled, priority, response_file, response_file_data,
                ntlm_capture, basic_auth_capture, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                rule.response_file_data,
                1 if rule.ntlm_capture else 0,
                1 if rule.basic_auth_capture else 0,
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
            d["ntlm_capture"] = bool(d.get("ntlm_capture", 0))
            d["basic_auth_capture"] = bool(d.get("basic_auth_capture", 0))
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
        d["ntlm_capture"] = bool(d.get("ntlm_capture", 0))
        d["basic_auth_capture"] = bool(d.get("basic_auth_capture", 0))
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

    # ── Credentials query ──────────────────────────────────────────────

    async def list_credentials(self, limit: int = 500) -> list[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._list_credentials, limit)

    def _list_credentials(self, limit: int) -> list[dict]:
        """Extract credentials from captured requests across all protocols."""
        # Search for requests containing credential-related keywords
        cursor = self._conn.execute(
            """SELECT id, timestamp, protocol, source_ip, source_port, details
               FROM requests
               WHERE source_ip NOT IN (SELECT ip FROM blocked_ips)
               AND (details LIKE '%password%' OR details LIKE '%credential_%'
                    OR details LIKE '%ntlm_hash%' OR details LIKE '%auth_user%'
                    OR details LIKE '%auth_response_hex%' OR details LIKE '%community%')
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        )
        results = []
        for row in cursor.fetchall():
            req_id, timestamp, protocol, source_ip, source_port, details_raw = row
            try:
                details = json.loads(details_raw) if details_raw else {}
            except (json.JSONDecodeError, TypeError):
                continue

            cred = self._extract_credential(details, protocol)
            if cred:
                cred["id"] = req_id
                cred["timestamp"] = timestamp
                cred["protocol"] = protocol
                cred["source_ip"] = source_ip
                cred["source_port"] = source_port
                results.append(cred)
        return results

    @staticmethod
    def _extract_credential(details: dict, protocol: str) -> dict | None:
        """Normalize credential fields from various protocols."""
        # NTLM hash
        if details.get("ntlm_hash"):
            return {
                "type": "ntlm_v2",
                "user": details.get("ntlm_user", ""),
                "secret": details["ntlm_hash"],
                "domain": details.get("ntlm_domain", ""),
                "hashcat_mode": "5600",
            }
        # Basic auth
        if details.get("credential_type") == "basic":
            return {
                "type": "basic",
                "user": details.get("credential_user", ""),
                "secret": details.get("credential_secret", ""),
            }
        # SMTP
        if details.get("auth_user"):
            return {
                "type": "plaintext",
                "user": details["auth_user"],
                "secret": details.get("auth_pass", ""),
            }
        # FTP, POP3, IMAP, Telnet, SSH (password)
        if details.get("username") and details.get("password"):
            return {
                "type": "plaintext",
                "user": details["username"],
                "secret": details["password"],
            }
        # LDAP simple bind
        if details.get("dn") and details.get("password"):
            return {
                "type": "plaintext",
                "user": details["dn"],
                "secret": details["password"],
            }
        # MySQL
        if details.get("username") and details.get("auth_response_hex"):
            return {
                "type": "mysql_hash",
                "user": details["username"],
                "secret": details["auth_response_hex"],
                "database": details.get("database", ""),
            }
        # SNMP community
        if details.get("community"):
            return {
                "type": "community_string",
                "user": "",
                "secret": details["community"],
            }
        return None

    # ── Settings KV store ──────────────────────────────────────────────

    async def get_setting(self, key: str) -> str | None:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, self._get_setting, key)

    def _get_setting(self, key: str) -> str | None:
        cursor = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    async def set_setting(self, key: str, value: str):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, self._set_setting, key, value)

    def _set_setting(self, key: str, value: str):
        self._conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )
        self._conn.commit()

    async def get_filter_config(self) -> FilterConfig:
        raw = await self.get_setting("filter_config")
        if raw:
            try:
                return FilterConfig.from_dict(json.loads(raw))
            except (json.JSONDecodeError, TypeError):
                pass
        return FilterConfig()

    async def save_filter_config(self, config: FilterConfig):
        await self.set_setting("filter_config", json.dumps(config.to_dict()))

    # ── Close ────────────────────────────────────────────────────────

    async def close(self):
        if self._conn:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(self._executor, self._close_db)

    def _close_db(self):
        if self._conn:
            self._conn.close()
            self._conn = None


async def store_consumer(bus: EventBus, store: Store, request_filter=None):
    queue = bus.subscribe()
    while True:
        event = await queue.get()
        if request_filter:
            from .filters import FilterResult
            result = request_filter.check(event.source_ip, event.details)
            if result.action == "drop":
                continue
            if result.action == "block":
                await store.add_blocked_ip(event.source_ip)
                continue
            if result.action == "tag" and result.tag:
                event.details = dict(event.details) if event.details else {}
                event.details["_filter_tag"] = result.tag
                event.details["_filter_reason"] = result.reason
        await store.save(event)
