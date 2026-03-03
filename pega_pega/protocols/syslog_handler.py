import asyncio
import logging
import re

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

# ---------------------------------------------------------------------------
# Syslog facility and severity names (RFC 3164 / RFC 5424)
# ---------------------------------------------------------------------------

_FACILITY_NAMES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

_SEVERITY_NAMES = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

# Match RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
# PRI is a decimal number inside angle brackets
_SYSLOG_RE = re.compile(
    r"^<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"  # timestamp
    r"(\S+)\s+"                                       # hostname
    r"(.*)$",                                          # message
    re.DOTALL,
)


def _parse_syslog_message(raw: bytes) -> dict:
    """Parse an RFC 3164 syslog message.

    Returns a dict with facility, severity, timestamp, hostname, message.
    Falls back to storing the entire raw message if parsing fails.
    """
    text = raw.decode("utf-8", errors="replace").rstrip("\n\r")
    m = _SYSLOG_RE.match(text)

    if m:
        pri = int(m.group(1))
        facility = pri >> 3
        severity = pri & 0x07
        return {
            "facility": facility,
            "facility_name": _FACILITY_NAMES.get(facility, f"facility{facility}"),
            "severity": severity,
            "severity_name": _SEVERITY_NAMES.get(severity, f"severity{severity}"),
            "timestamp": m.group(2),
            "hostname": m.group(3),
            "message": m.group(4),
        }

    # Fallback: try to extract just the PRI
    if text.startswith("<") and ">" in text:
        end = text.index(">")
        try:
            pri = int(text[1:end])
            facility = pri >> 3
            severity = pri & 0x07
            return {
                "facility": facility,
                "facility_name": _FACILITY_NAMES.get(facility, f"facility{facility}"),
                "severity": severity,
                "severity_name": _SEVERITY_NAMES.get(severity, f"severity{severity}"),
                "timestamp": "",
                "hostname": "",
                "message": text[end + 1:].strip(),
            }
        except ValueError:
            pass

    # Complete fallback
    return {
        "facility": 0,
        "facility_name": "kern",
        "severity": 0,
        "severity_name": "emerg",
        "timestamp": "",
        "hostname": "",
        "message": text,
    }


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that receives syslog UDP packets."""

    def __init__(self, handler: "SyslogHandler"):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    def error_received(self, exc: Exception):
        logger.debug("Syslog protocol error: %s", exc)

    async def _handle(self, data: bytes, addr: tuple):
        source_ip = addr[0]
        source_port = addr[1]

        parsed = _parse_syslog_message(data)
        facility_name = parsed["facility_name"]
        severity_name = parsed["severity_name"]
        hostname = parsed["hostname"] or source_ip
        message = parsed["message"]

        # Truncate message for summary
        msg_preview = message[:80]
        summary = f"[{facility_name}.{severity_name}] {hostname}: {msg_preview}"

        await self.handler.emit(CapturedRequest(
            protocol=Protocol.SYSLOG,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=summary,
            details=parsed,
            raw_data=data,
        ))
        # Syslog is fire-and-forget: no response is sent.


class SyslogHandler(BaseProtocolHandler):
    """Honeypot syslog receiver that captures syslog messages (UDP)."""

    name: str = "SYSLOG"
    default_port: int = 514

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _SyslogProtocol | None = None

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SyslogProtocol(self),
            local_addr=(self.bind, self.port),
        )
        self._transport = transport
        self._protocol = protocol
        logger.info("Syslog handler listening on %s:%d (UDP)", self.bind, self.port)

    async def stop(self):
        if self._transport:
            self._transport.close()
        await super().stop()
