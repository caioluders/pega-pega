from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid
import json


class Protocol(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    FTP = "FTP"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    SSH = "SSH"
    TELNET = "TELNET"
    LDAP = "LDAP"
    MYSQL = "MYSQL"
    RAW_TCP = "RAW_TCP"
    SNMP = "SNMP"
    SYSLOG = "SYSLOG"


@dataclass
class CapturedRequest:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    protocol: Protocol = Protocol.RAW_TCP
    source_ip: str = ""
    source_port: int = 0
    dest_port: int = 0
    subdomain: str = ""
    summary: str = ""
    details: dict = field(default_factory=dict)
    raw_data: bytes = b""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["raw_data"] = self.raw_data.hex() if self.raw_data else ""
        d["protocol"] = self.protocol.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)
