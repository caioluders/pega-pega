from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ProtocolConfig:
    enabled: bool = True
    port: int = 0
    bind: str = ""  # empty = use global bind_ip


@dataclass
class Config:
    bind_ip: str = "0.0.0.0"
    domain: str = "pega.local"
    response_ip: str = ""  # auto-detect if empty
    dashboard_port: int = 8443
    dashboard_host: str = "0.0.0.0"
    db_path: str = "pega_pega.db"
    no_dashboard: bool = False
    protocols: dict[str, ProtocolConfig] = field(default_factory=dict)
    _source_path: Path | None = field(default=None, init=False, repr=False, compare=False)

    PROTOCOL_DEFAULTS: dict[str, int] = field(default_factory=lambda: {
        "http": 80,
        "https": 443,
        "dns": 53,
        "ftp": 21,
        "smtp": 25,
        "pop3": 110,
        "imap": 143,
        "ssh": 22,
        "telnet": 23,
        "ldap": 389,
        "mysql": 3306,
        "raw_tcp": 9999,
        "snmp": 161,
        "syslog": 514,
    }, repr=False)

    def __post_init__(self):
        # Fill in missing protocol configs with defaults
        for name, default_port in self.PROTOCOL_DEFAULTS.items():
            if name not in self.protocols:
                self.protocols[name] = ProtocolConfig(port=default_port)
            else:
                pc = self.protocols[name]
                if pc.port == 0:
                    pc.port = default_port
                if not pc.bind:
                    pc.bind = self.bind_ip

        # Apply global bind_ip to protocols that don't have one
        for pc in self.protocols.values():
            if not pc.bind:
                pc.bind = self.bind_ip

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        raw: dict[str, Any] = {}
        if path and path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f) or {}

        protocols = {}
        for name, proto_data in raw.get("protocols", {}).items():
            if isinstance(proto_data, dict):
                protocols[name] = ProtocolConfig(
                    enabled=proto_data.get("enabled", True),
                    port=proto_data.get("port", 0),
                    bind=proto_data.get("bind", ""),
                )

        cfg = cls(
            bind_ip=raw.get("bind_ip", "0.0.0.0"),
            domain=raw.get("domain", "pega.local"),
            response_ip=raw.get("response_ip", ""),
            dashboard_port=raw.get("dashboard_port", 8443),
            dashboard_host=raw.get("dashboard_host", "0.0.0.0"),
            db_path=raw.get("db_path", "pega_pega.db"),
            protocols=protocols,
        )
        cfg._source_path = path
        return cfg

    def to_dict(self) -> dict[str, Any]:
        return {
            "bind_ip": self.bind_ip,
            "domain": self.domain,
            "response_ip": self.response_ip,
            "dashboard_port": self.dashboard_port,
            "dashboard_host": self.dashboard_host,
            "db_path": self.db_path,
            "protocols": {
                name: {"enabled": pc.enabled, "port": pc.port}
                for name, pc in self.protocols.items()
            },
        }

    def save(self, path: Path | None = None) -> Path:
        save_path = path or self._source_path or Path("/etc/pega-pega/config.yaml")
        with open(save_path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)
        return save_path

    def get_response_ip(self) -> str:
        if self.response_ip:
            return self.response_ip
        # Try to auto-detect
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
