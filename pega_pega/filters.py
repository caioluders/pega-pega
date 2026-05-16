"""Request filtering: rate-limiting, bot detection, and IP allowlist.

All filters are disabled by default and configurable via the dashboard settings.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field


# Known scanner user-agents (case-insensitive substring matches)
KNOWN_BOT_UAS = [
    "zgrab",
    "censys",
    "shodan",
    "masscan",
    "go-http-client",
    "python-requests",
    "python-urllib",
    "libwww-perl",
    "nmap",
    "nikto",
    "nuclei",
    "httpx",
    "gobuster",
    "dirbuster",
    "sqlmap",
    "wpscan",
    "curl/",
    "wget/",
    "scrapy",
    "bot",
    "crawler",
    "spider",
    "scan",
]

# Known scanner paths (exact prefix matches)
KNOWN_BOT_PATHS = [
    "/.env",
    "/.git/",
    "/.git/config",
    "/.aws/",
    "/.svn/",
    "/wp-login.php",
    "/wp-admin",
    "/wp-content/",
    "/wp-includes/",
    "/xmlrpc.php",
    "/administrator/",
    "/phpmyadmin",
    "/phpMyAdmin",
    "/actuator",
    "/solr/",
    "/console/",
    "/manager/html",
    "/jenkins",
    "/api/v1/pods",
    "/.well-known/security.txt",
    "/telescope/requests",
    "/vendor/phpunit",
    "/cgi-bin/",
    "/shell",
    "/eval",
    "/config.json",
    "/debug/",
    "/server-status",
    "/server-info",
]


@dataclass
class FilterConfig:
    """Runtime filter configuration — stored in DB, exposed in settings."""
    # Rate limiting
    rate_limit_enabled: bool = False
    rate_limit_window: int = 60  # seconds
    rate_limit_max_requests: int = 50  # per window

    # Bot detection
    bot_filter_enabled: bool = False
    bot_filter_block: bool = True  # True = block, False = tag only

    # IP allowlist
    allowlist_enabled: bool = False
    allowlist_ips: list[str] = field(default_factory=list)  # IPs or CIDRs

    def to_dict(self) -> dict:
        return {
            "rate_limit_enabled": self.rate_limit_enabled,
            "rate_limit_window": self.rate_limit_window,
            "rate_limit_max_requests": self.rate_limit_max_requests,
            "bot_filter_enabled": self.bot_filter_enabled,
            "bot_filter_block": self.bot_filter_block,
            "allowlist_enabled": self.allowlist_enabled,
            "allowlist_ips": self.allowlist_ips,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FilterConfig":
        return cls(
            rate_limit_enabled=bool(data.get("rate_limit_enabled", False)),
            rate_limit_window=int(data.get("rate_limit_window", 60)),
            rate_limit_max_requests=int(data.get("rate_limit_max_requests", 50)),
            bot_filter_enabled=bool(data.get("bot_filter_enabled", False)),
            bot_filter_block=bool(data.get("bot_filter_block", True)),
            allowlist_enabled=bool(data.get("allowlist_enabled", False)),
            allowlist_ips=data.get("allowlist_ips", []),
        )


class RequestFilter:
    """Evaluates incoming requests against configured filters.

    Returns a FilterResult indicating whether to accept, tag, or drop.
    """

    def __init__(self):
        self.config = FilterConfig()
        self._request_counts: dict[str, list[float]] = defaultdict(list)
        self._auto_blocked: set[str] = set()

    def update_config(self, config: FilterConfig):
        self.config = config
        # Clear auto-blocked if rate limiting is disabled
        if not config.rate_limit_enabled:
            self._auto_blocked.clear()
            self._request_counts.clear()

    def check(self, source_ip: str, details: dict | None = None) -> "FilterResult":
        """Check a request against all active filters.

        Returns FilterResult with action and reason.
        """
        # Allowlist check (highest priority — if enabled, only allowed IPs pass)
        if self.config.allowlist_enabled and self.config.allowlist_ips:
            if not self._ip_in_allowlist(source_ip):
                return FilterResult(action="drop", reason="not in allowlist")

        # Rate limit check
        if self.config.rate_limit_enabled:
            if source_ip in self._auto_blocked:
                return FilterResult(action="block", reason="rate limit exceeded")
            if self._check_rate_limit(source_ip):
                return FilterResult(action="block", reason="rate limit exceeded")

        # Bot detection
        if self.config.bot_filter_enabled and details:
            bot_reason = self._detect_bot(details)
            if bot_reason:
                if self.config.bot_filter_block:
                    return FilterResult(action="drop", reason=bot_reason)
                return FilterResult(action="tag", reason=bot_reason, tag="bot")

        return FilterResult(action="accept")

    def get_auto_blocked_ips(self) -> list[str]:
        """Return list of IPs auto-blocked by rate limiting."""
        return list(self._auto_blocked)

    def clear_auto_blocked(self, ip: str | None = None):
        """Clear auto-blocked IPs (all or specific)."""
        if ip:
            self._auto_blocked.discard(ip)
            self._request_counts.pop(ip, None)
        else:
            self._auto_blocked.clear()
            self._request_counts.clear()

    def _check_rate_limit(self, ip: str) -> bool:
        """Track request and return True if rate limit exceeded."""
        now = time.time()
        window = self.config.rate_limit_window
        max_req = self.config.rate_limit_max_requests

        # Clean old entries
        timestamps = self._request_counts[ip]
        cutoff = now - window
        self._request_counts[ip] = [t for t in timestamps if t > cutoff]
        self._request_counts[ip].append(now)

        if len(self._request_counts[ip]) > max_req:
            self._auto_blocked.add(ip)
            return True
        return False

    def _ip_in_allowlist(self, ip: str) -> bool:
        """Check if IP is in the allowlist (supports CIDR notation)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        for entry in self.config.allowlist_ips:
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if addr == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                continue
        return False

    def _detect_bot(self, details: dict) -> str | None:
        """Check request details for bot signatures. Returns reason or None."""
        headers = details.get("headers", {})
        ua = ""
        if isinstance(headers, dict):
            ua = headers.get("user-agent", "").lower()

        # Check user-agent
        for pattern in KNOWN_BOT_UAS:
            if pattern in ua:
                return f"bot UA: {pattern}"

        # Check path
        path = details.get("path", "")
        if path:
            path_lower = path.lower()
            for bot_path in KNOWN_BOT_PATHS:
                if path_lower.startswith(bot_path.lower()):
                    return f"scanner path: {bot_path}"

        return None


@dataclass
class FilterResult:
    action: str  # "accept", "drop", "block", "tag"
    reason: str = ""
    tag: str = ""  # e.g. "bot"
