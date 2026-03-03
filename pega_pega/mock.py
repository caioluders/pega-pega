"""Mock rule matcher for HTTP endpoints."""

from __future__ import annotations

import re


class MockMatcher:
    """Holds mock rules in memory and matches incoming requests."""

    def __init__(self, rules: list[dict] | None = None):
        self._rules: list[dict] = []
        self._compiled: list[tuple[re.Pattern, dict]] = []
        if rules:
            self.reload(rules)

    def reload(self, rules: list[dict]):
        """Replace all rules and recompile patterns."""
        self._rules = sorted(rules, key=lambda r: r.get("priority", 0))
        self._compiled = []
        for rule in self._rules:
            pattern = self._path_to_regex(rule["path"])
            self._compiled.append((pattern, rule))

    def match(self, method: str, path: str) -> dict | None:
        """Return the first enabled rule matching method + path, or None."""
        method = method.upper()
        for pattern, rule in self._compiled:
            if not rule.get("enabled", True):
                continue
            rule_method = rule.get("method", "ANY").upper()
            if rule_method != "ANY" and rule_method != method:
                continue
            if pattern.fullmatch(path):
                return rule
        return None

    @staticmethod
    def _path_to_regex(path: str) -> re.Pattern:
        """Convert a path pattern to a compiled regex.

        Supports:
          :param  — single segment  (/api/users/:id → /api/users/[^/]+)
          *       — match everything after this point (/api/* → /api/.*)
          **      — same as * (catch-all)
        The * wildcard can appear anywhere and captures all remaining path.
        """
        parts = path.rstrip("/").split("/")
        regex_parts = []
        for part in parts:
            if part.startswith(":"):
                regex_parts.append("[^/]+")
            elif part in ("*", "**"):
                # Catch-all: match everything from here
                regex_parts.append(".*")
                break
            else:
                regex_parts.append(re.escape(part))
        regex = "/".join(regex_parts)
        # Allow optional trailing slash
        regex += "/?"
        return re.compile(f"^{regex}$")
