"""Rich terminal live display for captured requests."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align

from .bus import EventBus
from .models import CapturedRequest, Protocol

# ── Protocol color map ──────────────────────────────────────────────────
PROTOCOL_COLORS: dict[Protocol, str] = {
    Protocol.HTTP: "green",
    Protocol.HTTPS: "bold green",
    Protocol.DNS: "cyan",
    Protocol.FTP: "yellow",
    Protocol.SMTP: "magenta",
    Protocol.POP3: "red",
    Protocol.IMAP: "dark_red",
    Protocol.SSH: "bold red",
    Protocol.TELNET: "bright_yellow",
    Protocol.LDAP: "blue",
    Protocol.MYSQL: "bright_blue",
    Protocol.RAW_TCP: "white",
    Protocol.SNMP: "bright_cyan",
    Protocol.SYSLOG: "bright_magenta",
}

BANNER = r"""
[bold cyan]
  ____  _____ ____    _        ____  _____ ____    _
 |  _ \| ____/ ___|  / \      |  _ \| ____/ ___|  / \
 | |_) |  _|| |  _  / _ \ ____| |_) |  _|| |  _  / _ \
 |  __/| |__| |_| |/ ___ \____|  __/| |__| |_| |/ ___ \
 |_|   |_____\____/_/   \_\   |_|   |_____\____/_/   \_\
[/bold cyan]
[dim]Multi-Protocol Request Logger & Honeypot[/dim]
"""

MAX_EVENTS = 50
REFRESH_PER_SECOND = 4


class TerminalDisplay:
    """Subscribes to the EventBus and renders a live Rich table in the terminal."""

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._events: deque[CapturedRequest] = deque(maxlen=MAX_EVENTS)
        self._console = Console()

    # ── Table builder ───────────────────────────────────────────────────

    def _build_table(self) -> Table:
        table = Table(
            title=None,
            expand=True,
            border_style="bright_black",
            header_style="bold bright_white",
            row_styles=["", "dim"],
            pad_edge=True,
            show_lines=False,
        )
        table.add_column("Time", style="bright_black", width=10, no_wrap=True)
        table.add_column("Protocol", width=10, no_wrap=True)
        table.add_column("Source", width=22, no_wrap=True)
        table.add_column("Subdomain", style="bright_white", ratio=1)
        table.add_column("Summary", ratio=2)

        for event in self._events:
            # Time ──────────────────────────────────────────────────────
            try:
                ts = datetime.fromisoformat(event.timestamp)
                time_str = ts.strftime("%H:%M:%S")
            except (ValueError, TypeError):
                time_str = str(event.timestamp)[:8]

            # Protocol (colored) ───────────────────────────────────────
            color = PROTOCOL_COLORS.get(event.protocol, "white")
            proto_text = Text(event.protocol.value, style=color)

            # Source ip:port ────────────────────────────────────────────
            source = f"{event.source_ip}:{event.source_port}"

            # Subdomain ────────────────────────────────────────────────
            subdomain = event.subdomain or "-"

            # Summary (truncated) ──────────────────────────────────────
            summary = (event.summary or "")[:120]

            table.add_row(time_str, proto_text, source, subdomain, summary)

        return table

    def _build_display(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=9),
            Layout(name="body"),
        )

        # Header ───────────────────────────────────────────────────────
        header = Align.center(Text.from_markup(BANNER.strip()))
        layout["header"].update(
            Panel(header, border_style="cyan", padding=(0, 0))
        )

        # Body: request table ──────────────────────────────────────────
        count = len(self._events)
        table_title = (
            f"[bold bright_white]Captured Requests[/bold bright_white]  "
            f"[dim]({count} shown, newest first)[/dim]"
        )
        table = self._build_table()
        layout["body"].update(
            Panel(table, title=table_title, border_style="bright_black")
        )
        return layout

    # ── Main loop ─────────────────────────────────────────────────────

    async def run(self) -> None:
        queue = self._bus.subscribe()
        try:
            with Live(
                self._build_display(),
                console=self._console,
                refresh_per_second=REFRESH_PER_SECOND,
                screen=False,
            ) as live:
                while True:
                    # Drain all available events without blocking
                    drained = False
                    while True:
                        try:
                            event: CapturedRequest = queue.get_nowait()
                            self._events.appendleft(event)
                            drained = True
                        except asyncio.QueueEmpty:
                            break

                    if drained:
                        live.update(self._build_display())

                    # Sleep to achieve ~REFRESH_PER_SECOND updates
                    await asyncio.sleep(1.0 / REFRESH_PER_SECOND)
        finally:
            self._bus.unsubscribe(queue)
