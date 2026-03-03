import asyncio
import logging
import signal
from pathlib import Path

import uvicorn

from .bus import EventBus
from .certs import generate_self_signed_cert
from .config import Config, ProtocolConfig
from .dashboard.app import create_app
from .display import TerminalDisplay
from .protocols import HANDLER_REGISTRY
from .store import Store, store_consumer

logger = logging.getLogger("pega-pega")


class PegaPegaServer:
    def __init__(self, config: Config):
        self.config = config
        self.bus = EventBus()
        self.store = Store(Path(config.db_path))
        self.display = TerminalDisplay(self.bus)
        self.handlers = []
        self._cert_path: Path | None = None
        self._key_path: Path | None = None

    async def start(self):
        await self.store.initialize()

        # Generate certs if HTTPS is enabled
        https_config = self.config.protocols.get("https", ProtocolConfig())
        if https_config.enabled:
            self._cert_path, self._key_path = generate_self_signed_cert(
                domain=self.config.domain,
                cert_dir=Path(".certs"),
            )
            logger.info("Generated self-signed certificate for %s", self.config.domain)

        # Start all enabled protocol handlers
        for name, cls in HANDLER_REGISTRY.items():
            proto_config = self.config.protocols.get(name, ProtocolConfig())
            if not proto_config.enabled:
                continue

            handler = cls(
                proto_config=proto_config,
                global_config=self.config,
                bus=self.bus,
            )

            # Pass cert paths to HTTPS handler
            if name == "https" and self._cert_path:
                handler.cert_path = self._cert_path
                handler.key_path = self._key_path

            try:
                await handler.start()
                self.handlers.append(handler)
            except OSError as e:
                logger.warning(
                    "[-] %s failed to bind on port %d: %s",
                    handler.name,
                    handler.port,
                    e,
                )
            except Exception as e:
                logger.warning(
                    "[-] %s failed to start: %s",
                    handler.name,
                    e,
                )

        # Start background store consumer
        asyncio.create_task(store_consumer(self.bus, self.store))

        # Start web dashboard
        if not self.config.no_dashboard:
            app = create_app(self.store, self.bus, self.config)
            dashboard_config = uvicorn.Config(
                app,
                host=self.config.dashboard_host,
                port=self.config.dashboard_port,
                log_level="warning",
            )
            dashboard_server = uvicorn.Server(dashboard_config)
            asyncio.create_task(dashboard_server.serve())
            logger.info(
                "[+] Dashboard on http://%s:%d",
                self.config.dashboard_host,
                self.config.dashboard_port,
            )

        # Start terminal display (this blocks)
        await self.display.run()

    async def stop(self):
        for handler in self.handlers:
            try:
                await handler.stop()
            except Exception:
                pass
        await self.store.close()


def run_server(config: Config):
    async def _run():
        server = PegaPegaServer(config)
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def handle_signal():
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, handle_signal)
            except NotImplementedError:
                pass

        # Run display + listeners, but also watch for stop signal
        start_task = asyncio.create_task(server.start())
        stop_task = asyncio.create_task(stop_event.wait())

        done, pending = await asyncio.wait(
            [start_task, stop_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for t in pending:
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass

        await server.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
