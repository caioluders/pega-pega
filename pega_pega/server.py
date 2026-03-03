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
from .letsencrypt import (
    certbot_available,
    le_certs_exist,
    get_le_cert_paths,
    obtain_certificate,
    renewal_loop,
)
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

        le_cfg = self.config.letsencrypt
        le_enabled = le_cfg.enabled and le_cfg.email and certbot_available()
        use_le_certs = False

        # ── Resolve SSL certificates ──────────────────────────────────
        https_config = self.config.protocols.get("https", ProtocolConfig())
        if https_config.enabled:
            if le_enabled and le_certs_exist(self.config.domain):
                # LE certs already on disk
                self._cert_path, self._key_path = get_le_cert_paths(self.config.domain)
                use_le_certs = True
                logger.info("Using existing Let's Encrypt certificate for %s", self.config.domain)
            elif le_enabled:
                # Need to obtain LE cert — start HTTP first for ACME challenge
                logger.info("Let's Encrypt enabled — starting HTTP handler for ACME challenge...")
                await self._start_protocol_handlers(only=["http"])
                loop = asyncio.get_running_loop()
                ok = await loop.run_in_executor(
                    None,
                    obtain_certificate,
                    self.config.domain,
                    le_cfg.email,
                )
                if ok and le_certs_exist(self.config.domain):
                    self._cert_path, self._key_path = get_le_cert_paths(self.config.domain)
                    use_le_certs = True
                    logger.info("Let's Encrypt certificate obtained for %s", self.config.domain)
                else:
                    logger.warning("Let's Encrypt failed — falling back to self-signed")
                    self._cert_path, self._key_path = generate_self_signed_cert(
                        domain=self.config.domain,
                        cert_dir=Path(".certs"),
                    )
            else:
                # No LE — self-signed
                self._cert_path, self._key_path = generate_self_signed_cert(
                    domain=self.config.domain,
                    cert_dir=Path(".certs"),
                )
                logger.info("Generated self-signed certificate for %s", self.config.domain)

        # ── Start remaining protocol handlers ─────────────────────────
        # _start_protocol_handlers skips ports already bound (via already_bound set),
        # so HTTP handlers started above for ACME won't be duplicated.
        await self._start_protocol_handlers()

        # Start background store consumer
        asyncio.create_task(store_consumer(self.bus, self.store))

        # ── Start certificate renewal loop ────────────────────────────
        if use_le_certs:
            async def _reload_certs():
                for h in self.handlers:
                    if hasattr(h, "reload_ssl_context"):
                        h.reload_ssl_context()
                logger.info("Reloaded SSL contexts after renewal")

            asyncio.create_task(renewal_loop(reload_callback=_reload_certs))

        # ── Start web dashboard ───────────────────────────────────────
        if not self.config.no_dashboard:
            app = create_app(self.store, self.bus, self.config)
            dashboard_kwargs = {
                "host": self.config.dashboard_host,
                "port": self.config.dashboard_port,
                "log_level": "warning",
            }
            # Serve dashboard over HTTPS if we have certs
            if self._cert_path and self._key_path:
                dashboard_kwargs["ssl_keyfile"] = str(self._key_path)
                dashboard_kwargs["ssl_certfile"] = str(self._cert_path)
                proto = "https"
            else:
                proto = "http"

            dashboard_config = uvicorn.Config(app, **dashboard_kwargs)
            dashboard_server = uvicorn.Server(dashboard_config)
            asyncio.create_task(dashboard_server.serve())
            logger.info(
                "[+] Dashboard on %s://%s:%d",
                proto,
                self.config.dashboard_host,
                self.config.dashboard_port,
            )

        # Start terminal display (this blocks)
        await self.display.run()

    async def _start_protocol_handlers(
        self,
        only: list[str] | None = None,
        exclude: list[str] | None = None,
    ):
        """Start protocol handlers. Use `only` to start specific ones, `exclude` to skip."""
        already_bound = {h.port for h in self.handlers}

        for name, cls in HANDLER_REGISTRY.items():
            if only and name not in only:
                continue
            if exclude and name in exclude:
                continue

            proto_config = self.config.protocols.get(name, ProtocolConfig())
            if not proto_config.enabled:
                continue

            ports_to_bind = [proto_config.port]
            for ep in proto_config.extra_ports:
                if ep not in ports_to_bind:
                    ports_to_bind.append(ep)

            for port in ports_to_bind:
                if port in already_bound:
                    continue

                pc = ProtocolConfig(
                    enabled=True,
                    port=port,
                    bind=proto_config.bind,
                )
                handler = cls(
                    proto_config=pc,
                    global_config=self.config,
                    bus=self.bus,
                )

                if name == "https" and self._cert_path:
                    handler.cert_path = self._cert_path
                    handler.key_path = self._key_path

                try:
                    await handler.start()
                    self.handlers.append(handler)
                except OSError as e:
                    logger.warning(
                        "[-] %s failed to bind on port %d: %s",
                        handler.name, port, e,
                    )
                except Exception as e:
                    logger.warning(
                        "[-] %s failed to start on port %d: %s",
                        handler.name, port, e,
                    )

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
