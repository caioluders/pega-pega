import asyncio
import logging
from pathlib import Path

from .http_handler import HttpHandler
from ..certs import create_ssl_context, generate_self_signed_cert
from ..models import Protocol

logger = logging.getLogger("pega-pega")

CERT_DIR = Path(".certs")


class HttpsHandler(HttpHandler):
    name = "HTTPS"
    default_port = 443

    # ------------------------------------------------------------------
    # Server lifecycle -- wrap TCP listener with TLS
    # ------------------------------------------------------------------

    async def start(self):
        ssl_ctx = self._ensure_ssl_context()
        server = await asyncio.start_server(
            self._handle_connection,
            host=self.bind,
            port=self.port,
            ssl=ssl_ctx,
        )
        self._servers.append(server)
        logger.info("HTTPS handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------
    # SSL helpers
    # ------------------------------------------------------------------

    def _ensure_ssl_context(self):
        """Load or create a self-signed certificate, then return an SSLContext."""
        cert_path = CERT_DIR / "server.pem"
        key_path = CERT_DIR / "server-key.pem"

        if not cert_path.exists() or not key_path.exists():
            domain = self.global_config.domain
            logger.info(
                "HTTPS: generating self-signed certificate for %s (dir=%s)",
                domain, CERT_DIR,
            )
            cert_path, key_path = generate_self_signed_cert(
                domain=domain,
                cert_dir=CERT_DIR,
            )

        return create_ssl_context(cert_path, key_path)

    # ------------------------------------------------------------------
    # Override emit to tag protocol as HTTPS
    # ------------------------------------------------------------------

    async def emit(self, request):
        request.protocol = Protocol.HTTPS
        await super().emit(request)
