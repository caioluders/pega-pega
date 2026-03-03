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
        self._ssl_ctx = self._ensure_ssl_context()
        server = await asyncio.start_server(
            self._handle_connection,
            host=self.bind,
            port=self.port,
            ssl=self._ssl_ctx,
        )
        self._servers.append(server)
        logger.info("HTTPS handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------
    # SSL helpers
    # ------------------------------------------------------------------

    def _ensure_ssl_context(self):
        """Load certificate from injected paths, or generate self-signed."""
        # Use injected cert paths (set by server.py) if available
        cert_path = getattr(self, "cert_path", None)
        key_path = getattr(self, "key_path", None)

        if cert_path and key_path and Path(cert_path).exists() and Path(key_path).exists():
            logger.info("HTTPS: using certificate %s", cert_path)
            return create_ssl_context(Path(cert_path), Path(key_path))

        # Fall back to self-signed
        ss_cert = CERT_DIR / "server.pem"
        ss_key = CERT_DIR / "server-key.pem"

        if not ss_cert.exists() or not ss_key.exists():
            domain = self.global_config.domain
            logger.info(
                "HTTPS: generating self-signed certificate for %s (dir=%s)",
                domain, CERT_DIR,
            )
            ss_cert, ss_key = generate_self_signed_cert(
                domain=domain,
                cert_dir=CERT_DIR,
            )

        return create_ssl_context(ss_cert, ss_key)

    def reload_ssl_context(self):
        """Rebuild SSL context (e.g. after certificate renewal)."""
        self._ssl_ctx = self._ensure_ssl_context()
        logger.info("HTTPS: reloaded SSL context on port %d", self.port)

    # ------------------------------------------------------------------
    # Override emit to tag protocol as HTTPS
    # ------------------------------------------------------------------

    async def emit(self, request):
        request.protocol = Protocol.HTTPS
        await super().emit(request)
