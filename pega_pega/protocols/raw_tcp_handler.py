import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30
_MAX_READ = 65536


class RawTcpHandler(BaseProtocolHandler):
    """Generic TCP honeypot that captures any raw bytes sent to it."""

    name: str = "RAW_TCP"
    default_port: int = 9999

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("RAW_TCP handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip: str = peer[0] if peer else "unknown"
        source_port: int = peer[1] if peer else 0

        try:
            try:
                data = await asyncio.wait_for(
                    reader.read(_MAX_READ), timeout=_CONNECTION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                data = b""

            if data:
                length = len(data)
                hex_dump = data[:256].hex()
                summary = f"{length} bytes from {source_ip}"

                await self.emit(CapturedRequest(
                    protocol=Protocol.RAW_TCP,
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    summary=summary,
                    details={
                        "length": length,
                        "hex_preview": hex_dump,
                    },
                    raw_data=data,
                ))

        except Exception:
            logger.debug("RAW_TCP handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
