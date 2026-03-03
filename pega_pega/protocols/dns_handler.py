"""DNS protocol handler — captures DNS queries over UDP and TCP."""

from __future__ import annotations

import asyncio
import logging
import struct

from .base import BaseProtocolHandler
from ..config import ProtocolConfig, Config
from ..bus import EventBus
from ..models import CapturedRequest, Protocol
from ..utils.dns_parser import parse_dns_query, build_dns_response, qtype_to_str
from ..utils.subdomain import extract_subdomain

logger = logging.getLogger("pega-pega")


# ---------------------------------------------------------------------------
# UDP transport
# ---------------------------------------------------------------------------

class DnsUdpProtocol(asyncio.DatagramProtocol):
    """asyncio datagram protocol that forwards every DNS packet to the handler."""

    def __init__(self, handler: "DnsHandler"):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        asyncio.ensure_future(self._handle(data, addr))

    async def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        response = await self.handler.handle_dns_query(data, addr)
        if response is not None and self.transport is not None:
            self.transport.sendto(response, addr)

    def error_received(self, exc: Exception) -> None:
        logger.warning("DNS UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class DnsHandler(BaseProtocolHandler):
    """Listens for DNS queries on UDP **and** TCP, logs them, and responds
    with the configured response IP so that subsequent protocol connections
    are directed back to pega-pega.
    """

    name: str = "DNS"
    default_port: int = 53

    def __init__(
        self,
        proto_config: ProtocolConfig,
        global_config: Config,
        bus: EventBus,
    ):
        super().__init__(proto_config, global_config, bus)
        self._response_ip: str = ""

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        self._response_ip = self.global_config.get_response_ip()
        loop = asyncio.get_running_loop()

        # UDP listener
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: DnsUdpProtocol(self),
            local_addr=(self.bind, self.port),
        )
        self._servers.append(transport)

        # TCP listener
        tcp_server = await asyncio.start_server(
            self._handle_tcp_client,
            host=self.bind,
            port=self.port,
        )
        self._servers.append(tcp_server)

        logger.info("DNS handler listening on %s:%d (UDP+TCP)", self.bind, self.port)

    async def stop(self) -> None:
        for srv in self._servers:
            if hasattr(srv, "close"):
                srv.close()
            if hasattr(srv, "wait_closed"):
                try:
                    await srv.wait_closed()
                except Exception:
                    pass
        self._servers.clear()

    # -- TCP handling --------------------------------------------------------

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        addr = writer.get_extra_info("peername") or ("unknown", 0)
        try:
            while True:
                # DNS-over-TCP: 2-byte big-endian length prefix
                length_prefix = await reader.readexactly(2)
                (msg_len,) = struct.unpack("!H", length_prefix)
                if msg_len == 0:
                    break
                data = await reader.readexactly(msg_len)

                response = await self.handle_dns_query(data, addr)
                if response is not None:
                    writer.write(struct.pack("!H", len(response)) + response)
                    await writer.drain()
        except asyncio.IncompleteReadError:
            pass  # client closed connection
        except Exception as exc:
            logger.debug("DNS TCP error from %s: %s", addr, exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # -- core query processing -----------------------------------------------

    async def handle_dns_query(
        self,
        data: bytes,
        addr: tuple[str, int],
    ) -> bytes | None:
        """Parse a raw DNS query, emit a CapturedRequest, and return the
        response bytes (or ``None`` if we cannot even build a response).
        """
        source_ip, source_port = addr[0], addr[1]

        try:
            query = parse_dns_query(data)
        except Exception as exc:
            logger.warning(
                "DNS: failed to parse query from %s:%d (%s) — raw %d bytes",
                source_ip, source_port, exc, len(data),
            )
            # Still emit a capture so the operator knows *something* arrived
            await self.emit(CapturedRequest(
                protocol=Protocol.DNS,
                source_ip=source_ip,
                source_port=source_port,
                dest_port=self.port,
                summary="DNS <parse-error>",
                details={"error": str(exc), "raw_hex": data.hex()},
                raw_data=data,
            ))
            return None

        # Process each question (usually just one)
        for q in query["questions"]:
            qname = q["qname"]
            qtype_str = qtype_to_str(q["qtype"])
            qclass = q["qclass"]

            subdomain = extract_subdomain(qname, self.global_config.domain)

            summary = f"DNS {qtype_str} {qname}"

            await self.emit(CapturedRequest(
                protocol=Protocol.DNS,
                source_ip=source_ip,
                source_port=source_port,
                dest_port=self.port,
                subdomain=subdomain,
                summary=summary,
                details={
                    "qname": qname,
                    "qtype": qtype_str,
                    "qclass": qclass,
                    "transaction_id": query["transaction_id"],
                },
                raw_data=data,
            ))

            logger.info(
                "DNS query from %s:%d — %s (class=%d)",
                source_ip, source_port, summary, qclass,
            )

        # Build and return the response
        try:
            return build_dns_response(data, query, self._response_ip)
        except Exception as exc:
            logger.error("DNS: failed to build response: %s", exc)
            return None
