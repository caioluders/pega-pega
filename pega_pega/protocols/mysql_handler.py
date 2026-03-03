import asyncio
import logging
import os
import struct

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30

# MySQL capability flags
_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_PLUGIN_AUTH = 0x00080000
_CLIENT_CONNECT_WITH_DB = 0x00000008

# Status flags
_SERVER_STATUS_AUTOCOMMIT = 0x0002

# Charset
_CHARSET_UTF8 = 0x21  # utf8_general_ci

# Error codes
_ER_ACCESS_DENIED = 1045


def _build_mysql_packet(seq_id: int, payload: bytes) -> bytes:
    """Build a MySQL wire packet: 3-byte length (LE) + 1-byte sequence + payload."""
    length = len(payload)
    header = struct.pack("<I", length)[:3] + bytes([seq_id])
    return header + payload


def _build_handshake_packet(connection_id: int) -> bytes:
    """Build a MySQL HandshakeV10 packet (sequence 0)."""
    # Auth plugin data: 20 random bytes split 8 + 12
    auth_data = os.urandom(20)
    auth_data_1 = auth_data[:8]
    auth_data_2 = auth_data[8:]

    capabilities = _CLIENT_PROTOCOL_41 | _CLIENT_SECURE_CONNECTION | _CLIENT_PLUGIN_AUTH
    cap_lower = capabilities & 0xFFFF
    cap_upper = (capabilities >> 16) & 0xFFFF

    server_version = b"5.7.99-Pega-Pega\x00"
    plugin_name = b"mysql_native_password\x00"

    payload = bytearray()
    # Protocol version
    payload.append(10)
    # Server version (null-terminated)
    payload.extend(server_version)
    # Connection ID (4 bytes LE)
    payload.extend(struct.pack("<I", connection_id))
    # Auth plugin data part 1 (8 bytes) + filler
    payload.extend(auth_data_1)
    payload.append(0x00)  # filler
    # Capability flags lower 2 bytes
    payload.extend(struct.pack("<H", cap_lower))
    # Character set
    payload.append(_CHARSET_UTF8)
    # Status flags
    payload.extend(struct.pack("<H", _SERVER_STATUS_AUTOCOMMIT))
    # Capability flags upper 2 bytes
    payload.extend(struct.pack("<H", cap_upper))
    # Length of auth plugin data (1 byte)
    payload.append(len(auth_data) + 1)  # includes trailing null
    # Reserved 10 bytes of zeros
    payload.extend(b"\x00" * 10)
    # Auth plugin data part 2 (at least 13 bytes, null-terminated)
    payload.extend(auth_data_2)
    payload.append(0x00)
    # Auth plugin name (null-terminated)
    payload.extend(plugin_name)

    return _build_mysql_packet(0, bytes(payload))


def _build_err_packet(seq_id: int, error_code: int, message: str) -> bytes:
    """Build a MySQL ERR_Packet."""
    payload = bytearray()
    payload.append(0xFF)  # ERR marker
    payload.extend(struct.pack("<H", error_code))
    # SQL state marker + state (Protocol 41)
    payload.extend(b"#")
    payload.extend(b"28000")  # Access denied SQL state
    payload.extend(message.encode("utf-8"))
    return _build_mysql_packet(seq_id, bytes(payload))


def _read_mysql_packet(data: bytes, offset: int = 0) -> tuple[int, int, bytes] | None:
    """Read one MySQL packet from data at offset.

    Returns (new_offset, seq_id, payload) or None if not enough data.
    """
    if len(data) - offset < 4:
        return None
    length = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)
    seq_id = data[offset + 3]
    if len(data) - offset - 4 < length:
        return None
    payload = data[offset + 4 : offset + 4 + length]
    return (offset + 4 + length, seq_id, payload)


def _parse_handshake_response(payload: bytes) -> dict:
    """Parse a HandshakeResponse41 payload to extract username and database."""
    result: dict = {"username": "", "database": "", "auth_response": b""}

    if len(payload) < 32:
        return result

    # Client capability flags (4 bytes LE)
    cap_flags = struct.unpack("<I", payload[0:4])[0]
    # Max packet size (4 bytes)
    # Charset (1 byte)
    # Reserved (23 bytes of zeros)
    offset = 4 + 4 + 1 + 23  # = 32

    # Username (null-terminated)
    end = payload.find(b"\x00", offset)
    if end == -1:
        return result
    result["username"] = payload[offset:end].decode("utf-8", errors="replace")
    offset = end + 1

    # Auth response
    if cap_flags & _CLIENT_SECURE_CONNECTION:
        if offset >= len(payload):
            return result
        auth_len = payload[offset]
        offset += 1
        result["auth_response"] = payload[offset : offset + auth_len]
        offset += auth_len
    else:
        end = payload.find(b"\x00", offset)
        if end != -1:
            result["auth_response"] = payload[offset:end]
            offset = end + 1

    # Database (optional, null-terminated)
    if cap_flags & _CLIENT_CONNECT_WITH_DB:
        end = payload.find(b"\x00", offset)
        if end != -1:
            result["database"] = payload[offset:end].decode("utf-8", errors="replace")

    return result


class MysqlHandler(BaseProtocolHandler):
    """Honeypot MySQL server that captures authentication attempts."""

    name: str = "MYSQL"
    default_port: int = 3306

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._connection_counter = 0

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("MySQL handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip: str = peer[0] if peer else "unknown"
        source_port: int = peer[1] if peer else 0

        self._connection_counter += 1
        conn_id = self._connection_counter

        try:
            # Send handshake
            handshake = _build_handshake_packet(conn_id)
            writer.write(handshake)
            await writer.drain()

            # Read client handshake response
            try:
                data = await asyncio.wait_for(
                    reader.read(65536), timeout=_CONNECTION_TIMEOUT,
                )
            except asyncio.TimeoutError:
                return

            if not data:
                return

            # Parse the MySQL packet
            parsed_pkt = _read_mysql_packet(data)
            if parsed_pkt is None:
                return
            _, seq_id, payload = parsed_pkt

            # Parse handshake response
            info = _parse_handshake_response(payload)
            username = info["username"]
            database = info["database"]

            summary = f"CONNECT user={username}"
            if database:
                summary += f" db={database}"

            await self.emit(CapturedRequest(
                protocol=Protocol.MYSQL,
                source_ip=source_ip,
                source_port=source_port,
                dest_port=self.port,
                summary=summary,
                details={
                    "username": username,
                    "database": database,
                    "auth_response_hex": info["auth_response"].hex(),
                },
                raw_data=data,
            ))

            # Send ERR packet (access denied)
            err_msg = f"Access denied for user '{username}'@'{source_ip}'"
            err_packet = _build_err_packet(seq_id + 1, _ER_ACCESS_DENIED, err_msg)
            writer.write(err_packet)
            await writer.drain()

        except Exception:
            logger.debug("MySQL handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
