import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30

# Telnet negotiation bytes
_IAC = bytes([255])   # Interpret As Command
_DO = bytes([253])    # Request the other side to perform
_WILL = bytes([251])  # Offer to perform
_ECHO = bytes([1])    # Echo option


class TelnetHandler(BaseProtocolHandler):
    """Honeypot Telnet server that captures login attempts and raw input."""

    name: str = "TELNET"
    default_port: int = 23

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("TELNET handler listening on %s:%d", self.bind, self.port)

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
            # Send IAC DO ECHO negotiation to suppress client-side echo
            writer.write(_IAC + _DO + _ECHO)
            await writer.drain()

            # Consume any negotiation responses the client sends back
            # (e.g. IAC WILL ECHO, IAC WONT ECHO). Give a brief window.
            await self._drain_negotiations(reader)

            # ---- Login prompt -----------------------------------------
            writer.write(b"pega-pega login: ")
            await writer.drain()

            username = await self._read_line(reader)
            if username is None:
                return

            # ---- Password prompt (IAC WILL ECHO to hide input) --------
            writer.write(_IAC + _WILL + _ECHO)
            await writer.drain()
            writer.write(b"Password: ")
            await writer.drain()

            password = await self._read_line(reader)
            if password is None:
                return

            # Turn echo back on
            writer.write(_IAC + _DO + _ECHO)
            await writer.drain()

            # Emit login event
            await self.emit(CapturedRequest(
                protocol=Protocol.TELNET,
                source_ip=source_ip,
                source_port=source_port,
                dest_port=self.port,
                summary=f"LOGIN {username}:{password}",
                details={
                    "username": username,
                    "password": password,
                },
                raw_data=f"{username}\n{password}".encode(),
            ))

            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

            # ---- Keep reading raw data until client disconnects -------
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.readline(), timeout=_CONNECTION_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    break

                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                # Strip any embedded telnet IAC sequences for the summary
                clean_line = self._strip_iac(line)
                if not clean_line:
                    continue

                await self.emit(CapturedRequest(
                    protocol=Protocol.TELNET,
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    summary=f"RAW {clean_line}",
                    details={"input": clean_line},
                    raw_data=data,
                ))

        except Exception:
            logger.debug("TELNET handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _read_line(self, reader: asyncio.StreamReader) -> str | None:
        """Read a single line from the client, with timeout."""
        try:
            data = await asyncio.wait_for(
                reader.readline(), timeout=_CONNECTION_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return None
        if not data:
            return None
        text = data.decode("utf-8", errors="replace").strip()
        return self._strip_iac(text)

    async def _drain_negotiations(self, reader: asyncio.StreamReader):
        """Read and discard any telnet negotiation bytes within a brief window."""
        try:
            # Give the client a short time to send negotiations
            await asyncio.wait_for(reader.read(256), timeout=0.5)
        except (asyncio.TimeoutError, ConnectionError):
            pass

    @staticmethod
    def _strip_iac(text: str) -> str:
        """Remove telnet IAC sequences from decoded text.

        IAC sequences are three bytes starting with 0xFF. After decoding
        to UTF-8 with errors="replace" these show up as replacement
        characters or high-codepoint chars. This strips the most common
        patterns.
        """
        result: list[str] = []
        i = 0
        while i < len(text):
            if ord(text[i]) == 0xFFFD or ord(text[i]) >= 0xFB:
                # Skip the IAC byte and its two arguments
                i += 3
                continue
            # Also skip bare high bytes that are remnants
            if ord(text[i]) > 127:
                i += 1
                continue
            result.append(text[i])
            i += 1
        return "".join(result).strip()
