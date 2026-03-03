import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class Pop3Handler(BaseProtocolHandler):
    """Honeypot POP3 server that captures authentication attempts."""

    name: str = "POP3"
    default_port: int = 110

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("POP3 handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip: str = peer[0] if peer else "unknown"
        source_port: int = peer[1] if peer else 0

        username: str = ""
        password: str = ""
        raw_accumulated = bytearray()

        try:
            # Send banner
            writer.write(b"+OK POP3 server ready\r\n")
            await writer.drain()

            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.readline(), timeout=_CONNECTION_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    break

                if not data:
                    break

                raw_accumulated.extend(data)
                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                parts = line.split(None, 1)
                verb = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                # --- CAPA -------------------------------------------------
                if verb == "CAPA":
                    writer.write(
                        b"+OK Capability list follows\r\n"
                        b"USER\r\n"
                        b"UIDL\r\n"
                        b"TOP\r\n"
                        b".\r\n"
                    )
                    await writer.drain()

                # --- USER -------------------------------------------------
                elif verb == "USER":
                    username = arg
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                # --- PASS -------------------------------------------------
                elif verb == "PASS":
                    password = arg
                    writer.write(b"+OK Logged in.\r\n")
                    await writer.drain()

                    # Emit authentication event
                    await self.emit(CapturedRequest(
                        protocol=Protocol.POP3,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"AUTH {username}:{password}",
                        details={
                            "username": username,
                            "password": password,
                        },
                        raw_data=bytes(raw_accumulated),
                    ))

                # --- STAT -------------------------------------------------
                elif verb == "STAT":
                    writer.write(b"+OK 0 0\r\n")
                    await writer.drain()

                # --- LIST -------------------------------------------------
                elif verb == "LIST":
                    writer.write(
                        b"+OK 0 messages\r\n"
                        b".\r\n"
                    )
                    await writer.drain()

                # --- UIDL -------------------------------------------------
                elif verb == "UIDL":
                    writer.write(
                        b"+OK\r\n"
                        b".\r\n"
                    )
                    await writer.drain()

                # --- RETR -------------------------------------------------
                elif verb == "RETR":
                    writer.write(b"-ERR No such message\r\n")
                    await writer.drain()

                # --- DELE -------------------------------------------------
                elif verb == "DELE":
                    writer.write(b"+OK Marked for deletion\r\n")
                    await writer.drain()

                # --- NOOP -------------------------------------------------
                elif verb == "NOOP":
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                # --- RSET -------------------------------------------------
                elif verb == "RSET":
                    writer.write(b"+OK\r\n")
                    await writer.drain()

                # --- TOP --------------------------------------------------
                elif verb == "TOP":
                    writer.write(
                        b"+OK\r\n"
                        b".\r\n"
                    )
                    await writer.drain()

                # --- QUIT -------------------------------------------------
                elif verb == "QUIT":
                    writer.write(b"+OK Bye\r\n")
                    await writer.drain()
                    break

                # --- Catch-all --------------------------------------------
                else:
                    writer.write(b"-ERR Unknown command\r\n")
                    await writer.drain()

        except Exception:
            logger.debug("POP3 handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
