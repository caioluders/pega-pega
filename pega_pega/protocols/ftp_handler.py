import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class FtpHandler(BaseProtocolHandler):
    """Honeypot FTP server that captures credentials and commands."""

    name: str = "FTP"
    default_port: int = 21

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("FTP handler listening on %s:%d", self.bind, self.port)

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

        try:
            # Send banner
            writer.write(b"220 ftp.pega.local FTP server ready\r\n")
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

                raw_line = data
                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                parts = line.split(None, 1)
                verb = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                # --- USER --------------------------------------------------
                if verb == "USER":
                    username = arg
                    writer.write(b"331 Please specify the password.\r\n")
                    await writer.drain()

                # --- PASS --------------------------------------------------
                elif verb == "PASS":
                    password = arg
                    writer.write(b"230 Login successful.\r\n")
                    await writer.drain()

                    # Emit a LOGIN event
                    await self.emit(CapturedRequest(
                        protocol=Protocol.FTP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"LOGIN {username}:{password}",
                        details={
                            "command": "LOGIN",
                            "username": username,
                            "password": password,
                        },
                        raw_data=raw_line,
                    ))

                # --- SYST --------------------------------------------------
                elif verb == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                    await writer.drain()

                # --- PWD ---------------------------------------------------
                elif verb == "PWD":
                    writer.write(b'257 "/" is the current directory\r\n')
                    await writer.drain()

                # --- LIST --------------------------------------------------
                elif verb == "LIST":
                    writer.write(b"150 Here comes the directory listing.\r\n")
                    await writer.drain()
                    writer.write(b"226 Directory send OK.\r\n")
                    await writer.drain()

                # --- CWD / MKD ---------------------------------------------
                elif verb in ("CWD", "MKD"):
                    writer.write(b"250 Directory operation successful.\r\n")
                    await writer.drain()

                # --- TYPE --------------------------------------------------
                elif verb == "TYPE":
                    writer.write(b"200 Switching to Binary mode.\r\n")
                    await writer.drain()

                # --- PASV --------------------------------------------------
                elif verb == "PASV":
                    # Fake passive response: 127,0,0,1,<high-port>
                    writer.write(
                        b"227 Entering Passive Mode (127,0,0,1,192,42).\r\n"
                    )
                    await writer.drain()

                # --- RETR / STOR -------------------------------------------
                elif verb in ("RETR", "STOR"):
                    writer.write(b"550 File not found.\r\n")
                    await writer.drain()

                # --- QUIT --------------------------------------------------
                elif verb == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()

                    # Emit command event, then leave loop
                    await self.emit(CapturedRequest(
                        protocol=Protocol.FTP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"CMD {verb}",
                        details={"command": verb},
                        raw_data=raw_line,
                    ))
                    break

                # --- Catch-all ---------------------------------------------
                else:
                    writer.write(
                        f"502 Command not implemented: {verb}\r\n".encode()
                    )
                    await writer.drain()

                # Emit a per-command event (except PASS which is logged above
                # as LOGIN, and QUIT which is logged just before break).
                if verb not in ("PASS", "QUIT"):
                    await self.emit(CapturedRequest(
                        protocol=Protocol.FTP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"CMD {verb} {arg}".strip(),
                        details={"command": verb, "argument": arg},
                        raw_data=raw_line,
                    ))

        except Exception:
            logger.debug("FTP handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
