import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class ImapHandler(BaseProtocolHandler):
    """Honeypot IMAP4rev1 server that captures authentication and commands."""

    name: str = "IMAP"
    default_port: int = 143

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("IMAP handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip: str = peer[0] if peer else "unknown"
        source_port: int = peer[1] if peer else 0

        raw_accumulated = bytearray()

        try:
            # Send untagged banner
            writer.write(b"* OK IMAP4rev1 pega.local server ready\r\n")
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

                # IMAP commands are tagged: "<tag> <command> [<args>]"
                parts = line.split(None, 2)
                if len(parts) < 2:
                    writer.write(b"* BAD Invalid command\r\n")
                    await writer.drain()
                    continue

                tag = parts[0]
                verb = parts[1].upper()
                arg = parts[2] if len(parts) > 2 else ""

                # --- CAPABILITY -------------------------------------------
                if verb == "CAPABILITY":
                    writer.write(
                        b"* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN "
                        b"STARTTLS IDLE NAMESPACE\r\n"
                    )
                    writer.write(
                        f"{tag} OK CAPABILITY completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary="CMD CAPABILITY",
                        details={"tag": tag, "command": "CAPABILITY"},
                        raw_data=data,
                    ))

                # --- LOGIN ------------------------------------------------
                elif verb == "LOGIN":
                    # Args: <username> <password>
                    # Credentials may be quoted or unquoted
                    cred_parts = self._parse_login_args(arg)
                    username = cred_parts[0]
                    password = cred_parts[1]

                    writer.write(
                        f"{tag} OK LOGIN completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"AUTH {username}:{password}",
                        details={
                            "tag": tag,
                            "command": "LOGIN",
                            "username": username,
                            "password": password,
                        },
                        raw_data=data,
                    ))

                # --- AUTHENTICATE -----------------------------------------
                elif verb == "AUTHENTICATE":
                    writer.write(b"+ \r\n")
                    await writer.drain()
                    try:
                        cred_data = await asyncio.wait_for(
                            reader.readline(), timeout=_CONNECTION_TIMEOUT,
                        )
                    except asyncio.TimeoutError:
                        break
                    if not cred_data:
                        break
                    raw_accumulated.extend(cred_data)

                    writer.write(
                        f"{tag} OK AUTHENTICATE completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary="CMD AUTHENTICATE",
                        details={
                            "tag": tag,
                            "command": "AUTHENTICATE",
                            "mechanism": arg.split()[0] if arg else "UNKNOWN",
                            "credentials_b64": cred_data.decode(
                                "utf-8", errors="replace"
                            ).strip(),
                        },
                        raw_data=cred_data,
                    ))

                # --- SELECT -----------------------------------------------
                elif verb == "SELECT":
                    mailbox = arg.strip('"') if arg else "INBOX"
                    writer.write(
                        b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n"
                        b"* 0 EXISTS\r\n"
                        b"* 0 RECENT\r\n"
                        b"* OK [UIDVALIDITY 1] UIDs valid\r\n"
                    )
                    writer.write(
                        f"{tag} OK [READ-WRITE] SELECT completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"CMD SELECT",
                        details={"tag": tag, "command": "SELECT", "mailbox": mailbox},
                        raw_data=data,
                    ))

                # --- LIST -------------------------------------------------
                elif verb == "LIST":
                    writer.write(
                        b'* LIST (\\HasNoChildren) "/" "INBOX"\r\n'
                    )
                    writer.write(
                        f"{tag} OK LIST completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary="CMD LIST",
                        details={"tag": tag, "command": "LIST", "argument": arg},
                        raw_data=data,
                    ))

                # --- NOOP -------------------------------------------------
                elif verb == "NOOP":
                    writer.write(f"{tag} OK NOOP completed\r\n".encode())
                    await writer.drain()

                # --- STARTTLS ---------------------------------------------
                elif verb == "STARTTLS":
                    writer.write(
                        f"{tag} BAD STARTTLS not available\r\n".encode()
                    )
                    await writer.drain()

                # --- NAMESPACE --------------------------------------------
                elif verb == "NAMESPACE":
                    writer.write(
                        b'* NAMESPACE (("" "/")) NIL NIL\r\n'
                    )
                    writer.write(
                        f"{tag} OK NAMESPACE completed\r\n".encode()
                    )
                    await writer.drain()

                # --- LOGOUT -----------------------------------------------
                elif verb == "LOGOUT":
                    writer.write(b"* BYE IMAP4rev1 server logging out\r\n")
                    writer.write(
                        f"{tag} OK LOGOUT completed\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary="CMD LOGOUT",
                        details={"tag": tag, "command": "LOGOUT"},
                        raw_data=data,
                    ))
                    break

                # --- Catch-all --------------------------------------------
                else:
                    writer.write(
                        f"{tag} BAD Command not recognized\r\n".encode()
                    )
                    await writer.drain()

                    await self.emit(CapturedRequest(
                        protocol=Protocol.IMAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"CMD {verb}",
                        details={"tag": tag, "command": verb, "argument": arg},
                        raw_data=data,
                    ))

        except Exception:
            logger.debug("IMAP handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_login_args(arg: str) -> tuple[str, str]:
        """Parse LOGIN arguments that may be quoted or unquoted.

        Examples:
            ``user pass``        -> ("user", "pass")
            ``"user" "pass"``    -> ("user", "pass")
            ``"user name" pass`` -> ("user name", "pass")
        """
        tokens: list[str] = []
        current = ""
        in_quote = False

        for ch in arg:
            if ch == '"':
                in_quote = not in_quote
            elif ch == " " and not in_quote:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += ch

        if current:
            tokens.append(current)

        username = tokens[0] if len(tokens) > 0 else ""
        password = tokens[1] if len(tokens) > 1 else ""
        return username, password
