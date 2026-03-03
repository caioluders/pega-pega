import asyncio
import base64
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class SmtpHandler(BaseProtocolHandler):
    """Honeypot SMTP server that captures mail envelopes and credentials."""

    name: str = "SMTP"
    default_port: int = 25

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("SMTP handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip: str = peer[0] if peer else "unknown"
        source_port: int = peer[1] if peer else 0

        ehlo_domain: str = ""
        mail_from: str = ""
        rcpt_to: list[str] = []
        data_body: str = ""
        auth_user: str = ""
        auth_pass: str = ""
        raw_accumulated = bytearray()

        try:
            # Send banner
            writer.write(b"220 mail.pega.local ESMTP Pega-Pega\r\n")
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

                # --- EHLO / HELO ------------------------------------------
                if verb in ("EHLO", "HELO"):
                    ehlo_domain = arg
                    if verb == "EHLO":
                        writer.write(
                            b"250-mail.pega.local Hello\r\n"
                            b"250-SIZE 10485760\r\n"
                            b"250-AUTH PLAIN LOGIN\r\n"
                            b"250-STARTTLS\r\n"
                            b"250 8BITMIME\r\n"
                        )
                    else:
                        writer.write(b"250 mail.pega.local Hello\r\n")
                    await writer.drain()

                # --- MAIL FROM --------------------------------------------
                elif verb == "MAIL" and arg.upper().startswith("FROM:"):
                    mail_from = arg[5:].strip().strip("<>")
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                # --- RCPT TO ----------------------------------------------
                elif verb == "RCPT" and arg.upper().startswith("TO:"):
                    recipient = arg[3:].strip().strip("<>")
                    rcpt_to.append(recipient)
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                # --- DATA -------------------------------------------------
                elif verb == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()

                    body_lines: list[str] = []
                    while True:
                        try:
                            body_data = await asyncio.wait_for(
                                reader.readline(), timeout=_CONNECTION_TIMEOUT,
                            )
                        except asyncio.TimeoutError:
                            break
                        if not body_data:
                            break
                        raw_accumulated.extend(body_data)
                        body_line = body_data.decode("utf-8", errors="replace").rstrip("\r\n")
                        if body_line == ".":
                            break
                        body_lines.append(body_line)

                    data_body = "\n".join(body_lines)
                    writer.write(b"250 OK: message queued\r\n")
                    await writer.drain()

                    # Emit full envelope event after DATA completes
                    recipients_str = ", ".join(rcpt_to) if rcpt_to else ""
                    await self.emit(CapturedRequest(
                        protocol=Protocol.SMTP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=f"MAIL from={mail_from} to={recipients_str}",
                        details={
                            "ehlo": ehlo_domain,
                            "mail_from": mail_from,
                            "rcpt_to": list(rcpt_to),
                            "data": data_body,
                            "auth_user": auth_user,
                            "auth_pass": auth_pass,
                        },
                        raw_data=bytes(raw_accumulated),
                    ))

                # --- AUTH -------------------------------------------------
                elif verb == "AUTH":
                    mechanism = arg.split()[0].upper() if arg else "UNKNOWN"

                    if mechanism == "PLAIN":
                        # Client may supply credentials inline
                        auth_parts = arg.split(None, 1)
                        if len(auth_parts) > 1 and auth_parts[1]:
                            cred_blob = auth_parts[1]
                        else:
                            writer.write(b"334 \r\n")
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
                            cred_blob = cred_data.decode("utf-8", errors="replace").strip()

                        try:
                            decoded = base64.b64decode(cred_blob).decode("utf-8", errors="replace")
                            # PLAIN format: \0user\0pass
                            cred_parts = decoded.split("\x00")
                            auth_user = cred_parts[1] if len(cred_parts) > 1 else ""
                            auth_pass = cred_parts[2] if len(cred_parts) > 2 else ""
                        except Exception:
                            auth_user = cred_blob
                            auth_pass = ""

                    elif mechanism == "LOGIN":
                        # Username prompt
                        writer.write(b"334 VXNlcm5hbWU6\r\n")  # base64("Username:")
                        await writer.drain()
                        try:
                            user_data = await asyncio.wait_for(
                                reader.readline(), timeout=_CONNECTION_TIMEOUT,
                            )
                        except asyncio.TimeoutError:
                            break
                        if not user_data:
                            break
                        raw_accumulated.extend(user_data)
                        try:
                            auth_user = base64.b64decode(
                                user_data.strip()
                            ).decode("utf-8", errors="replace")
                        except Exception:
                            auth_user = user_data.decode("utf-8", errors="replace").strip()

                        # Password prompt
                        writer.write(b"334 UGFzc3dvcmQ6\r\n")  # base64("Password:")
                        await writer.drain()
                        try:
                            pass_data = await asyncio.wait_for(
                                reader.readline(), timeout=_CONNECTION_TIMEOUT,
                            )
                        except asyncio.TimeoutError:
                            break
                        if not pass_data:
                            break
                        raw_accumulated.extend(pass_data)
                        try:
                            auth_pass = base64.b64decode(
                                pass_data.strip()
                            ).decode("utf-8", errors="replace")
                        except Exception:
                            auth_pass = pass_data.decode("utf-8", errors="replace").strip()

                    else:
                        # Unknown mechanism -- prompt anyway
                        writer.write(b"334 \r\n")
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
                        auth_user = cred_data.decode("utf-8", errors="replace").strip()

                    writer.write(b"235 Authentication successful\r\n")
                    await writer.drain()

                # --- STARTTLS ---------------------------------------------
                elif verb == "STARTTLS":
                    writer.write(b"454 TLS not available\r\n")
                    await writer.drain()

                # --- RSET -------------------------------------------------
                elif verb == "RSET":
                    mail_from = ""
                    rcpt_to = []
                    data_body = ""
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                # --- NOOP -------------------------------------------------
                elif verb == "NOOP":
                    writer.write(b"250 OK\r\n")
                    await writer.drain()

                # --- QUIT -------------------------------------------------
                elif verb == "QUIT":
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()

                    # Emit envelope event on quit if we haven't already
                    recipients_str = ", ".join(rcpt_to) if rcpt_to else ""
                    summary = f"MAIL from={mail_from} to={recipients_str}"
                    await self.emit(CapturedRequest(
                        protocol=Protocol.SMTP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=summary,
                        details={
                            "ehlo": ehlo_domain,
                            "mail_from": mail_from,
                            "rcpt_to": list(rcpt_to),
                            "data": data_body,
                            "auth_user": auth_user,
                            "auth_pass": auth_pass,
                        },
                        raw_data=bytes(raw_accumulated),
                    ))
                    break

                # --- Catch-all --------------------------------------------
                else:
                    writer.write(
                        f"502 Command not recognized: {verb}\r\n".encode()
                    )
                    await writer.drain()

        except Exception:
            logger.debug("SMTP handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
