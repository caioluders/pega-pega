import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol
from ..utils.ldap_parser import parse_ldap_message, build_bind_response, build_search_done

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class LdapHandler(BaseProtocolHandler):
    """Honeypot LDAP server that captures bind and search operations."""

    name: str = "LDAP"
    default_port: int = 389

    async def start(self):
        server = await asyncio.start_server(
            self._handle_client, self.bind, self.port,
        )
        self._servers.append(server)
        logger.info("LDAP handler listening on %s:%d", self.bind, self.port)

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
            while True:
                try:
                    data = await asyncio.wait_for(
                        reader.read(65536), timeout=_CONNECTION_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    break

                if not data:
                    break

                try:
                    msg = parse_ldap_message(data)
                except Exception:
                    logger.debug(
                        "LDAP parse error from %s (hex: %s)",
                        source_ip, data[:64].hex(),
                    )
                    break

                operation = msg.get("operation", "Unknown")
                message_id = msg.get("message_id", 0)

                if operation == "BindRequest":
                    dn = msg.get("dn", "")
                    auth = msg.get("auth", {})
                    auth_method = auth.get("method", "unknown")

                    summary = f"BIND {dn}" if dn else "BIND (anonymous)"

                    details: dict = {
                        "operation": operation,
                        "dn": dn,
                        "auth_method": auth_method,
                    }
                    if auth_method == "simple":
                        details["password"] = auth.get("password", "")
                    elif auth_method == "SASL":
                        details["sasl_mechanism"] = auth.get("mechanism", "")

                    await self.emit(CapturedRequest(
                        protocol=Protocol.LDAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=summary,
                        details=details,
                        raw_data=data,
                    ))

                    # Send BindResponse (success)
                    response = build_bind_response(message_id, success=True)
                    writer.write(response)
                    await writer.drain()

                elif operation == "SearchRequest":
                    base = msg.get("base", "")
                    scope = msg.get("scope", "")
                    filt = msg.get("filter", "")
                    attrs = msg.get("attributes", [])

                    summary = f"SEARCH base={base} filter={filt}"

                    await self.emit(CapturedRequest(
                        protocol=Protocol.LDAP,
                        source_ip=source_ip,
                        source_port=source_port,
                        dest_port=self.port,
                        summary=summary,
                        details={
                            "operation": operation,
                            "base": base,
                            "scope": scope,
                            "filter": filt,
                            "attributes": attrs,
                        },
                        raw_data=data,
                    ))

                    # Send SearchResultDone (no actual results)
                    response = build_search_done(message_id)
                    writer.write(response)
                    await writer.drain()

                elif operation == "UnbindRequest":
                    # Client is disconnecting
                    break

                else:
                    logger.debug(
                        "LDAP: unhandled operation %s from %s",
                        operation, source_ip,
                    )

        except Exception:
            logger.debug("LDAP handler error for %s", source_ip, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
