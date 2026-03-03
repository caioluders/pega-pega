import asyncio
import logging

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol
from ..utils.snmp_parser import parse_snmp_message, build_snmp_response

logger = logging.getLogger("pega-pega")


class _SnmpProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol that receives SNMP packets."""

    def __init__(self, handler: "SnmpHandler"):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handle(data, addr))

    def error_received(self, exc: Exception):
        logger.debug("SNMP protocol error: %s", exc)

    async def _handle(self, data: bytes, addr: tuple):
        source_ip = addr[0]
        source_port = addr[1]

        try:
            parsed = parse_snmp_message(data)
        except Exception:
            logger.debug(
                "SNMP parse error from %s (hex: %s)",
                source_ip, data[:64].hex(),
            )
            return

        community = parsed.get("community", "")
        pdu_type_name = parsed.get("pdu_type_name", "Unknown")
        varbinds = parsed.get("variable_bindings", [])
        oids = [vb["oid"] for vb in varbinds]
        oid_list = ",".join(oids) if oids else "(none)"

        # Determine the verb for the summary
        verb = "GET"
        pdu_type = parsed.get("pdu_type", 0)
        if pdu_type == 0xA1:
            verb = "GETNEXT"
        elif pdu_type == 0xA3:
            verb = "SET"

        summary = f"{verb} community={community} oids={oid_list}"

        await self.handler.emit(CapturedRequest(
            protocol=Protocol.SNMP,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=summary,
            details={
                "version": parsed.get("version_name", ""),
                "community": community,
                "pdu_type": pdu_type_name,
                "oids": oids,
            },
            raw_data=data,
        ))

        # Send response
        try:
            response = build_snmp_response(data, parsed)
            if self.transport:
                self.transport.sendto(response, addr)
        except Exception:
            logger.debug("SNMP response build error for %s", source_ip, exc_info=True)


class SnmpHandler(BaseProtocolHandler):
    """Honeypot SNMP server that captures community strings and OID queries."""

    name: str = "SNMP"
    default_port: int = 161

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _SnmpProtocol | None = None

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SnmpProtocol(self),
            local_addr=(self.bind, self.port),
        )
        self._transport = transport
        self._protocol = protocol
        logger.info("SNMP handler listening on %s:%d (UDP)", self.bind, self.port)

    async def stop(self):
        if self._transport:
            self._transport.close()
        await super().stop()
