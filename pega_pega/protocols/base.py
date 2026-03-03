from abc import ABC, abstractmethod
import asyncio
import logging

from ..bus import EventBus
from ..config import ProtocolConfig, Config
from ..models import CapturedRequest

logger = logging.getLogger("pega-pega")


class BaseProtocolHandler(ABC):
    """Base class for all protocol handlers."""

    name: str = "UNKNOWN"
    default_port: int = 0

    def __init__(self, proto_config: ProtocolConfig, global_config: Config, bus: EventBus):
        self.proto_config = proto_config
        self.global_config = global_config
        self.bus = bus
        self._servers: list = []

    @abstractmethod
    async def start(self):
        ...

    async def stop(self):
        for srv in self._servers:
            if hasattr(srv, "close"):
                srv.close()
            if hasattr(srv, "wait_closed"):
                await srv.wait_closed()

    async def emit(self, request: CapturedRequest):
        await self.bus.publish(request)

    @property
    def port(self) -> int:
        return self.proto_config.port or self.default_port

    @property
    def bind(self) -> str:
        return self.proto_config.bind or self.global_config.bind_ip
