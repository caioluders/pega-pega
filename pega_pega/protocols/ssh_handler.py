import asyncio
import logging
import os
import socket
import threading

import paramiko

from ..protocols.base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol

logger = logging.getLogger("pega-pega")

_CONNECTION_TIMEOUT = 30


class PegaSSHServer(paramiko.ServerInterface):
    """Paramiko SSH server interface that captures auth attempts."""

    def __init__(self, handler: "SshHandler", client_addr: tuple):
        self.handler = handler
        self.client_addr = client_addr
        self.event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        source_ip = self.client_addr[0]
        source_port = self.client_addr[1]

        request = CapturedRequest(
            protocol=Protocol.SSH,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=f"AUTH {username}:{password}",
            details={
                "auth_type": "password",
                "username": username,
                "password": password,
            },
            raw_data=f"{username}:{password}".encode(),
        )

        loop = self.handler._loop
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.handler.emit(request), loop)

        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        source_ip = self.client_addr[0]
        source_port = self.client_addr[1]
        fingerprint = key.get_fingerprint().hex()

        request = CapturedRequest(
            protocol=Protocol.SSH,
            source_ip=source_ip,
            source_port=source_port,
            dest_port=self.handler.port,
            summary=f"AUTH {username}:[pubkey:{fingerprint}]",
            details={
                "auth_type": "publickey",
                "username": username,
                "key_type": key.get_name(),
                "fingerprint": fingerprint,
            },
            raw_data=f"{username}:pubkey:{fingerprint}".encode(),
        )

        loop = self.handler._loop
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.handler.emit(request), loop)

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED


class SshHandler(BaseProtocolHandler):
    """Honeypot SSH server that captures authentication attempts."""

    name: str = "SSH"
    default_port: int = 22

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._running = False
        self._host_key: paramiko.RSAKey | None = None
        self._socket: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self):
        self._loop = asyncio.get_running_loop()
        self._host_key = paramiko.RSAKey.generate(2048)
        self._running = True

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind((self.bind, self.port))
        sock.listen(10)
        self._socket = sock

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
        )
        self._accept_thread.start()
        logger.info("SSH handler listening on %s:%d", self.bind, self.port)

    async def stop(self):
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        if self._accept_thread:
            self._accept_thread.join(timeout=5)
        await super().stop()

    # ------------------------------------------------------------------

    def _accept_loop(self):
        """Run in a background thread: accept incoming connections."""
        while self._running:
            try:
                client_sock, addr = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            t = threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
            )
            t.start()

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        """Handle a single SSH client connection (runs in its own thread)."""
        transport = None
        try:
            client_sock.settimeout(_CONNECTION_TIMEOUT)
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self._host_key)

            server = PegaSSHServer(self, addr)
            transport.start_server(server=server)

            # Wait for auth to complete (or fail / timeout)
            channel = transport.accept(timeout=_CONNECTION_TIMEOUT)
            if channel is not None:
                channel.close()

        except paramiko.SSHException:
            logger.debug("SSH negotiation error from %s", addr[0])
        except Exception:
            logger.debug("SSH handler error for %s", addr[0], exc_info=True)
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
            try:
                client_sock.close()
            except Exception:
                pass
