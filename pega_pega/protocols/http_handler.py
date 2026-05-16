import asyncio
import base64
import logging
from urllib.parse import urlparse, parse_qs

from pathlib import Path

from .base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol
from ..utils.subdomain import extract_subdomain
from ..utils.ntlm_parser import (
    decode_ntlm_auth,
    parse_ntlm_type,
    parse_ntlm_type3,
    build_ntlm_challenge,
    generate_challenge,
    NTLM_NEGOTIATE,
    NTLM_AUTHENTICATE,
)

ACME_WEBROOT = Path("/tmp/pega-pega-acme")

logger = logging.getLogger("pega-pega")

READ_TIMEOUT = 30
KEEPALIVE_TIMEOUT = 30
MAX_HEADER_SIZE = 64 * 1024
MAX_BODY_SIZE = 4 * 1024 * 1024

HTML_RESPONSE = (
    "<!DOCTYPE html>\n"
    "<html><head><title>OK</title></head>"
    "<body><h1>200 OK</h1></body></html>"
)
JSON_OK_RESPONSE = '{"status":"ok"}'


class HttpHandler(BaseProtocolHandler):
    name = "HTTP"
    default_port = 80
    mock_matcher = None  # injected by server.py
    def __init__(self, proto_config, global_config, bus):
        super().__init__(proto_config, global_config, bus)
        self._conn_challenges: dict[int, bytes] = {}  # writer id → server challenge

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self):
        server = await asyncio.start_server(
            self._handle_connection,
            host=self.bind,
            port=self.port,
        )
        self._servers.append(server)
        logger.info("HTTP handler listening on %s:%d", self.bind, self.port)

    # ------------------------------------------------------------------
    # Connection loop (supports keep-alive)
    # ------------------------------------------------------------------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = peer[1] if peer else 0

        try:
            while True:
                try:
                    request_info = await asyncio.wait_for(
                        self._read_request(reader),
                        timeout=KEEPALIVE_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    break
                except ConnectionError:
                    break

                if request_info is None:
                    # Client closed cleanly or sent empty data
                    break

                method, path, version, headers, body, raw = request_info

                # Extract query params
                parsed = urlparse(path)
                query_params = parse_qs(parsed.query)

                # Subdomain
                host_header = headers.get("host", "")
                subdomain = extract_subdomain(
                    host_header, self.global_config.domain
                )

                summary = f"{method} {path}"
                details = {
                    "method": method,
                    "path": parsed.path,
                    "http_version": version,
                    "headers": headers,
                    "body": body.decode("utf-8", errors="replace") if body else "",
                    "query_params": query_params,
                }

                captured = CapturedRequest(
                    protocol=Protocol.HTTP,
                    source_ip=source_ip,
                    source_port=source_port,
                    dest_port=self.port,
                    subdomain=subdomain,
                    summary=summary,
                    details=details,
                    raw_data=raw,
                )
                await self.emit(captured)
                logger.info(
                    "HTTP %s %s from %s:%d (Host: %s)",
                    method, path, source_ip, source_port, host_header,
                )

                # Send response — check mock rules first
                mock_rule = None
                if self.mock_matcher:
                    mock_rule = self.mock_matcher.match(method, parsed.path)

                if mock_rule and mock_rule.get("ntlm_capture"):
                    # NTLM handshake — connection-based multi-step auth
                    auth_header = headers.get("authorization", "")
                    ntlm_data = decode_ntlm_auth(auth_header) if auth_header else None
                    ntlm_type = parse_ntlm_type(ntlm_data) if ntlm_data else None

                    if ntlm_type == NTLM_NEGOTIATE:
                        # Type 1 received — send Type 2 challenge
                        ntlm_challenge = generate_challenge()
                        # Store challenge on connection for Type 3 parsing
                        self._conn_challenges[id(writer)] = ntlm_challenge
                        challenge_b64 = base64.b64encode(
                            build_ntlm_challenge(ntlm_challenge)
                        ).decode()
                        response_bytes = self._build_ntlm_challenge_response(
                            version, challenge_b64
                        )
                    elif ntlm_type == NTLM_AUTHENTICATE:
                        # Type 3 received — extract hash
                        server_challenge = self._conn_challenges.pop(id(writer), b"\x00" * 8)
                        result = parse_ntlm_type3(ntlm_data, server_challenge)
                        if result:
                            details["ntlm_hash"] = result["hash"]
                            details["ntlm_user"] = result["user"]
                            details["ntlm_domain"] = result["domain"]
                            captured.details = details
                            captured.summary = f"{method} {path} [NTLM: {result['user']}]"
                            logger.info(
                                "NTLM hash captured: %s from %s:%d",
                                result["hash"], source_ip, source_port,
                            )
                            # Re-emit with NTLM details
                            await self.emit(captured)
                        response_bytes = self._build_mock_response(mock_rule, version)
                    else:
                        # No auth header — send initial 401
                        response_bytes = self._build_ntlm_initial_response(version)
                elif mock_rule:
                    logger.info("Mock rule matched: %s %s → rule %s", method, parsed.path, mock_rule.get("id", "?"))
                    response_bytes = self._build_mock_response(mock_rule, version)
                else:
                    response_bytes = self._build_response(method, version, parsed.path)
                try:
                    writer.write(response_bytes)
                    await writer.drain()
                except ConnectionError:
                    break

                # Decide keep-alive
                connection_hdr = headers.get("connection", "").lower()
                if version == "HTTP/1.0" and connection_hdr != "keep-alive":
                    break
                if connection_hdr == "close":
                    break
        except Exception:
            logger.debug("HTTP connection error from %s:%d", source_ip, source_port, exc_info=True)
        finally:
            self._conn_challenges.pop(id(writer), None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Request parsing
    # ------------------------------------------------------------------

    async def _read_request(self, reader: asyncio.StreamReader):
        """Read and parse a single HTTP request.

        Returns (method, path, version, headers_dict, body_bytes, raw_bytes)
        or None if the connection is closed.
        """
        raw_chunks: list[bytes] = []

        # --- Read the request line -------------------------------------------
        try:
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise
        except Exception:
            return None

        if not request_line:
            return None

        raw_chunks.append(request_line)

        # Strip and decode
        try:
            request_str = request_line.decode("utf-8", errors="replace").strip()
        except Exception:
            request_str = ""

        parts = request_str.split(None, 2)
        if len(parts) == 3:
            method, path, version = parts
        elif len(parts) == 2:
            method, path = parts
            version = "HTTP/1.0"
        elif len(parts) == 1:
            method = parts[0]
            path = "/"
            version = "HTTP/1.0"
        else:
            # Completely empty / garbage -- emit what we have
            method, path, version = "UNKNOWN", "/", "HTTP/1.0"

        # --- Read headers ----------------------------------------------------
        headers: dict[str, str] = {}
        header_bytes = 0
        while True:
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=READ_TIMEOUT,
                )
            except asyncio.TimeoutError:
                break

            raw_chunks.append(line)
            header_bytes += len(line)

            if header_bytes > MAX_HEADER_SIZE:
                logger.warning("HTTP headers exceeded size limit from peer")
                break

            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                # Empty line signals end of headers
                break

            colon = decoded.find(":")
            if colon != -1:
                key = decoded[:colon].strip().lower()
                value = decoded[colon + 1 :].strip()
                headers[key] = value

        # --- Read body -------------------------------------------------------
        body = b""
        transfer_encoding = headers.get("transfer-encoding", "").lower()
        content_length_str = headers.get("content-length", "")

        if transfer_encoding == "chunked":
            body = await self._read_chunked_body(reader, raw_chunks)
        elif content_length_str:
            try:
                content_length = int(content_length_str)
            except ValueError:
                content_length = 0

            if 0 < content_length <= MAX_BODY_SIZE:
                try:
                    body = await asyncio.wait_for(
                        reader.readexactly(content_length),
                        timeout=READ_TIMEOUT,
                    )
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as exc:
                    if isinstance(exc, asyncio.IncompleteReadError):
                        body = exc.partial
                    else:
                        body = b""
                raw_chunks.append(body)

        raw = b"".join(raw_chunks)
        return method, path, version, headers, body, raw

    async def _read_chunked_body(
        self,
        reader: asyncio.StreamReader,
        raw_chunks: list[bytes],
    ) -> bytes:
        """Read a chunked Transfer-Encoding body."""
        body_parts: list[bytes] = []
        total = 0

        while True:
            try:
                size_line = await asyncio.wait_for(
                    reader.readline(), timeout=READ_TIMEOUT,
                )
            except (asyncio.TimeoutError, ConnectionError):
                break

            raw_chunks.append(size_line)
            size_str = size_line.decode("utf-8", errors="replace").strip()

            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                break

            if chunk_size == 0:
                # Read optional trailing CRLF
                try:
                    trailer = await asyncio.wait_for(
                        reader.readline(), timeout=READ_TIMEOUT,
                    )
                    raw_chunks.append(trailer)
                except Exception:
                    pass
                break

            if total + chunk_size > MAX_BODY_SIZE:
                break

            try:
                chunk_data = await asyncio.wait_for(
                    reader.readexactly(chunk_size),
                    timeout=READ_TIMEOUT,
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as exc:
                if isinstance(exc, asyncio.IncompleteReadError):
                    body_parts.append(exc.partial)
                break

            raw_chunks.append(chunk_data)
            body_parts.append(chunk_data)
            total += chunk_size

            # Consume trailing CRLF after chunk data
            try:
                crlf = await asyncio.wait_for(
                    reader.readline(), timeout=READ_TIMEOUT,
                )
                raw_chunks.append(crlf)
            except Exception:
                break

        return b"".join(body_parts)

    # ------------------------------------------------------------------
    # Response building
    # ------------------------------------------------------------------

    @staticmethod
    def _build_response(method: str, version: str, path: str = "/") -> bytes:
        """Build a realistic HTTP response.

        Serves ACME challenge tokens for Let's Encrypt webroot validation.
        """
        # Serve ACME challenge files for Let's Encrypt
        acme_prefix = "/.well-known/acme-challenge/"
        if path.startswith(acme_prefix):
            token = path[len(acme_prefix):]
            # Sanitize: only allow alphanumeric, dash, underscore, dot
            if token and all(c.isalnum() or c in "-_." for c in token):
                challenge_file = ACME_WEBROOT / ".well-known" / "acme-challenge" / token
                if challenge_file.exists():
                    body = challenge_file.read_bytes()
                    status_line = f"{version} 200 OK\r\n"
                    headers = (
                        "Content-Type: text/plain\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        "Server: pega-pega\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    )
                    return (status_line + headers).encode() + body

        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            body = JSON_OK_RESPONSE.encode()
            content_type = "application/json"
        else:
            body = HTML_RESPONSE.encode()
            content_type = "text/html; charset=utf-8"

        status_line = f"{version} 200 OK\r\n"
        headers = (
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Server: pega-pega\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
        return (status_line + headers).encode() + body

    @staticmethod
    def _build_ntlm_initial_response(version: str) -> bytes:
        """401 response requesting NTLM auth (initial, no token)."""
        body = b"<html><body><h1>401 Unauthorized</h1></body></html>"
        return (
            f"{version} 401 Unauthorized\r\n"
            "WWW-Authenticate: NTLM\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n"
            "Server: pega-pega\r\n"
            "\r\n"
        ).encode() + body

    @staticmethod
    def _build_ntlm_challenge_response(version: str, challenge_b64: str) -> bytes:
        """401 response with Type 2 NTLM challenge token."""
        body = b"<html><body><h1>401 Unauthorized</h1></body></html>"
        return (
            f"{version} 401 Unauthorized\r\n"
            f"WWW-Authenticate: NTLM {challenge_b64}\r\n"
            "Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: keep-alive\r\n"
            "Server: pega-pega\r\n"
            "\r\n"
        ).encode() + body

    @staticmethod
    def _build_mock_response(rule: dict, version: str) -> bytes:
        """Build an HTTP response from a mock rule."""
        status_code = rule.get("status_code", 200)
        reasons = {
            200: "OK", 201: "Created", 204: "No Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
            404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
            422: "Unprocessable Entity", 429: "Too Many Requests",
            500: "Internal Server Error", 502: "Bad Gateway",
            503: "Service Unavailable",
        }
        reason = reasons.get(status_code, "OK")
        content_type = rule.get("content_type", "application/json")

        # Serve file data from DB if available, otherwise use response_body
        file_data = rule.get("response_file_data")
        if file_data:
            body = file_data if isinstance(file_data, bytes) else bytes(file_data)
        else:
            body = rule.get("response_body", "").encode("utf-8")

        header_lines = [
            f"{version} {status_code} {reason}\r\n",
            f"Content-Type: {content_type}\r\n",
            f"Content-Length: {len(body)}\r\n",
            "Server: pega-pega\r\n",
            "Connection: keep-alive\r\n",
        ]
        for k, v in rule.get("headers", {}).items():
            header_lines.append(f"{k}: {v}\r\n")
        header_lines.append("\r\n")

        return "".join(header_lines).encode() + body
