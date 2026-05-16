"""Tests for the NTLM parser utility."""

import base64
import struct

from pega_pega.utils.ntlm_parser import (
    NTLM_AUTHENTICATE,
    NTLM_CHALLENGE,
    NTLM_NEGOTIATE,
    NTLM_SIGNATURE,
    build_ntlm_challenge,
    decode_ntlm_auth,
    generate_challenge,
    parse_ntlm_type,
    parse_ntlm_type3,
)


def test_generate_challenge_length():
    challenge = generate_challenge()
    assert len(challenge) == 8


def test_generate_challenge_random():
    c1 = generate_challenge()
    c2 = generate_challenge()
    assert c1 != c2


def test_build_ntlm_challenge_signature():
    challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    msg = build_ntlm_challenge(challenge)
    assert msg[:8] == NTLM_SIGNATURE


def test_build_ntlm_challenge_type():
    challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    msg = build_ntlm_challenge(challenge)
    msg_type = struct.unpack_from("<I", msg, 8)[0]
    assert msg_type == NTLM_CHALLENGE


def test_build_ntlm_challenge_contains_challenge():
    challenge = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22"
    msg = build_ntlm_challenge(challenge)
    # Challenge is at offset 24 (after signature + type + target name fields + flags)
    assert msg[24:32] == challenge


def test_parse_ntlm_type_negotiate():
    msg = NTLM_SIGNATURE + struct.pack("<I", NTLM_NEGOTIATE) + b"\x00" * 20
    assert parse_ntlm_type(msg) == NTLM_NEGOTIATE


def test_parse_ntlm_type_challenge():
    challenge = generate_challenge()
    msg = build_ntlm_challenge(challenge)
    assert parse_ntlm_type(msg) == NTLM_CHALLENGE


def test_parse_ntlm_type_authenticate():
    msg = NTLM_SIGNATURE + struct.pack("<I", NTLM_AUTHENTICATE) + b"\x00" * 80
    assert parse_ntlm_type(msg) == NTLM_AUTHENTICATE


def test_parse_ntlm_type_invalid():
    assert parse_ntlm_type(b"short") is None
    assert parse_ntlm_type(b"GARBAGE\x00\x01\x00\x00\x00" + b"\x00" * 20) is None
    assert parse_ntlm_type(b"") is None


def test_parse_ntlm_type_bad_type_number():
    msg = NTLM_SIGNATURE + struct.pack("<I", 99) + b"\x00" * 20
    assert parse_ntlm_type(msg) is None


def test_decode_ntlm_auth_valid():
    raw = NTLM_SIGNATURE + struct.pack("<I", NTLM_NEGOTIATE) + b"\x00" * 20
    b64 = base64.b64encode(raw).decode()
    result = decode_ntlm_auth(f"NTLM {b64}")
    assert result == raw


def test_decode_ntlm_auth_case_insensitive():
    raw = b"\x01\x02\x03"
    b64 = base64.b64encode(raw).decode()
    result = decode_ntlm_auth(f"ntlm {b64}")
    assert result == raw


def test_decode_ntlm_auth_invalid_scheme():
    result = decode_ntlm_auth("Basic dXNlcjpwYXNz")
    assert result is None


def test_decode_ntlm_auth_no_blob():
    assert decode_ntlm_auth("NTLM") is None
    assert decode_ntlm_auth("") is None


def test_parse_ntlm_type3_extracts_hash():
    """Build a synthetic Type 3 message and verify hash extraction."""
    server_challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"

    # Build a minimal Type 3 message
    user = "testuser".encode("utf-16-le")
    domain = "WORKGROUP".encode("utf-16-le")
    # NTLMv2 response: 16 bytes NTProofStr + blob
    nt_proof_str = b"\xaa" * 16
    blob = b"\xbb" * 48
    nt_response = nt_proof_str + blob
    lm_response = b"\x00" * 24

    # Offsets: header is 88 bytes
    header_size = 88
    lm_offset = header_size
    nt_offset = lm_offset + len(lm_response)
    dom_offset = nt_offset + len(nt_response)
    user_offset = dom_offset + len(domain)

    msg = bytearray()
    msg += NTLM_SIGNATURE
    msg += struct.pack("<I", NTLM_AUTHENTICATE)
    # LM response (len, max_len, offset)
    msg += struct.pack("<HHI", len(lm_response), len(lm_response), lm_offset)
    # NT response
    msg += struct.pack("<HHI", len(nt_response), len(nt_response), nt_offset)
    # Domain
    msg += struct.pack("<HHI", len(domain), len(domain), dom_offset)
    # User
    msg += struct.pack("<HHI", len(user), len(user), user_offset)
    # Workstation (empty)
    ws_offset = user_offset + len(user)
    msg += struct.pack("<HHI", 0, 0, ws_offset)
    # Encrypted random session key (empty)
    msg += struct.pack("<HHI", 0, 0, ws_offset)
    # Negotiate flags
    msg += struct.pack("<I", 0)
    # Pad to header_size
    while len(msg) < header_size:
        msg += b"\x00"

    # Payload
    msg += lm_response
    msg += nt_response
    msg += domain
    msg += user

    result = parse_ntlm_type3(bytes(msg), server_challenge)
    assert result is not None
    assert result["user"] == "testuser"
    assert result["domain"] == "WORKGROUP"
    assert server_challenge.hex() in result["hash"]
    assert nt_proof_str.hex() in result["hash"]
    assert blob.hex() in result["hash"]
    # Verify format: user::domain:challenge:ntproofstr:blob
    parts = result["hash"].split(":")
    assert parts[0] == "testuser"
    assert parts[1] == ""
    assert parts[2] == "WORKGROUP"
    assert parts[3] == server_challenge.hex()
    assert parts[4] == nt_proof_str.hex()
    assert parts[5] == blob.hex()


def test_parse_ntlm_type3_too_short():
    result = parse_ntlm_type3(b"short", b"\x00" * 8)
    assert result is None


def test_parse_ntlm_type3_wrong_signature():
    msg = b"GARBAGE\x00" + struct.pack("<I", NTLM_AUTHENTICATE) + b"\x00" * 80
    result = parse_ntlm_type3(msg, b"\x00" * 8)
    assert result is None
