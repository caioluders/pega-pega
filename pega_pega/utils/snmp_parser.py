"""Minimal SNMPv1/v2c parser and response builder.

Decodes enough of the BER wire format to extract community strings,
PDU types, and OID variable bindings.  No external dependencies.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# BER tag constants
# ---------------------------------------------------------------------------

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30

# SNMP PDU types (context-class, constructed)
_PDU_GET_REQUEST = 0xA0
_PDU_GET_NEXT_REQUEST = 0xA1
_PDU_GET_RESPONSE = 0xA2
_PDU_SET_REQUEST = 0xA3

_PDU_TYPE_NAMES = {
    0xA0: "GetRequest",
    0xA1: "GetNextRequest",
    0xA2: "GetResponse",
    0xA3: "SetRequest",
}


# ---------------------------------------------------------------------------
# BER decoding helpers
# ---------------------------------------------------------------------------

def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length.  Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("BER length: unexpected end of data")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ValueError("BER indefinite length not supported")
    if offset + 1 + num_bytes > len(data):
        raise ValueError("BER length: not enough bytes")
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


def _decode_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Decode one TLV.  Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        raise ValueError("BER TLV: unexpected end of data")
    tag = data[offset]
    length, off = _decode_length(data, offset + 1)
    if off + length > len(data):
        raise ValueError("BER TLV: value extends past data")
    value = data[off : off + length]
    return tag, value, off + length


def _decode_integer(data: bytes) -> int:
    """Decode a BER INTEGER value."""
    return int.from_bytes(data, "big", signed=True)


def _decode_oid(data: bytes) -> str:
    """Decode a BER OBJECT IDENTIFIER value into dotted string form."""
    if len(data) == 0:
        return ""
    # First octet encodes the first two components
    first = data[0]
    components = [first // 40, first % 40]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            components.append(value)
            value = 0
    return ".".join(str(c) for c in components)


def _decode_sequence_items(data: bytes) -> list[tuple[int, bytes]]:
    """Decode all TLV items inside a SEQUENCE."""
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = _decode_tlv(data, offset)
        items.append((tag, value))
    return items


# ---------------------------------------------------------------------------
# BER encoding helpers
# ---------------------------------------------------------------------------

def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(value: int) -> bytes:
    if value == 0:
        return _encode_tlv(_TAG_INTEGER, b"\x00")
    byte_len = (value.bit_length() + 8) // 8
    return _encode_tlv(_TAG_INTEGER, value.to_bytes(byte_len, "big", signed=True))


def _encode_octet_string(value: bytes) -> bytes:
    return _encode_tlv(_TAG_OCTET_STRING, value)


def _encode_null() -> bytes:
    return _encode_tlv(_TAG_NULL, b"")


def _encode_oid(dotted: str) -> bytes:
    """Encode a dotted OID string into BER OBJECT IDENTIFIER."""
    parts = [int(x) for x in dotted.split(".")]
    if len(parts) < 2:
        parts.extend([0] * (2 - len(parts)))
    result = bytearray([parts[0] * 40 + parts[1]])
    for component in parts[2:]:
        if component == 0:
            result.append(0)
        else:
            # Encode in base-128 with high bit set on all but last byte
            sub = []
            val = component
            while val > 0:
                sub.append(val & 0x7F)
                val >>= 7
            sub.reverse()
            for i in range(len(sub) - 1):
                sub[i] |= 0x80
            result.extend(sub)
    return _encode_tlv(_TAG_OID, bytes(result))


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def parse_snmp_message(data: bytes) -> dict:
    """Parse an SNMPv1/v2c message from raw bytes.

    Returns a dict with:
        - ``version`` (int): 0 = v1, 1 = v2c
        - ``version_name`` (str): "v1" or "v2c"
        - ``community`` (str)
        - ``pdu_type`` (int)
        - ``pdu_type_name`` (str)
        - ``request_id`` (int)
        - ``variable_bindings`` (list of dicts with oid + value)
    """
    # Outer SEQUENCE
    tag, seq_data, _ = _decode_tlv(data, 0)
    if tag != _TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE 0x30, got 0x{tag:02x}")

    items = _decode_sequence_items(seq_data)
    if len(items) < 3:
        raise ValueError("SNMP message needs version + community + PDU")

    # Version
    version = _decode_integer(items[0][1])
    version_name = {0: "v1", 1: "v2c"}.get(version, f"v{version}")

    # Community string
    community = items[1][1].decode("utf-8", errors="replace")

    # PDU
    pdu_tag = items[2][0]
    pdu_data = items[2][1]
    pdu_type_name = _PDU_TYPE_NAMES.get(pdu_tag, f"PDU(0x{pdu_tag:02x})")

    # Parse PDU internals
    pdu_items = _decode_sequence_items(pdu_data)
    request_id = _decode_integer(pdu_items[0][1]) if len(pdu_items) > 0 else 0
    # pdu_items[1] = error-status, pdu_items[2] = error-index, pdu_items[3] = variable-bindings

    variable_bindings: list[dict] = []
    if len(pdu_items) >= 4:
        # Variable bindings is a SEQUENCE of SEQUENCE { OID, value }
        varbind_items = _decode_sequence_items(pdu_items[3][1])
        for _, vb_data in varbind_items:
            vb_items = _decode_sequence_items(vb_data)
            if len(vb_items) >= 1:
                oid = _decode_oid(vb_items[0][1])
                value_tag = vb_items[1][0] if len(vb_items) > 1 else _TAG_NULL
                value_data = vb_items[1][1] if len(vb_items) > 1 else b""
                variable_bindings.append({
                    "oid": oid,
                    "value_tag": f"0x{value_tag:02x}",
                    "value_hex": value_data.hex(),
                })

    return {
        "version": version,
        "version_name": version_name,
        "community": community,
        "pdu_type": pdu_tag,
        "pdu_type_name": pdu_type_name,
        "request_id": request_id,
        "variable_bindings": variable_bindings,
    }


# ---------------------------------------------------------------------------
# Public API — response building
# ---------------------------------------------------------------------------

def build_snmp_response(data: bytes, parsed: dict) -> bytes:
    """Build a GetResponse for the given request with noSuchName error.

    Parameters
    ----------
    data:
        Original raw SNMP message bytes (not directly used, kept for API symmetry).
    parsed:
        Parsed SNMP dict as returned by :func:`parse_snmp_message`.
    """
    version = parsed["version"]
    community = parsed["community"]
    request_id = parsed["request_id"]
    varbinds = parsed["variable_bindings"]

    # Rebuild variable bindings (return the same OIDs with NULL values)
    vb_encoded = b""
    for vb in varbinds:
        oid_enc = _encode_oid(vb["oid"])
        val_enc = _encode_null()
        vb_encoded += _encode_tlv(_TAG_SEQUENCE, oid_enc + val_enc)
    varbind_seq = _encode_tlv(_TAG_SEQUENCE, vb_encoded)

    # Error status = 2 (noSuchName), error index = 1 (first varbind)
    error_status = _encode_integer(2)
    error_index = _encode_integer(1 if varbinds else 0)

    pdu_body = (
        _encode_integer(request_id)
        + error_status
        + error_index
        + varbind_seq
    )
    pdu = _encode_tlv(_PDU_GET_RESPONSE, pdu_body)

    # Message: version + community + PDU
    message_body = (
        _encode_integer(version)
        + _encode_octet_string(community.encode("utf-8"))
        + pdu
    )
    return _encode_tlv(_TAG_SEQUENCE, message_body)
