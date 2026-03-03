"""Minimal LDAP/BER parser and response builder.

Decodes enough of the BER/ASN.1 wire format to log interesting LDAP
fields (bind DN, credentials, search base/filter).  No external
dependencies — all BER encoding/decoding is done manually.
"""

from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# BER tag constants
# ---------------------------------------------------------------------------

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_ENUMERATED = 0x0A
_TAG_SEQUENCE = 0x30

# LDAP application tags (constructed, context-class = 0x60)
_APP_BIND_REQUEST = 0x60       # [APPLICATION 0]
_APP_BIND_RESPONSE = 0x61      # [APPLICATION 1]
_APP_UNBIND_REQUEST = 0x42     # [APPLICATION 2] — primitive
_APP_SEARCH_REQUEST = 0x63     # [APPLICATION 3]
_APP_SEARCH_RESULT_DONE = 0x65 # [APPLICATION 5]

# Context-specific tags inside BindRequest authentication choice
_CTX_SIMPLE_AUTH = 0x80        # [0] IMPLICIT OCTET STRING
_CTX_SASL_AUTH = 0xA3          # [3] CONSTRUCTED


# ---------------------------------------------------------------------------
# BER decoding helpers
# ---------------------------------------------------------------------------

def _decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a BER length field.  Returns (length, new_offset)."""
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
    """Decode one TLV element.  Returns (tag, value_bytes, new_offset)."""
    if offset >= len(data):
        raise ValueError("BER TLV: unexpected end of data")
    tag = data[offset]
    length, offset = _decode_length(data, offset + 1)
    if offset + length > len(data):
        raise ValueError("BER TLV: value extends past data")
    value = data[offset : offset + length]
    return tag, value, offset + length


def _decode_integer(data: bytes) -> int:
    """Decode a BER INTEGER value (already stripped of tag+length)."""
    return int.from_bytes(data, "big", signed=True)


def _decode_string(data: bytes) -> str:
    """Decode an OCTET STRING value as UTF-8."""
    return data.decode("utf-8", errors="replace")


def _decode_sequence_items(data: bytes) -> list[tuple[int, bytes]]:
    """Decode all TLV items inside a SEQUENCE/constructed value."""
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
    """Encode a BER length."""
    if length < 0x80:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


def _encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode a TLV element."""
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(value: int) -> bytes:
    """Encode a BER INTEGER."""
    if value == 0:
        return _encode_tlv(_TAG_INTEGER, b"\x00")
    byte_len = (value.bit_length() + 8) // 8  # +8 for sign bit
    return _encode_tlv(_TAG_INTEGER, value.to_bytes(byte_len, "big", signed=True))


def _encode_octet_string(value: str | bytes) -> bytes:
    """Encode a BER OCTET STRING."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _encode_tlv(_TAG_OCTET_STRING, value)


def _encode_enumerated(value: int) -> bytes:
    """Encode a BER ENUMERATED."""
    if value == 0:
        return _encode_tlv(_TAG_ENUMERATED, b"\x00")
    byte_len = (value.bit_length() + 8) // 8
    return _encode_tlv(_TAG_ENUMERATED, value.to_bytes(byte_len, "big", signed=True))


# ---------------------------------------------------------------------------
# LDAP message parsing
# ---------------------------------------------------------------------------

def _parse_bind_request(data: bytes) -> dict:
    """Parse a BindRequest body."""
    items = _decode_sequence_items(data)
    result: dict = {"operation": "BindRequest", "version": 0, "dn": "", "auth": {}}

    if len(items) >= 1:
        result["version"] = _decode_integer(items[0][1])
    if len(items) >= 2:
        result["dn"] = _decode_string(items[1][1])
    if len(items) >= 3:
        auth_tag, auth_value = items[2]
        if auth_tag == _CTX_SIMPLE_AUTH:
            result["auth"] = {
                "method": "simple",
                "password": _decode_string(auth_value),
            }
        elif auth_tag == _CTX_SASL_AUTH:
            # SASL: first element is mechanism name
            sasl_items = _decode_sequence_items(auth_value)
            mechanism = _decode_string(sasl_items[0][1]) if sasl_items else "unknown"
            result["auth"] = {"method": "SASL", "mechanism": mechanism}
        else:
            result["auth"] = {"method": f"unknown(tag=0x{auth_tag:02x})"}

    return result


def _parse_search_request(data: bytes) -> dict:
    """Parse a SearchRequest body."""
    items = _decode_sequence_items(data)
    result: dict = {
        "operation": "SearchRequest",
        "base": "",
        "scope": 0,
        "filter": "(unknown)",
    }

    scope_names = {0: "baseObject", 1: "singleLevel", 2: "wholeSubtree"}

    if len(items) >= 1:
        result["base"] = _decode_string(items[0][1])
    if len(items) >= 2:
        scope_val = _decode_integer(items[1][1])
        result["scope"] = scope_names.get(scope_val, str(scope_val))
    # items[2] = derefAliases, items[3] = sizeLimit, items[4] = timeLimit,
    # items[5] = typesOnly, items[6] = filter
    if len(items) >= 7:
        result["filter"] = _format_filter(items[6][0], items[6][1])
    # items[7] = attributes
    if len(items) >= 8:
        attr_items = _decode_sequence_items(items[7][1])
        result["attributes"] = [_decode_string(v) for _, v in attr_items]

    return result


def _format_filter(tag: int, data: bytes) -> str:
    """Produce a rough string representation of an LDAP search filter."""
    # Context-specific constructed tags for filter choices
    # 0xa0 = AND, 0xa1 = OR, 0xa2 = NOT, 0xa3 = equalityMatch,
    # 0xa4 = substrings, 0xa7 = present, etc.
    try:
        if tag == 0xA0:  # AND
            subs = _decode_sequence_items(data)
            inner = "".join(_format_filter(t, v) for t, v in subs)
            return f"(&{inner})"
        elif tag == 0xA1:  # OR
            subs = _decode_sequence_items(data)
            inner = "".join(_format_filter(t, v) for t, v in subs)
            return f"(|{inner})"
        elif tag == 0xA2:  # NOT
            sub_tag, sub_val, _ = _decode_tlv(data, 0)
            return f"(!{_format_filter(sub_tag, sub_val)})"
        elif tag == 0xA3:  # equalityMatch
            items = _decode_sequence_items(data)
            attr = _decode_string(items[0][1]) if len(items) > 0 else "?"
            val = _decode_string(items[1][1]) if len(items) > 1 else "?"
            return f"({attr}={val})"
        elif tag == 0x87:  # present (context [7] primitive)
            return f"({_decode_string(data)}=*)"
        elif tag == 0xA4:  # substrings
            items = _decode_sequence_items(data)
            attr = _decode_string(items[0][1]) if items else "?"
            return f"({attr}=*substr*)"
        else:
            return f"(filter:0x{tag:02x})"
    except Exception:
        return "(parse-error)"


def parse_ldap_message(data: bytes) -> dict:
    """Parse an LDAP message from raw bytes.

    Returns a dict with at minimum:
        - ``message_id`` (int)
        - ``operation`` (str)
    Plus operation-specific fields.
    """
    # Outer SEQUENCE
    tag, seq_data, _ = _decode_tlv(data, 0)
    if tag != _TAG_SEQUENCE:
        raise ValueError(f"Expected SEQUENCE tag 0x30, got 0x{tag:02x}")

    items = _decode_sequence_items(seq_data)
    if len(items) < 2:
        raise ValueError("LDAP message needs at least messageID + operation")

    # messageID (INTEGER)
    message_id = _decode_integer(items[0][1])

    # Protocol operation (APPLICATION tagged)
    op_tag = items[1][0]
    op_data = items[1][1]

    result: dict

    if op_tag == _APP_BIND_REQUEST:
        result = _parse_bind_request(op_data)
    elif op_tag == _APP_SEARCH_REQUEST:
        result = _parse_search_request(op_data)
    elif op_tag == _APP_UNBIND_REQUEST:
        result = {"operation": "UnbindRequest"}
    else:
        result = {"operation": f"Unknown(tag=0x{op_tag:02x})"}

    result["message_id"] = message_id
    return result


# ---------------------------------------------------------------------------
# Response builders
# ---------------------------------------------------------------------------

def build_bind_response(message_id: int, success: bool = True) -> bytes:
    """Build a BindResponse LDAP message.

    Result code 0 = success, 49 = invalidCredentials.
    """
    result_code = 0 if success else 49

    # BindResponse body: resultCode (ENUM), matchedDN (OCTET STRING), diagnosticMessage (OCTET STRING)
    body = _encode_enumerated(result_code)
    body += _encode_octet_string("")  # matchedDN
    body += _encode_octet_string("")  # diagnosticMessage

    # Wrap in APPLICATION 1 constructed tag
    op = _encode_tlv(_APP_BIND_RESPONSE, body)

    # Wrap in outer SEQUENCE with messageID
    inner = _encode_integer(message_id) + op
    return _encode_tlv(_TAG_SEQUENCE, inner)


def build_search_done(message_id: int) -> bytes:
    """Build a SearchResultDone LDAP message with result code 0 (success)."""
    body = _encode_enumerated(0)       # resultCode
    body += _encode_octet_string("")   # matchedDN
    body += _encode_octet_string("")   # diagnosticMessage

    op = _encode_tlv(_APP_SEARCH_RESULT_DONE, body)
    inner = _encode_integer(message_id) + op
    return _encode_tlv(_TAG_SEQUENCE, inner)
