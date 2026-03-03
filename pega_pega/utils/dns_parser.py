"""Minimal DNS wire-format parser and response builder.

Handles enough of RFC 1035 to parse queries and craft A/AAAA responses.
No external dependencies.
"""

from __future__ import annotations

import struct
import socket

# ---------------------------------------------------------------------------
# Common query-type constants
# ---------------------------------------------------------------------------

_QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    65: "HTTPS",
    99: "SPF",
    255: "ANY",
    257: "CAA",
}


def qtype_to_str(qtype: int) -> str:
    """Convert a numeric DNS query type to its human-readable name."""
    return _QTYPE_MAP.get(qtype, f"TYPE{qtype}")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS label-encoded domain name, handling pointer compression.

    Returns ``(domain_name, new_offset)`` where *new_offset* points to the
    byte immediately after the name field in the original data.
    """
    labels: list[str] = []
    jumped = False
    end_offset = offset  # track where the *original* pointer should resume

    seen_offsets: set[int] = set()  # guard against infinite pointer loops

    while True:
        if offset >= len(data):
            raise ValueError("DNS name extends past end of packet")

        if offset in seen_offsets:
            raise ValueError("Circular pointer detected in DNS name")
        seen_offsets.add(offset)

        length = data[offset]

        if length == 0:
            # Root label — end of name
            if not jumped:
                end_offset = offset + 1
            break

        if (length & 0xC0) == 0xC0:
            # Pointer (2 bytes)
            if offset + 1 >= len(data):
                raise ValueError("DNS pointer extends past end of packet")
            pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
            if not jumped:
                end_offset = offset + 2
            jumped = True
            offset = pointer
            continue

        # Normal label
        offset += 1
        if offset + length > len(data):
            raise ValueError("DNS label extends past end of packet")
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), end_offset


# ---------------------------------------------------------------------------
# Public API — parsing
# ---------------------------------------------------------------------------

def parse_dns_query(data: bytes) -> dict:
    """Parse a DNS query packet from raw bytes.

    Returns a dict with keys:
        - ``transaction_id``  (int)
        - ``flags``           (int)
        - ``questions``       (list of dicts with *qname*, *qtype*, *qclass*)
    """
    if len(data) < 12:
        raise ValueError(f"Packet too short for DNS header ({len(data)} bytes)")

    tid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])

    questions: list[dict] = []
    offset = 12

    for _ in range(qdcount):
        qname, offset = _decode_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Packet truncated in question section")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append({
            "qname": qname,
            "qtype": qtype,
            "qclass": qclass,
        })

    return {
        "transaction_id": tid,
        "flags": flags,
        "questions": questions,
    }


# ---------------------------------------------------------------------------
# Public API — response building
# ---------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    """Encode a domain name into DNS label format (no compression)."""
    parts: list[bytes] = []
    for label in name.split("."):
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        parts.append(bytes([len(encoded)]) + encoded)
    parts.append(b"\x00")
    return b"".join(parts)


def build_dns_response(query_data: bytes, query: dict, response_ip: str) -> bytes:
    """Build a DNS response for the given *query*.

    Every A question gets an answer pointing to *response_ip*.
    AAAA questions receive an empty answer section (NOERROR, 0 answers) so
    that clients fall back to A records.  All other types also receive an
    A record answer so pega-pega can capture the interaction.

    Parameters
    ----------
    query_data:
        The raw bytes of the original query (used to copy the question section
        verbatim for maximum compatibility).
    query:
        Parsed query dict as returned by :func:`parse_dns_query`.
    response_ip:
        IPv4 address to place in A-record answers.
    """
    tid = query["transaction_id"]

    # Flags: QR=1 (response), opcode=0 (QUERY), AA=1, TC=0, RD copied, RA=1
    rd_flag = query["flags"] & 0x0100  # preserve recursion-desired
    flags = 0x8000 | 0x0400 | rd_flag | 0x0080  # QR | AA | RD? | RA

    questions = query["questions"]
    qdcount = len(questions)

    # Rebuild the question section from our parsed data to guarantee
    # correctness even if the raw packet contained compression.
    question_bytes = b""
    for q in questions:
        question_bytes += _encode_name(q["qname"])
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    # Build answer section
    answer_bytes = b""
    ancount = 0
    ip_bytes = socket.inet_aton(response_ip)

    for q in questions:
        qtype = q["qtype"]

        if qtype == 28:
            # AAAA — respond with no answers (NOERROR, 0 answers for this q).
            # The client will typically fall back to A.
            continue

        # For A (1) and everything else, return an A record.
        answer_bytes += _encode_name(q["qname"])
        answer_bytes += struct.pack(
            "!HHIH",
            1,       # TYPE  = A
            1,       # CLASS = IN
            300,     # TTL   = 5 minutes
            4,       # RDLENGTH
        )
        answer_bytes += ip_bytes
        ancount += 1

    header = struct.pack(
        "!HHHHHH",
        tid,
        flags,
        qdcount,
        ancount,
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    return header + question_bytes + answer_bytes
