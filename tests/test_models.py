import json

from pega_pega.models import CapturedRequest, Protocol


def test_protocol_enum_has_14_members():
    assert len(Protocol) == 14


def test_protocol_is_str_enum():
    assert isinstance(Protocol.HTTP, str)
    assert Protocol.HTTP == "HTTP"
    assert Protocol.RAW_TCP == "RAW_TCP"


def test_captured_request_auto_generates_id():
    r = CapturedRequest()
    assert len(r.id) == 32  # uuid4 hex


def test_captured_request_auto_generates_timestamp():
    r = CapturedRequest()
    assert "T" in r.timestamp  # ISO format


def test_captured_request_unique_ids():
    r1 = CapturedRequest()
    r2 = CapturedRequest()
    assert r1.id != r2.id


def test_to_dict_raw_data_as_hex():
    r = CapturedRequest(raw_data=b"\xde\xad")
    d = r.to_dict()
    assert d["raw_data"] == "dead"


def test_to_dict_empty_raw_data():
    r = CapturedRequest(raw_data=b"")
    assert r.to_dict()["raw_data"] == ""


def test_to_dict_protocol_is_string():
    r = CapturedRequest(protocol=Protocol.DNS)
    assert r.to_dict()["protocol"] == "DNS"
    assert isinstance(r.to_dict()["protocol"], str)


def test_to_json_valid(sample_request):
    j = sample_request.to_json()
    parsed = json.loads(j)
    assert parsed["id"] == "abc123"
    assert parsed["protocol"] == "HTTP"
    assert parsed["source_ip"] == "192.168.1.100"
