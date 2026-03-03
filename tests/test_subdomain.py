from pega_pega.utils.subdomain import extract_subdomain


def test_exact_domain_returns_empty():
    assert extract_subdomain("pega.local", "pega.local") == ""


def test_subdomain_extraction():
    assert extract_subdomain("foo.bar.pega.local", "pega.local") == "foo.bar"


def test_single_subdomain():
    assert extract_subdomain("test.pega.local", "pega.local") == "test"


def test_unrelated_domain():
    assert extract_subdomain("other.com", "pega.local") == "other.com"


def test_strips_port():
    assert extract_subdomain("foo.pega.local:8080", "pega.local") == "foo"


def test_case_insensitive():
    assert extract_subdomain("FOO.PEGA.LOCAL", "pega.local") == "foo"


def test_empty_host():
    assert extract_subdomain("", "pega.local") == ""
