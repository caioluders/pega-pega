from pega_pega.mock import MockMatcher


def test_exact_match():
    m = MockMatcher([{"path": "/api/hello", "method": "GET", "enabled": True, "priority": 0}])
    assert m.match("GET", "/api/hello") is not None
    assert m.match("GET", "/api/world") is None


def test_wildcard_param():
    m = MockMatcher([{"path": "/api/users/:id", "method": "ANY", "enabled": True, "priority": 0}])
    assert m.match("GET", "/api/users/123") is not None
    assert m.match("POST", "/api/users/abc") is not None
    assert m.match("GET", "/api/users") is None
    assert m.match("GET", "/api/users/123/posts") is None


def test_wildcard_star():
    m = MockMatcher([{"path": "/static/*", "method": "GET", "enabled": True, "priority": 0}])
    assert m.match("GET", "/static/foo.js") is not None
    assert m.match("GET", "/static/css/bar.css") is not None
    assert m.match("GET", "/other") is None


def test_method_filter():
    m = MockMatcher([{"path": "/api/data", "method": "POST", "enabled": True, "priority": 0}])
    assert m.match("POST", "/api/data") is not None
    assert m.match("GET", "/api/data") is None


def test_any_method():
    m = MockMatcher([{"path": "/api/data", "method": "ANY", "enabled": True, "priority": 0}])
    assert m.match("GET", "/api/data") is not None
    assert m.match("DELETE", "/api/data") is not None


def test_priority_ordering():
    m = MockMatcher([
        {"path": "/api/users/:id", "method": "GET", "enabled": True, "priority": 1, "id": "catch-all"},
        {"path": "/api/users/me", "method": "GET", "enabled": True, "priority": 0, "id": "specific"},
    ])
    result = m.match("GET", "/api/users/me")
    assert result["id"] == "specific"


def test_disabled_rule_skipped():
    m = MockMatcher([{"path": "/api/test", "method": "GET", "enabled": False, "priority": 0}])
    assert m.match("GET", "/api/test") is None


def test_no_rules():
    m = MockMatcher()
    assert m.match("GET", "/anything") is None


def test_trailing_slash():
    m = MockMatcher([{"path": "/api/test", "method": "GET", "enabled": True, "priority": 0}])
    assert m.match("GET", "/api/test") is not None
    assert m.match("GET", "/api/test/") is not None


def test_reload():
    m = MockMatcher()
    assert m.match("GET", "/x") is None
    m.reload([{"path": "/x", "method": "GET", "enabled": True, "priority": 0}])
    assert m.match("GET", "/x") is not None
