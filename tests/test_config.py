from pathlib import Path
from unittest.mock import MagicMock

import yaml

from pega_pega.config import Config, ProtocolConfig, LetsEncryptConfig


def test_default_config_has_14_protocols():
    cfg = Config()
    assert len(cfg.protocols) == 14


def test_default_ports():
    cfg = Config()
    assert cfg.protocols["http"].port == 80
    assert cfg.protocols["dns"].port == 53
    assert cfg.protocols["ssh"].port == 22
    assert cfg.protocols["mysql"].port == 3306


def test_bind_ip_propagates():
    cfg = Config(bind_ip="10.0.0.1")
    for pc in cfg.protocols.values():
        assert pc.bind == "10.0.0.1"


def test_extra_ports_defaults():
    cfg = Config()
    assert 8080 in cfg.protocols["http"].extra_ports
    assert 4443 in cfg.protocols["https"].extra_ports


def test_dashboard_port_stripped_from_extra_ports():
    cfg = Config(dashboard_port=8080)
    assert 8080 not in cfg.protocols["http"].extra_ports


def test_load_from_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump({
        "domain": "test.com",
        "protocols": {"http": {"port": 8888}},
    }))
    cfg = Config.load(p)
    assert cfg.domain == "test.com"
    assert cfg.protocols["http"].port == 8888
    # Other protocols still get defaults
    assert cfg.protocols["dns"].port == 53


def test_load_nonexistent_uses_defaults():
    cfg = Config.load(Path("/nonexistent/config.yaml"))
    assert cfg.domain == "pega.local"
    assert len(cfg.protocols) == 14


def test_load_empty_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("")
    cfg = Config.load(p)
    assert cfg.domain == "pega.local"


def test_to_dict_roundtrip():
    cfg = Config(domain="foo.bar")
    d = cfg.to_dict()
    assert d["domain"] == "foo.bar"
    assert d["letsencrypt"]["enabled"] is False
    assert "http" in d["protocols"]


def test_save_and_reload(tmp_path):
    cfg = Config(domain="save.test")
    cfg._source_path = tmp_path / "out.yaml"
    cfg.save()
    cfg2 = Config.load(tmp_path / "out.yaml")
    assert cfg2.domain == "save.test"


def test_letsencrypt_from_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump({
        "letsencrypt": {"enabled": True, "email": "a@b.com", "agree_tos": True},
    }))
    cfg = Config.load(p)
    assert cfg.letsencrypt.enabled is True
    assert cfg.letsencrypt.email == "a@b.com"


def test_dashboard_password_default_empty():
    cfg = Config()
    assert cfg.dashboard_password == ""


def test_dashboard_password_from_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(yaml.dump({"dashboard_password": "secret123"}))
    cfg = Config.load(p)
    assert cfg.dashboard_password == "secret123"


def test_dashboard_password_in_to_dict():
    cfg = Config(dashboard_password="mypass")
    d = cfg.to_dict()
    assert d["dashboard_password"] == "mypass"


def test_get_response_ip_explicit():
    cfg = Config(response_ip="1.2.3.4")
    assert cfg.get_response_ip() == "1.2.3.4"


def test_get_response_ip_auto_detect(monkeypatch):
    mock_sock = MagicMock()
    mock_sock.getsockname.return_value = ("10.20.30.40", 0)

    import socket
    original_socket = socket.socket

    def mock_socket(*args, **kwargs):
        return mock_sock

    monkeypatch.setattr(socket, "socket", mock_socket)
    cfg = Config(response_ip="")
    assert cfg.get_response_ip() == "10.20.30.40"
