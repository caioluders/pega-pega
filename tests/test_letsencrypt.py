import shutil
import subprocess
from pathlib import Path

from pega_pega import letsencrypt


def test_certbot_available_true(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/certbot")
    assert letsencrypt.certbot_available() is True


def test_certbot_available_false(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: None)
    assert letsencrypt.certbot_available() is False


def test_le_certs_exist_true(tmp_path, monkeypatch):
    domain_dir = tmp_path / "example.com"
    domain_dir.mkdir()
    (domain_dir / "fullchain.pem").write_text("cert")
    (domain_dir / "privkey.pem").write_text("key")
    monkeypatch.setattr(letsencrypt, "LE_CERT_DIR", tmp_path)
    assert letsencrypt.le_certs_exist("example.com") is True


def test_le_certs_exist_false(tmp_path, monkeypatch):
    monkeypatch.setattr(letsencrypt, "LE_CERT_DIR", tmp_path)
    assert letsencrypt.le_certs_exist("example.com") is False


def test_get_le_cert_paths():
    cert, key = letsencrypt.get_le_cert_paths("example.com")
    assert str(cert).endswith("example.com/fullchain.pem")
    assert str(key).endswith("example.com/privkey.pem")


def test_obtain_certificate_success(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/certbot")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
    )
    assert letsencrypt.obtain_certificate("example.com", "a@b.com") is True


def test_obtain_certificate_failure(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/certbot")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 1, "", "error"),
    )
    assert letsencrypt.obtain_certificate("example.com", "a@b.com") is False


def test_obtain_certificate_no_certbot(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: None)
    assert letsencrypt.obtain_certificate("example.com", "a@b.com") is False


def test_obtain_certificate_timeout(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/certbot")

    def raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="certbot", timeout=120)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    assert letsencrypt.obtain_certificate("example.com", "a@b.com") is False


def test_renew_success(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: "/usr/bin/certbot")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], 0, "", ""),
    )
    assert letsencrypt.renew_certificates() is True


def test_renew_no_certbot(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: None)
    assert letsencrypt.renew_certificates() is False
