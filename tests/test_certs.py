import ssl

from cryptography import x509

from pega_pega.certs import generate_self_signed_cert, create_ssl_context


def test_generate_creates_files(tmp_path):
    cert_path, key_path = generate_self_signed_cert(domain="test.local", cert_dir=tmp_path)
    assert cert_path.exists()
    assert key_path.exists()


def test_cert_has_correct_cn(tmp_path):
    cert_path, _ = generate_self_signed_cert(domain="test.local", cert_dir=tmp_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "test.local"


def test_cert_has_wildcard_san(tmp_path):
    cert_path, _ = generate_self_signed_cert(domain="test.local", cert_dir=tmp_path)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "*.test.local" in dns_names
    assert "localhost" in dns_names


def test_extra_san_domains(tmp_path):
    cert_path, _ = generate_self_signed_cert(
        domain="a.com", san_domains=["b.com"], cert_dir=tmp_path,
    )
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "b.com" in dns_names
    assert "*.b.com" in dns_names


def test_create_ssl_context(tmp_path):
    cert_path, key_path = generate_self_signed_cert(domain="test.local", cert_dir=tmp_path)
    ctx = create_ssl_context(cert_path, key_path)
    assert isinstance(ctx, ssl.SSLContext)
