import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_self_signed_cert(
    domain: str = "pega.local",
    san_domains: list[str] | None = None,
    cert_dir: Path = Path(".certs"),
) -> tuple[Path, Path]:
    """Generate RSA key + self-signed X.509 cert with wildcard SAN."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    sans = [
        x509.DNSName(domain),
        x509.DNSName(f"*.{domain}"),
        x509.DNSName("localhost"),
        x509.IPAddress(
            __import__("ipaddress").IPv4Address("127.0.0.1")
        ),
    ]
    if san_domains:
        for d in san_domains:
            sans.append(x509.DNSName(d))
            sans.append(x509.DNSName(f"*.{d}"))

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pega-Pega"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_path = cert_dir / "server.pem"
    key_path = cert_dir / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def create_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert_path), str(key_path))
    return ctx
