"""Let's Encrypt integration via certbot webroot mode."""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("pega-pega")

LE_CERT_DIR = Path("/etc/letsencrypt/live")
WEBROOT_DIR = Path("/tmp/pega-pega-acme")


def certbot_available() -> bool:
    return shutil.which("certbot") is not None


def le_certs_exist(domain: str) -> bool:
    cert_dir = LE_CERT_DIR / domain
    return (cert_dir / "fullchain.pem").exists() and (cert_dir / "privkey.pem").exists()


def get_le_cert_paths(domain: str) -> tuple[Path, Path]:
    cert_dir = LE_CERT_DIR / domain
    return cert_dir / "fullchain.pem", cert_dir / "privkey.pem"


def get_cert_expiry(domain: str) -> datetime | None:
    """Read expiry date from existing LE certificate."""
    if not le_certs_exist(domain):
        return None
    try:
        from cryptography import x509

        cert_path = LE_CERT_DIR / domain / "fullchain.pem"
        cert_data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        return cert.not_valid_after_utc
    except Exception:
        return None


def obtain_certificate(domain: str, email: str, webroot: Path = WEBROOT_DIR) -> bool:
    """Run certbot to obtain a certificate via HTTP-01 challenge."""
    if not certbot_available():
        logger.error("certbot is not installed")
        return False

    webroot.mkdir(parents=True, exist_ok=True)

    cmd = [
        "certbot", "certonly",
        "--webroot",
        "-w", str(webroot),
        "-d", domain,
        "--non-interactive",
        "--agree-tos",
        "-m", email,
    ]

    logger.info("Running certbot: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            logger.info("Certificate obtained successfully for %s", domain)
            return True
        else:
            logger.error("certbot failed (exit %d): %s", result.returncode, result.stderr)
            return False
    except subprocess.TimeoutExpired:
        logger.error("certbot timed out")
        return False
    except Exception as e:
        logger.error("certbot error: %s", e)
        return False


def renew_certificates() -> bool:
    """Run certbot renew."""
    if not certbot_available():
        return False

    try:
        result = subprocess.run(
            ["certbot", "renew", "--quiet"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            logger.info("Certificate renewal check completed")
            return True
        else:
            logger.warning("certbot renew failed: %s", result.stderr)
            return False
    except Exception as e:
        logger.error("certbot renew error: %s", e)
        return False


async def renewal_loop(
    reload_callback=None,
    interval: int = 43200,  # 12 hours
):
    """Background task that periodically renews certificates."""
    while True:
        await asyncio.sleep(interval)
        try:
            loop = asyncio.get_running_loop()
            renewed = await loop.run_in_executor(None, renew_certificates)
            if renewed and reload_callback:
                await reload_callback()
        except asyncio.CancelledError:
            break
        except Exception:
            logger.debug("Renewal loop error", exc_info=True)
