"""Self-update logic for pega-pega."""

import subprocess
import sys
from pathlib import Path

from . import __version__

INSTALL_DIR = Path("/opt/pega-pega")
SRC_DIR = INSTALL_DIR / "src"
VENV_DIR = INSTALL_DIR / "venv"
SERVICE_NAME = "pega-pega"


class UpdateError(Exception):
    pass


class UpdateResult:
    def __init__(self, old_version: str, new_version: str, restarted: bool,
                 already_up_to_date: bool = False, message: str = ""):
        self.old_version = old_version
        self.new_version = new_version
        self.restarted = restarted
        self.already_up_to_date = already_up_to_date
        self.message = message


def detect_install_type() -> tuple[Path, Path | None]:
    """Return (source_dir, venv_pip_or_None)."""
    if SRC_DIR.exists() and (VENV_DIR / "bin" / "pip").exists():
        return SRC_DIR, VENV_DIR / "bin" / "pip"

    pkg_dir = Path(__file__).resolve().parent
    repo_dir = pkg_dir.parent
    if (repo_dir / ".git").exists():
        return repo_dir, None

    raise UpdateError(
        "Cannot determine installation type. "
        "Expected /opt/pega-pega/src or a git checkout."
    )


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None,
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            raise UpdateError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise UpdateError(f"Command timed out: {' '.join(cmd)}")
    except FileNotFoundError:
        raise UpdateError(f"Command not found: {cmd[0]}")


def check_for_updates(src_dir: Path) -> bool:
    _run(["git", "fetch", "--quiet", "origin", "main"], cwd=src_dir)
    local = _run(["git", "rev-parse", "HEAD"], cwd=src_dir)
    remote = _run(["git", "rev-parse", "origin/main"], cwd=src_dir)
    return local != remote


def _read_version_from_file(src_dir: Path) -> str:
    init_file = src_dir / "pega_pega" / "__init__.py"
    if init_file.exists():
        for line in init_file.read_text().splitlines():
            if line.startswith("__version__"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return "unknown"


def _try_restart_service() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-enabled", "--quiet", SERVICE_NAME],
            capture_output=True, timeout=10,
        )
        if result.returncode != 0:
            return False
        subprocess.run(
            ["systemctl", "restart", SERVICE_NAME],
            capture_output=True, timeout=30,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def perform_update() -> UpdateResult:
    old_version = __version__
    src_dir, venv_pip = detect_install_type()

    if not check_for_updates(src_dir):
        return UpdateResult(
            old_version=old_version, new_version=old_version,
            restarted=False, already_up_to_date=True,
            message=f"Already up to date (v{old_version})",
        )

    _run(["git", "pull", "--quiet", "origin", "main"], cwd=src_dir)

    if venv_pip:
        _run([str(venv_pip), "install", "--quiet", "--upgrade", str(src_dir)])
    else:
        _run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", str(src_dir)])

    new_version = _read_version_from_file(src_dir)
    restarted = _try_restart_service()

    msg = f"Updated {old_version} → {new_version}"
    if restarted:
        msg += " (service restarted)"

    return UpdateResult(
        old_version=old_version, new_version=new_version,
        restarted=restarted, already_up_to_date=False, message=msg,
    )
