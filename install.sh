#!/usr/bin/env bash
#
# pega-pega installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/caioluders/pega-pega/main/install.sh | sudo bash
#   curl -sSL https://raw.githubusercontent.com/caioluders/pega-pega/main/install.sh | sudo bash -s -- --domain example.com --ip 1.2.3.4
#
# Options:
#   --domain DOMAIN    Base domain for subdomain tracking (default: pega.local)
#   --ip IP            IP to return in DNS responses (default: auto-detect)
#   --dashboard PORT   Web dashboard port (default: 8443)
#   --no-service       Install only, don't create systemd service
#   --update           Update existing installation from GitHub
#   --uninstall        Remove pega-pega completely
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

REPO="https://github.com/caioluders/pega-pega"
INSTALL_DIR="/opt/pega-pega"
CONFIG_DIR="/etc/pega-pega"
SERVICE_NAME="pega-pega"

DOMAIN=""
RESPONSE_IP=""
DASHBOARD_PORT=""
NO_SERVICE=false
UNINSTALL=false
UPDATE=false

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain|-d)    DOMAIN="$2"; shift 2 ;;
        --ip|-i)        RESPONSE_IP="$2"; shift 2 ;;
        --dashboard)    DASHBOARD_PORT="$2"; shift 2 ;;
        --no-service)   NO_SERVICE=true; shift ;;
        --update)       UPDATE=true; shift ;;
        --uninstall)    UNINSTALL=true; shift ;;
        --help|-h)
            head -14 "$0" 2>/dev/null | tail -11 || true
            exit 0
            ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Uninstall ─────────────────────────────────────────────────────────
if $UNINSTALL; then
    info "Uninstalling pega-pega..."
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
    fi
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    rm -rf "$INSTALL_DIR"
    ok "Removed ${INSTALL_DIR}"
    warn "Config left at ${CONFIG_DIR} — remove manually if desired"
    ok "Uninstall complete"
    exit 0
fi

# ── Update ───────────────────────────────────────────────────────────
if $UPDATE; then
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root"
        exit 1
    fi

    if [[ ! -d "${INSTALL_DIR}/src" ]]; then
        err "pega-pega is not installed at ${INSTALL_DIR}"
        err "Run the installer first (without --update)"
        exit 1
    fi

    echo ""
    echo -e "${CYAN}  ____  _____ ____    _        ____  _____ ____    _${NC}"
    echo -e "${CYAN} |  _ \\| ____/ ___|  / \\      |  _ \\| ____/ ___|  / \\${NC}"
    echo -e "${CYAN} | |_) |  _|| |  _  / _ \\ ____|_) |  _|| |  _  / _ \\${NC}"
    echo -e "${CYAN} |  __/| |__| |_| |/ ___ \\____|  __/| |__| |_| |/ ___ \\${NC}"
    echo -e "${CYAN} |_|   |_____\\____/_/   \\_\\   |_|   |_____\\____/_/   \\_\\${NC}"
    echo ""

    OLD_VERSION=$(${INSTALL_DIR}/venv/bin/python -c 'import pega_pega; print(pega_pega.__version__)' 2>/dev/null || echo "unknown")

    info "Pulling latest from GitHub..."
    cd "${INSTALL_DIR}/src"
    git fetch --quiet origin main
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)

    if [[ "$LOCAL" == "$REMOTE" ]]; then
        ok "Already up to date (v${OLD_VERSION})"
        exit 0
    fi

    git pull --quiet origin main
    ok "Downloaded latest changes"

    info "Reinstalling..."
    "${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade "${INSTALL_DIR}/src"
    NEW_VERSION=$(${INSTALL_DIR}/venv/bin/python -c 'import pega_pega; print(pega_pega.__version__)' 2>/dev/null || echo "unknown")

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Restarting service..."
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            ok "Updated ${OLD_VERSION} → ${NEW_VERSION} and restarted"
        else
            err "Service failed to start after update"
            err "Check logs: journalctl -u ${SERVICE_NAME} -e"
            exit 1
        fi
    else
        ok "Updated ${OLD_VERSION} → ${NEW_VERSION}"
        warn "No systemd service found — restart manually"
    fi
    exit 0
fi

# ── Checks ────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (for binding privileged ports)"
    err "Run: curl -sSL ... | sudo bash"
    exit 1
fi

echo ""
echo -e "${CYAN}  ____  _____ ____    _        ____  _____ ____    _${NC}"
echo -e "${CYAN} |  _ \\| ____/ ___|  / \\      |  _ \\| ____/ ___|  / \\${NC}"
echo -e "${CYAN} | |_) |  _|| |  _  / _ \\ ____|_) |  _|| |  _  / _ \\${NC}"
echo -e "${CYAN} |  __/| |__| |_| |/ ___ \\____|  __/| |__| |_| |/ ___ \\${NC}"
echo -e "${CYAN} |_|   |_____\\____/_/   \\_\\   |_|   |_____\\____/_/   \\_\\${NC}"
echo ""

# Check for python3
if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install it first:"
    err "  Debian/Ubuntu: apt install python3 python3-venv"
    err "  RHEL/Fedora:   dnf install python3"
    err "  Arch:          pacman -S python"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11 ]]; then
    err "Python >= 3.11 required (found ${PY_VERSION})"
    exit 1
fi
info "Found Python ${PY_VERSION}"

# Check for venv module
if ! python3 -m venv --help &>/dev/null; then
    err "python3-venv not found. Install it:"
    err "  Debian/Ubuntu: apt install python3-venv"
    exit 1
fi

# Check for git
if ! command -v git &>/dev/null; then
    err "git not found. Install it first:"
    err "  Debian/Ubuntu: apt install git"
    err "  RHEL/Fedora:   dnf install git"
    err "  Arch:          pacman -S git"
    exit 1
fi

# ── Stop existing service ─────────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "Stopping existing pega-pega service..."
    systemctl stop "$SERVICE_NAME"
fi

# ── Clone / update ────────────────────────────────────────────────────
info "Downloading pega-pega..."
if [[ -d "${INSTALL_DIR}/src" ]]; then
    cd "${INSTALL_DIR}/src"
    git pull --quiet origin main
    ok "Updated existing installation"
else
    mkdir -p "$INSTALL_DIR"
    git clone --quiet --depth 1 "$REPO" "${INSTALL_DIR}/src"
    ok "Downloaded to ${INSTALL_DIR}/src"
fi

# ── Create venv & install ─────────────────────────────────────────────
info "Installing dependencies..."
if [[ ! -f "${INSTALL_DIR}/venv/bin/pip" ]]; then
    rm -rf "${INSTALL_DIR}/venv"
    python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --quiet --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --quiet "${INSTALL_DIR}/src"
ok "Installed pega-pega $(${INSTALL_DIR}/venv/bin/python -c 'import pega_pega; print(pega_pega.__version__)')"

# ── Config ────────────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
    cp "${INSTALL_DIR}/src/config.default.yaml" "${CONFIG_DIR}/config.yaml"

    # Apply CLI overrides to config
    if [[ -n "$DOMAIN" ]]; then
        sed -i "s/^domain:.*/domain: \"${DOMAIN}\"/" "${CONFIG_DIR}/config.yaml"
    fi
    if [[ -n "$RESPONSE_IP" ]]; then
        sed -i "s/^response_ip:.*/response_ip: \"${RESPONSE_IP}\"/" "${CONFIG_DIR}/config.yaml"
    fi
    if [[ -n "$DASHBOARD_PORT" ]]; then
        sed -i "s/^dashboard_port:.*/dashboard_port: ${DASHBOARD_PORT}/" "${CONFIG_DIR}/config.yaml"
    fi

    ok "Config written to ${CONFIG_DIR}/config.yaml"
else
    warn "Existing config preserved at ${CONFIG_DIR}/config.yaml"
fi

# ── Systemd service ───────────────────────────────────────────────────
if ! $NO_SERVICE; then
    info "Setting up systemd service..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Pega-Pega Multi-Protocol Request Logger
After=network.target
Documentation=${REPO}

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/venv/bin/pega-pega -c ${CONFIG_DIR}/config.yaml
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --quiet "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "<server-ip>")

        echo ""
        ok "pega-pega is running!"
        echo ""
        echo -e "    ${CYAN}Dashboard${NC}   http://${SERVER_IP}:${DASHBOARD_PORT:-8443}"
        echo -e "    ${CYAN}Config${NC}      ${CONFIG_DIR}/config.yaml"
        echo -e "    ${CYAN}Logs${NC}        journalctl -u ${SERVICE_NAME} -f"
        echo -e "    ${CYAN}Restart${NC}     systemctl restart ${SERVICE_NAME}"
        echo -e "    ${CYAN}Stop${NC}        systemctl stop ${SERVICE_NAME}"
        echo -e "    ${CYAN}Uninstall${NC}   curl -sSL .../install.sh | sudo bash -s -- --uninstall"
        echo ""
    else
        err "Service failed to start"
        err "Check logs: journalctl -u ${SERVICE_NAME} -e"
        exit 1
    fi
else
    echo ""
    ok "Installed (no service created)"
    echo ""
    echo -e "    Run manually: sudo ${INSTALL_DIR}/venv/bin/pega-pega -c ${CONFIG_DIR}/config.yaml"
    echo ""
fi
