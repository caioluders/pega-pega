#!/usr/bin/env bash
#
# deploy.sh — Build and deploy pega-pega to a remote server
#
# Usage:
#   ./deploy.sh <user@host> [--config config.yaml]
#
# Examples:
#   ./deploy.sh root@10.10.10.10
#   ./deploy.sh deploy@myserver.com --config my-config.yaml
#   ./deploy.sh root@vps.example.com --config /path/to/config.yaml
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
err()   { echo -e "${RED}[-]${NC} $*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE=""
CONFIG_FILE=""

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config|-c)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 <user@host> [--config config.yaml]"
            echo ""
            echo "Builds pega-pega and deploys it to a remote server via SSH."
            echo "Sets up a systemd service for persistent operation."
            echo ""
            echo "Options:"
            echo "  --config, -c    Path to config.yaml to deploy (default: config.default.yaml)"
            echo "  --help, -h      Show this help"
            exit 0
            ;;
        -*)
            err "Unknown option: $1"
            exit 1
            ;;
        *)
            REMOTE="$1"
            shift
            ;;
    esac
done

if [[ -z "$REMOTE" ]]; then
    err "Missing target. Usage: $0 <user@host> [--config config.yaml]"
    exit 1
fi

if [[ -z "$CONFIG_FILE" ]]; then
    CONFIG_FILE="${SCRIPT_DIR}/config.default.yaml"
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    err "Config file not found: $CONFIG_FILE"
    exit 1
fi

# ── Build ─────────────────────────────────────────────────────────────
info "Building pega-pega wheel..."
cd "$SCRIPT_DIR"

# Create a temp venv for building if needed
if [[ ! -d .venv ]]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --quiet build
python -m build --wheel --outdir dist/ 2>&1 | tail -1

WHEEL=$(ls -t dist/pega_pega-*.whl 2>/dev/null | head -1)
if [[ -z "$WHEEL" ]]; then
    err "Build failed — no wheel found in dist/"
    exit 1
fi
ok "Built: $(basename "$WHEEL")"

# ── Upload ────────────────────────────────────────────────────────────
info "Uploading to ${REMOTE}..."
scp -q "$WHEEL" "${REMOTE}:/tmp/pega_pega.whl"
scp -q "$CONFIG_FILE" "${REMOTE}:/tmp/pega_pega_config.yaml"
ok "Files uploaded"

# ── Install & configure on remote ────────────────────────────────────
info "Installing on ${REMOTE}..."
ssh "$REMOTE" bash -s << 'REMOTE_SCRIPT'
set -euo pipefail

INSTALL_DIR="/opt/pega-pega"
CONFIG_DIR="/etc/pega-pega"
SERVICE_NAME="pega-pega"

echo "[*] Setting up directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

# Stop existing service if running
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo "[*] Stopping existing service..."
    systemctl stop "$SERVICE_NAME"
fi

# Create/update venv and install
echo "[*] Installing into ${INSTALL_DIR}..."
if [ ! -d "${INSTALL_DIR}/venv" ]; then
    python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --quiet --force-reinstall /tmp/pega_pega.whl

# Deploy config (don't overwrite if already customized, unless first install)
if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    cp /tmp/pega_pega_config.yaml "${CONFIG_DIR}/config.yaml"
    echo "[+] Config deployed to ${CONFIG_DIR}/config.yaml"
else
    cp /tmp/pega_pega_config.yaml "${CONFIG_DIR}/config.yaml.new"
    echo "[*] Existing config preserved. New config saved as config.yaml.new"
fi

# Create systemd unit
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << 'EOF'
[Unit]
Description=Pega-Pega Multi-Protocol Request Logger
After=network.target
Documentation=https://github.com/caioluders/pega-pega

[Service]
Type=simple
ExecStart=/opt/pega-pega/venv/bin/pega-pega -c /etc/pega-pega/config.yaml
WorkingDirectory=/opt/pega-pega
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=strict
ReadWritePaths=/opt/pega-pega /etc/pega-pega
PrivateTmp=true
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# Cleanup
rm -f /tmp/pega_pega.whl /tmp/pega_pega_config.yaml

# Status
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "[+] pega-pega is running!"
    echo ""
    echo "    Dashboard:  http://$(hostname -I | awk '{print $1}'):8443"
    echo "    Config:     ${CONFIG_DIR}/config.yaml"
    echo "    Logs:       journalctl -u ${SERVICE_NAME} -f"
    echo "    Status:     systemctl status ${SERVICE_NAME}"
    echo "    Restart:    systemctl restart ${SERVICE_NAME}"
    echo ""
else
    echo "[-] Service failed to start. Check: journalctl -u ${SERVICE_NAME} -e"
    exit 1
fi
REMOTE_SCRIPT

ok "Deployment complete!"
