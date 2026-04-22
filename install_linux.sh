#!/usr/bin/env bash
# install_linux.sh — One-shot setup for NetScan on Debian / Kali / Ubuntu
# Usage: bash install_linux.sh
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

echo -e "${BOLD}NetScan — Linux Debian/Kali Setup${RESET}"
echo "=================================================="

# ── 1. System packages ──────────────────────────────────────────────────────
info "Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y \
        python3 python3-pip python3-venv \
        libpcap-dev \
        nftables iptables \
        iproute2 \
        --no-install-recommends
else
    warn "apt-get not found. Please install manually: python3-venv libpcap-dev nftables"
fi

# ── 2. Python virtual environment ───────────────────────────────────────────
if [ ! -d "venv" ]; then
    info "Creating Python virtual environment..."
    python3 -m venv venv
else
    info "Virtual environment already exists — skipping creation."
fi

info "Activating venv and installing Python packages..."
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
info "Python packages installed."

# ── 3. Initialise the database ──────────────────────────────────────────────
info "Initialising NetScan database..."
python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
from app.db.db_session import init_db
init_db()
print("  Database ready.")
PYEOF

# ── 4. Capability grant (optional, non-root capture) ────────────────────────
PYTHON_BIN="$(pwd)/venv/bin/python3"
echo ""
warn "Packet capture requires root or CAP_NET_RAW/CAP_NET_ADMIN."
warn "Option A (recommended): run with sudo"
warn "    sudo venv/bin/python3 cli.py live --interface eth0"
warn ""
warn "Option B (non-root capability grant — allows capture without sudo):"
warn "    sudo setcap cap_net_raw,cap_net_admin+eip ${PYTHON_BIN}"
warn "    NOTE: setcap is reset when Python is updated; re-run after upgrades."

# ── 5. Auto-detect default interface ────────────────────────────────────────
DEFAULT_IFACE="eth0"
if command -v ip &>/dev/null; then
    DETECTED=$(ip -o -4 route show default 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')
    if [ -n "$DETECTED" ]; then
        DEFAULT_IFACE="$DETECTED"
    fi
fi
info "Detected default network interface: ${BOLD}${DEFAULT_IFACE}${RESET}"

# ── 6. Summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}✓ NetScan is ready!${RESET}"
echo ""
echo "  Start dashboard only:"
echo "    source venv/bin/activate && python3 cli.py api"
echo ""
echo "  Start full live monitor (requires root):"
echo "    sudo venv/bin/python3 cli.py live --interface ${DEFAULT_IFACE}"
echo ""
echo "  Train ML model (after capturing baseline traffic):"
echo "    sudo venv/bin/python3 cli.py train"
echo ""
echo "  Install as systemd service (optional):"
echo "    sudo cp netscan.service /etc/systemd/system/"
echo "    sudo sed -i \"s|/opt/netscan|$(pwd)|g\" /etc/systemd/system/netscan.service"
echo "    sudo systemctl daemon-reload && sudo systemctl enable --now netscan"
echo ""
