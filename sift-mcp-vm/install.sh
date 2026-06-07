#!/usr/bin/env bash
#
# install.sh - set up the Sift MCP server inside the SIFT VM (Ubuntu 24.04).
#
# Run this INSIDE the SIFT virtual machine, not on the host:
#   chmod +x install.sh && ./install.sh
#
# It creates a Python virtualenv, installs dependencies, checks which forensic
# tools are available, and optionally installs a systemd service that serves the
# MCP over HTTP on boot. server.py and requirements.txt sit next to this script.

set -euo pipefail

# ----- Configuration (edit to taste or pass as env vars) ---------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SIFT_VENV:-$REPO_ROOT/.venv}"
EVIDENCE_ROOT="${SIFT_EVIDENCE_ROOT:-/cases}"
OUTPUT_ROOT="${SIFT_OUTPUT_ROOT:-/cases/output}"
PORT="${SIFT_PORT:-8000}"
HOST="${SIFT_HOST:-0.0.0.0}"

echo "==> Sift MCP installer"
echo "    repo root   : $REPO_ROOT"
echo "    venv        : $VENV_DIR"
echo "    evidence    : $EVIDENCE_ROOT"
echo "    output      : $OUTPUT_ROOT"
echo "    bind        : $HOST:$PORT"
echo

# ----- Python venv + deps ----------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found." >&2; exit 1
fi

echo "==> Creating virtualenv"
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip >/dev/null
echo "==> Installing Python requirements"
pip install -r "$REPO_ROOT/requirements.txt"
echo "==> Installing Python forensic tools (Volatility 3, python-evtx)"
pip install volatility3 python-evtx

# ----- Evidence / output dirs ------------------------------------------------
echo "==> Ensuring evidence/output directories"
sudo mkdir -p "$EVIDENCE_ROOT" "$OUTPUT_ROOT"
sudo chown "$USER" "$EVIDENCE_ROOT" "$OUTPUT_ROOT" 2>/dev/null || true

# ----- Tool availability report ---------------------------------------------
echo
echo "==> Checking forensic toolchain (missing tools just disable their MCP tool):"
check() { if command -v "$1" >/dev/null 2>&1; then echo "    [ok]   $1"; else echo "    [MISS] $1  ($2)"; fi; }
check mmls            "sleuthkit:     sudo apt install sleuthkit"
check fls             "sleuthkit"
check icat            "sleuthkit"
check fsstat          "sleuthkit"
check foremost        "carving:       sudo apt install foremost"
check exiftool        "metadata:      sudo apt install libimage-exiftool-perl"
check binwalk         "embedded:      sudo apt install binwalk"
check yara            "yara:          sudo apt install yara"
check xxd             "hexdump:       sudo apt install xxd"
check strings         "binutils:      sudo apt install binutils"
check vol             "volatility3:   pipx install volatility3"
check log2timeline.py "plaso:         sudo apt install plaso-tools"
check psort.py        "plaso"
check evtx_dump.py    "python-evtx:   pipx install python-evtx"

# ----- Optional systemd service ---------------------------------------------
echo
read -r -p "Install a systemd service to run the server on boot? [y/N] " ans
if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
  SERVICE=/etc/systemd/system/sift-mcp.service
  echo "==> Writing $SERVICE"
  sudo tee "$SERVICE" >/dev/null <<UNIT_EOF
[Unit]
Description=Sift MCP server (DFIR tools over MCP/HTTP)
After=network.target

[Service]
Type=simple
User=$USER
Environment=SIFT_EVIDENCE_ROOT=$EVIDENCE_ROOT
Environment=SIFT_OUTPUT_ROOT=$OUTPUT_ROOT
Environment=SIFT_HOST=$HOST
Environment=SIFT_PORT=$PORT
Environment=SIFT_TRANSPORT=streamable-http
ExecStart=$VENV_DIR/bin/python $REPO_ROOT/server.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT_EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now sift-mcp.service
  echo "==> Service started. Check status with: systemctl status sift-mcp"
else
  echo
  echo "==> Skipped service. Run the server manually with:"
  echo "    source $VENV_DIR/bin/activate"
  echo "    SIFT_EVIDENCE_ROOT=$EVIDENCE_ROOT SIFT_OUTPUT_ROOT=$OUTPUT_ROOT SIFT_HOST=$HOST SIFT_PORT=$PORT python $REPO_ROOT/server.py"
fi

echo
echo "==> Done. The MCP endpoint will be: http://<vm-ip>:$PORT/mcp"
echo "    Find the VM IP with: ip -4 addr show | grep inet"
