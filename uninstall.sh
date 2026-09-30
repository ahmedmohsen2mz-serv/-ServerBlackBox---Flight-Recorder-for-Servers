#!/usr/bin/env bash
# ServerBlackBox — Uninstaller
set -euo pipefail

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo $0"; exit 1; }

SERVICE_NAME="server-blackbox"
INSTALL_DIR="/opt/server-blackbox"
DATA_DIR="/var/lib/server-blackbox"

echo "Stopping service..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

echo "Removing files..."
rm -rf "$INSTALL_DIR"

read -rp "Delete recorded data in $DATA_DIR? [y/N] " ans
if [[ "${ans,,}" == "y" ]]; then
    rm -rf "$DATA_DIR"
    echo "Data deleted."
else
    echo "Data preserved at $DATA_DIR"
fi

echo "ServerBlackBox uninstalled."
