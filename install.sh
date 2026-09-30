#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
#  ServerBlackBox — Linux Installer (systemd)
#  Creates a systemd service for continuous recording.
# ──────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/server-blackbox"
DATA_DIR="/var/lib/server-blackbox"
SERVICE_NAME="server-blackbox"
SERVICE_USER="blackbox"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# ── Python check ─────────────────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON="$(command -v "$cmd")"  # Fix #28: absolute path
        break
    fi
done
[[ -z "$PYTHON" ]] && error "Python 3 not found. Install it first."
info "Using $PYTHON ($($PYTHON --version 2>&1))"

# Verify it's Python 3
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
[[ "$PY_MAJOR" != "3" ]] && error "Python 3 required, found Python $PY_MAJOR"

# ── Install psutil ───────────────────────────────────────────
# Fix #6: Quote 'psutil>=5.9.0' — unquoted >= is shell redirect
$PYTHON -m pip install --quiet 'psutil>=5.9.0' 2>/dev/null \
    || $PYTHON -m pip install --quiet --user 'psutil>=5.9.0' \
    || warn "Could not install psutil via pip. Please install manually."

# ── Create service user ──────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created system user: $SERVICE_USER"
else
    info "User $SERVICE_USER already exists"
fi

# Fix #10: Add blackbox user to systemd-journal group for journalctl access
if getent group systemd-journal &>/dev/null; then
    usermod -aG systemd-journal "$SERVICE_USER" 2>/dev/null || true
    info "Added $SERVICE_USER to systemd-journal group"
fi

# ── Copy files ───────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
cp "$SCRIPT_DIR/blackbox.py" "$INSTALL_DIR/blackbox.py"
cp "$SCRIPT_DIR/analyzer.py" "$INSTALL_DIR/analyzer.py"
# Fix #7: Scripts should NOT be world-executable. 750 = owner+group only.
chmod 750 "$INSTALL_DIR/blackbox.py" "$INSTALL_DIR/analyzer.py"
chown root:root "$INSTALL_DIR/blackbox.py" "$INSTALL_DIR/analyzer.py"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 700 "$DATA_DIR"
info "Installed to $INSTALL_DIR"

# ── Create systemd unit ──────────────────────────────────────
# Fix #28: Use absolute Python path to avoid PATH issues in service context
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=ServerBlackBox — Server Flight Recorder
After=network.target
Wants=network.target

[Service]
Type=notify
NotifyAccess=main
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${PYTHON} ${INSTALL_DIR}/blackbox.py \\
    --interval 30 \\
    --output-dir ${DATA_DIR} \\
    --log-level WARNING
Restart=always
RestartSec=10
WatchdogSec=120

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
PrivateTmp=yes
ProtectKernelModules=yes
# Fix #8: ProtectKernelTunables=yes blocks /proc/vmstat, /proc/pressure/*,
# /proc/sys/fs/file-nr which we need. Use 'no' but restrict other access.
ProtectKernelTunables=no
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
# MemoryDenyWriteExecute breaks psutil's C extension on some systems
MemoryDenyWriteExecute=no
LockPersonality=yes
SystemCallArchitectures=native
# Fix #9/#10: Need CAP_DAC_READ_SEARCH for /proc, CAP_SYS_PTRACE for
# process info, CAP_NET_ADMIN for connections, CAP_SYSLOG for dmesg
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN CAP_SYSLOG
AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_NET_ADMIN CAP_SYSLOG

[Install]
WantedBy=multi-user.target
EOF

info "Created systemd service: ${SERVICE_NAME}.service"

# ── Enable & start ───────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"
info "Service started and enabled on boot"

# ── Verify ───────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "ServerBlackBox is running! ✅"
    echo ""
    echo "  Data directory : $DATA_DIR"
    echo "  View status    : systemctl status $SERVICE_NAME"
    echo "  View logs      : journalctl -u $SERVICE_NAME -f"
    echo "  Analyze        : $PYTHON $INSTALL_DIR/analyzer.py $DATA_DIR"
    echo ""
else
    warn "Service may not have started correctly."
    echo "  Check: systemctl status $SERVICE_NAME"
    echo "  Logs:  journalctl -u $SERVICE_NAME --no-pager"
fi
