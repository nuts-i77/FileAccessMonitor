#!/bin/sh
# FileAccessMonitor Linux agent: installs, upgrades or removes the agent on a Samba file server.
#
#   sudo ./install.sh                         install or upgrade (keeps the registration)
#   sudo ./install.sh FAM1.xxxx               install and register with a monitoring server
#   sudo ./install.sh --uninstall             remove the agent (keeps /var/lib/fileaccessmonitor)
#   sudo ./install.sh --uninstall --purge     also remove its data (registration, waiting records)
set -eu

APP_DIR=/opt/fileaccessmonitor
DATA_DIR=/var/lib/fileaccessmonitor
UNIT=fileaccessmonitor-agent.service
UNIT_FILE=/etc/systemd/system/$UNIT
BIN=$APP_DIR/fileaccessmonitor-agent
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo $0 $*)." >&2
    exit 1
fi

# The Samba service is smbd.service (Debian, Ubuntu) or smb.service (RHEL, Rocky, Alma, SUSE)
smb_unit() {
    for u in smbd.service smb.service; do
        if systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl list-unit-files "$u" | grep -q "^$u"; then
            echo "$u"; return
        fi
    done
}

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now "$UNIT" 2>/dev/null || true
    rm -f "$UNIT_FILE" /usr/local/bin/fileaccessmonitor-agent
    rm -rf "$APP_DIR"
    for u in smbd.service smb.service; do rm -f "/etc/systemd/system/$u.d/fileaccessmonitor.conf"; done
    systemctl daemon-reload
    if [ "${2:-}" = "--purge" ]; then rm -rf "$DATA_DIR"; fi
    echo "The agent was removed. Shares keep the audit settings it added to smb.conf (between"
    echo "\"# FileAccessMonitor begin\" and \"# FileAccessMonitor end\"); remove the folders on the"
    echo "monitoring server first, or delete those lines and run: smbcontrol smbd reload-config"
    exit 0
fi

SMB_UNIT=$(smb_unit)
if [ -z "$SMB_UNIT" ]; then
    echo "Samba (smbd) is not installed. Install it first (apt install samba / dnf install samba)." >&2
    exit 1
fi

echo "Installing the agent to $APP_DIR ..."
mkdir -p "$APP_DIR" "$DATA_DIR"
chmod 700 "$DATA_DIR"
systemctl stop "$UNIT" 2>/dev/null || true
install -m 755 "$HERE/fileaccessmonitor-agent" "$BIN"
ln -sf "$BIN" /usr/local/bin/fileaccessmonitor-agent
install -m 644 "$HERE/$UNIT" "$UNIT_FILE"

# journald drops lines from a service that logs very fast (by default more than 10,000 in 30
# seconds); let smbd's audit lines through. Takes effect when smbd next restarts.
mkdir -p "/etc/systemd/system/$SMB_UNIT.d"
cat > "/etc/systemd/system/$SMB_UNIT.d/fileaccessmonitor.conf" <<EOF
# Added by FileAccessMonitor: journald must not drop Samba's audit lines
[Service]
LogRateLimitIntervalSec=0
EOF
systemctl daemon-reload

if [ -n "${1:-}" ]; then
    "$BIN" enroll "$1"
fi

if [ -f "$DATA_DIR/agent.json" ]; then
    systemctl enable --now "$UNIT"
    echo "The agent is running (systemctl status fileaccessmonitor-agent)."
else
    systemctl enable "$UNIT"
    echo "Register the agent with a connection string from Settings > Agents on the monitoring server:"
    echo "  fileaccessmonitor-agent enroll <connection string> && systemctl start fileaccessmonitor-agent"
fi
echo "Restart Samba when convenient (systemctl restart $SMB_UNIT) so that journald keeps all of its audit lines."
