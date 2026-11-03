#!/bin/sh
# FileAccessMonitor monitoring server for Linux: installs, upgrades or removes it.
#
#   sudo sh install.sh                    install (monitoring only) or upgrade (keeps the current mode)
#   sudo sh install.sh --collect          also record Samba accesses on this server (runs as root)
#   sudo sh install.sh --monitor-only     only show what agents send (runs as user fileaccessmonitor)
#   sudo sh install.sh --port 8080        web GUI port (default 8080, kept on upgrade)
#   sudo sh install.sh --uninstall [--purge]   remove it (--purge also deletes records and settings)
set -eu

APP_DIR=/opt/fileaccessmonitor
DATA_DIR=/var/lib/fileaccessmonitor
UNIT=fileaccessmonitor.service
UNIT_FILE=/etc/systemd/system/$UNIT
SERVICE_USER=fileaccessmonitor
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo sh $0 $*)." >&2
    exit 1
fi

MODE=""
PORT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --collect) MODE=collect ;;
        --monitor-only) MODE=monitor ;;
        --port) PORT="$2"; shift ;;
        --uninstall)
            systemctl disable --now "$UNIT" 2>/dev/null || true
            rm -f "$UNIT_FILE"
            rm -rf "$APP_DIR"
            for u in smbd.service smb.service; do rm -f "/etc/systemd/system/$u.d/fileaccessmonitor.conf"; done
            systemctl daemon-reload
            if [ "${2:-}" = "--purge" ]; then rm -rf "$DATA_DIR"; userdel "$SERVICE_USER" 2>/dev/null || true; fi
            echo "FileAccessMonitor was removed."
            [ "${2:-}" = "--purge" ] || echo "Records and settings were kept in $DATA_DIR."
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if systemctl list-unit-files fileaccessmonitor-agent.service 2>/dev/null | grep -q fileaccessmonitor-agent; then
    echo "The FileAccessMonitor agent is installed on this machine. Remove it first (sh install.sh --uninstall in" >&2
    echo "the agent package); with --collect the monitoring server records this machine's Samba accesses itself." >&2
    exit 1
fi

# Upgrade: keep the mode and port of the current install unless asked otherwise
if [ -z "$MODE" ]; then
    if [ -f "$DATA_DIR/settings.json" ] && grep -q '"LocalCollection": true' "$DATA_DIR/settings.json"; then
        MODE=collect
    else
        MODE=monitor
    fi
fi
if [ -z "$PORT" ]; then
    PORT=$(sed -n 's/.*"Url": "http:\/\/0\.0\.0\.0:\([0-9]*\)".*/\1/p' "$APP_DIR/appsettings.Production.json" 2>/dev/null || true)
    PORT=${PORT:-8080}
fi

# Collecting needs root (it reads the journal and edits smb.conf); monitoring only does not
if [ "$MODE" = collect ]; then
    SMB_UNIT=""
    for u in smbd.service smb.service; do
        if systemctl list-unit-files "$u" 2>/dev/null | grep -q "^$u"; then SMB_UNIT=$u; fi
    done
    if [ -z "$SMB_UNIT" ]; then
        echo "--collect records Samba accesses, but Samba (smbd) is not installed." >&2
        exit 1
    fi
    RUN_AS=root
else
    id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    RUN_AS=$SERVICE_USER
fi

echo "Installing FileAccessMonitor to $APP_DIR (port $PORT, $( [ "$MODE" = collect ] && echo "collecting Samba accesses on this server" || echo "monitoring only")) ..."
systemctl stop "$UNIT" 2>/dev/null || true
mkdir -p "$APP_DIR" "$DATA_DIR"
cp -R "$HERE"/. "$APP_DIR"/
rm -f "$APP_DIR/install.sh" "$APP_DIR/$UNIT"
chmod 755 "$APP_DIR/FileAccessMonitor"
cat > "$APP_DIR/appsettings.Production.json" <<EOF
{
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://0.0.0.0:$PORT" } } }
}
EOF

"$APP_DIR/FileAccessMonitor" local-collection "$( [ "$MODE" = collect ] && echo on || echo off)" >/dev/null
chown -R "$RUN_AS": "$DATA_DIR"
chmod 700 "$DATA_DIR"

sed "s/^User=.*/User=$RUN_AS/" "$HERE/$UNIT" > "$UNIT_FILE"
chmod 644 "$UNIT_FILE"

if [ "$MODE" = collect ]; then
    # journald drops lines from a service that logs very fast; let smbd's audit lines through.
    # Takes effect when smbd next restarts.
    mkdir -p "/etc/systemd/system/$SMB_UNIT.d"
    cat > "/etc/systemd/system/$SMB_UNIT.d/fileaccessmonitor.conf" <<EOF
# Added by FileAccessMonitor: journald must not drop Samba's audit lines
[Service]
LogRateLimitIntervalSec=0
EOF
fi
systemctl daemon-reload
systemctl enable --now "$UNIT"

for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$DATA_DIR/initial-admin-password.txt" ] && break
    sleep 1
done
echo
echo "FileAccessMonitor is running (systemctl status fileaccessmonitor; log: journalctl -u fileaccessmonitor)."
echo "Web GUI: http://$(hostname -I 2>/dev/null | awk '{print $1}'):$PORT  (agents connect to port 8443)"
if [ -f "$DATA_DIR/initial-admin-password.txt" ]; then
    echo "Sign in as admin; the initial password is shown by: sudo cat $DATA_DIR/initial-admin-password.txt"
fi
echo "Open the ports in the firewall if it is on, for example:"
echo "  firewall-cmd --permanent --add-port=$PORT/tcp --add-port=8443/tcp && firewall-cmd --reload   (RHEL, Rocky, Alma)"
echo "  ufw allow $PORT/tcp && ufw allow 8443/tcp                                                      (Ubuntu, Debian)"
if [ "$MODE" = collect ]; then
    echo "Restart Samba when convenient (systemctl restart $SMB_UNIT) so that journald keeps all of its audit lines."
fi
