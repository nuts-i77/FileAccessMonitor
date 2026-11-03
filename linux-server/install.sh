#!/bin/sh
# FileAccessMonitor monitoring server for Linux, from the tar.gz: installs, upgrades or removes it.
# (The deb and rpm packages do the same through the package manager.)
#
#   sudo sh install.sh                    install (monitoring only) or upgrade (keeps the current mode and port)
#   sudo sh install.sh --collect          also record Samba accesses on this server (runs as root)
#   sudo sh install.sh --monitor-only     only show what agents send (runs as user fileaccessmonitor)
#   sudo sh install.sh --port 8080        web GUI port
#   sudo sh install.sh --uninstall [--purge]   remove it (--purge also deletes records and settings)
# After installing, fileaccessmonitor-server shows or changes the mode and port.
set -eu

APP_DIR=/opt/fileaccessmonitor
DATA_DIR=/var/lib/fileaccessmonitor
UNIT=fileaccessmonitor.service
UNIT_FILE=/etc/systemd/system/$UNIT
DROPIN_DIR=/etc/systemd/system/$UNIT.d
SERVICE_USER=fileaccessmonitor
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo sh $0 $*)." >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now "$UNIT" 2>/dev/null || true
    rm -rf "$UNIT_FILE" "$DROPIN_DIR" "$APP_DIR" /usr/local/bin/fileaccessmonitor-server
    for u in smbd.service smb.service; do rm -f "/etc/systemd/system/$u.d/fileaccessmonitor.conf"; done
    systemctl daemon-reload
    if [ "${2:-}" = "--purge" ]; then rm -rf "$DATA_DIR"; userdel "$SERVICE_USER" 2>/dev/null || true; fi
    echo "FileAccessMonitor was removed."
    [ "${2:-}" = "--purge" ] || echo "Records and settings were kept in $DATA_DIR."
    exit 0
fi

if [ -f /usr/lib/systemd/system/$UNIT ]; then
    echo "FileAccessMonitor is installed from the deb/rpm package here; upgrade it with apt or dnf instead." >&2
    exit 1
fi
if systemctl list-unit-files fileaccessmonitor-agent.service 2>/dev/null | grep -q "^fileaccessmonitor-agent"; then
    echo "The FileAccessMonitor agent is installed on this machine. Remove it first (sh install.sh --uninstall in" >&2
    echo "the agent package); with --collect the monitoring server records this machine's Samba accesses itself." >&2
    exit 1
fi

FIRST_INSTALL=false
[ -f "$DATA_DIR/settings.json" ] || FIRST_INSTALL=true

echo "Installing FileAccessMonitor to $APP_DIR ..."
systemctl stop "$UNIT" 2>/dev/null || true
id "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
mkdir -p "$APP_DIR" "$DATA_DIR"
cp -R "$HERE"/. "$APP_DIR"/
rm -f "$APP_DIR/install.sh" "$APP_DIR/$UNIT"
chmod 755 "$APP_DIR/FileAccessMonitor" "$APP_DIR/fileaccessmonitor-server"
ln -sf "$APP_DIR/fileaccessmonitor-server" /usr/local/bin/fileaccessmonitor-server
install -m 644 "$HERE/$UNIT" "$UNIT_FILE"
systemctl daemon-reload

# A new install is monitoring only unless --collect is given; an upgrade keeps the mode in settings.json
# (and the service account and drop-ins that go with it)
if [ $# -eq 0 ]; then
    if $FIRST_INSTALL || grep -q '"LocalCollection": false' "$DATA_DIR/settings.json"; then
        set -- --monitor-only
    else
        set -- --collect
    fi
fi
"$APP_DIR/fileaccessmonitor-server" "$@" >/dev/null
systemctl enable --now "$UNIT" >/dev/null 2>&1

for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -f "$DATA_DIR/initial-admin-password.txt" ] || ! $FIRST_INSTALL && break
    sleep 1
done
echo
"$APP_DIR/fileaccessmonitor-server"
PORT=$("$APP_DIR/fileaccessmonitor-server" | sed -n 's/^Web GUI: port \([0-9]*\).*/\1/p')
echo "Open TCP $PORT and 8443 in the firewall if it is on, for example:"
echo "  firewall-cmd --permanent --add-port=$PORT/tcp --add-port=8443/tcp && firewall-cmd --reload   (RHEL, Rocky, Alma)"
echo "  ufw allow $PORT/tcp && ufw allow 8443/tcp   (Ubuntu, Debian)"
