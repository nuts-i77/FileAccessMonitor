#!/bin/sh
# After installing or upgrading the monitoring server package (deb: $1 = configure, $2 = the old
# version on upgrades; rpm: $1 = 1 install, 2 upgrade). The web GUI service always runs as the user
# fileaccessmonitor. A new install is monitoring only; fileaccessmonitor-server --collect also records
# this machine's Samba accesses, through the separate fileaccessmonitor-collector service (root).
# Upgrades keep the mode; before 1.11 collecting ran the whole server as root (a systemd drop-in), which
# is replaced by the collector service here.
set -e
DATA_DIR=/var/lib/fileaccessmonitor
id fileaccessmonitor >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin fileaccessmonitor
mkdir -p "$DATA_DIR"
DROPIN_DIR=/etc/systemd/system/fileaccessmonitor.service.d
COLLECT=false
if [ -f "$DATA_DIR/agent.json" ]; then
    # This machine was an agent (the agent package was replaced): its registration would keep the
    # server from starting, and its settings are the monitoring server's copy, not this server's
    mv "$DATA_DIR/agent.json" "$DATA_DIR/agent.json.replaced"
    rm -f "$DATA_DIR/settings.json"
fi
if [ ! -f "$DATA_DIR/settings.json" ]; then
    /opt/fileaccessmonitor/FileAccessMonitor local-collection off >/dev/null
    # A new install serves the web GUI over HTTPS (self-signed certificate); upgrades keep their setting
    /opt/fileaccessmonitor/FileAccessMonitor web-https on >/dev/null
elif ! grep -q '"LocalCollection": false' "$DATA_DIR/settings.json"; then
    # Records and settings from an install that collected on this machine (tar.gz, or this package
    # before 1.11): keep doing so, with the collector service
    COLLECT=true
fi
# The root drop-in of 1.10 and older: the web part no longer runs as root
rm -f "$DROPIN_DIR/collect.conf"
# The data folder belongs to the web service account; the collector's folder inside it stays root's
# (root-owned, files private except key.hash)
mkdir -p "$DATA_DIR/collector"
find "$DATA_DIR" -path "$DATA_DIR/collector" -prune -o -exec chown fileaccessmonitor: {} +
chown root: "$DATA_DIR/collector"
chmod 755 "$DATA_DIR/collector"
chmod 700 "$DATA_DIR"
systemctl daemon-reload || true

if [ "$1" = 2 ] || { [ "$1" = configure ] && [ -n "${2:-}" ]; }; then
    systemctl try-restart fileaccessmonitor || true
    if $COLLECT; then
        systemctl enable --now fileaccessmonitor-collector >/dev/null 2>&1 || true
        systemctl try-restart fileaccessmonitor-collector || true
    else
        systemctl disable --now fileaccessmonitor-collector >/dev/null 2>&1 || true
    fi
else
    systemctl enable --now fileaccessmonitor >/dev/null 2>&1 || true
    if $COLLECT; then systemctl enable --now fileaccessmonitor-collector >/dev/null 2>&1 || true; fi
    sleep 3
    fileaccessmonitor-server || true
    echo "Open TCP 8080 and 8443 in the firewall if it is on. To also record this machine's Samba accesses:"
    echo "  sudo fileaccessmonitor-server --collect"
    if [ -f "$DATA_DIR/settings.json" ] && grep -q '"Https"' "$DATA_DIR/settings.json"; then
        echo "The web GUI is at https://<this machine>:8080 (self-signed certificate: the browser warns once)."
        echo "To use HTTP instead: sudo fileaccessmonitor-server --https off"
    fi
fi
