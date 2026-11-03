#!/bin/sh
# After installing or upgrading the monitoring server package (deb: $1 = configure, $2 = the old
# version on upgrades; rpm: $1 = 1 install, 2 upgrade). A new install is monitoring only, running as
# the user fileaccessmonitor; fileaccessmonitor-server --collect changes that. Upgrades keep the mode.
set -e
DATA_DIR=/var/lib/fileaccessmonitor
id fileaccessmonitor >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin fileaccessmonitor
mkdir -p "$DATA_DIR"
DROPIN_DIR=/etc/systemd/system/fileaccessmonitor.service.d
if [ -f "$DATA_DIR/agent.json" ]; then
    # This machine was an agent (the agent package was replaced): its registration would keep the
    # server from starting, and its settings are the monitoring server's copy, not this server's
    mv "$DATA_DIR/agent.json" "$DATA_DIR/agent.json.replaced"
    rm -f "$DATA_DIR/settings.json"
fi
if [ ! -f "$DATA_DIR/settings.json" ]; then
    /opt/fileaccessmonitor/FileAccessMonitor local-collection off >/dev/null
elif ! grep -q '"LocalCollection": false' "$DATA_DIR/settings.json" && [ ! -f "$DROPIN_DIR/collect.conf" ]; then
    # Records and settings from a tar.gz install that collected on this machine: keep doing so (as root)
    mkdir -p "$DROPIN_DIR"
    printf '# Set by fileaccessmonitor-server --collect\n[Service]\nUser=root\n' > "$DROPIN_DIR/collect.conf"
fi
if [ -f "$DROPIN_DIR/collect.conf" ]; then
    chown -R root: "$DATA_DIR"
else
    chown -R fileaccessmonitor: "$DATA_DIR"
fi
chmod 700 "$DATA_DIR"
systemctl daemon-reload || true

if [ "$1" = 2 ] || { [ "$1" = configure ] && [ -n "${2:-}" ]; }; then
    systemctl try-restart fileaccessmonitor || true
else
    systemctl enable --now fileaccessmonitor >/dev/null 2>&1 || true
    sleep 3
    fileaccessmonitor-server || true
    echo "Open TCP 8080 and 8443 in the firewall if it is on. To also record this machine's Samba accesses:"
    echo "  sudo fileaccessmonitor-server --collect"
fi
