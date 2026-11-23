#!/bin/sh
# Before removing the monitoring server package (deb: $1 = remove; rpm: $1 = 0). Not on upgrades.
set -e
if [ "$1" = remove ] || [ "$1" = 0 ]; then
    # The daily backup timer (the backups themselves are kept with the data folder)
    /opt/fileaccessmonitor/FileAccessMonitor backup-schedule --off >/dev/null 2>&1 || true
    rm -f /var/lib/fileaccessmonitor/backup-schedule.json
    systemctl disable --now fileaccessmonitor-collector >/dev/null 2>&1 || true
    systemctl disable --now fileaccessmonitor >/dev/null 2>&1 || true
fi
