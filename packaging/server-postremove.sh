#!/bin/sh
# After removing the monitoring server package (deb: $1 = remove or purge; rpm: $1 = 0, or 1 on an
# upgrade). Records and settings in /var/lib/fileaccessmonitor are kept; deb "purge" deletes them.
set -e
if [ "$1" = remove ] || [ "$1" = purge ] || [ "$1" = 0 ]; then
    rm -rf /etc/systemd/system/fileaccessmonitor.service.d
    rm -f /etc/systemd/system/smbd.service.d/fileaccessmonitor.conf /etc/systemd/system/smb.service.d/fileaccessmonitor.conf
fi
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = purge ]; then
    # The agent package uses the same data folder: leave it when that is installed now
    [ -f /usr/lib/systemd/system/fileaccessmonitor-agent.service ] || rm -rf /var/lib/fileaccessmonitor
    userdel fileaccessmonitor >/dev/null 2>&1 || true
fi
