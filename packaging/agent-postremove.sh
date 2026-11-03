#!/bin/sh
# After removing the agent package. The registration and waiting records in /var/lib/fileaccessmonitor
# are kept (deb "purge" deletes them). Shares keep the audit settings the agent added to smb.conf
# until their folders are removed on the monitoring server.
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
# The monitoring server package uses the same data folder: leave it when that is installed now
if [ "$1" = purge ] && [ ! -f /usr/lib/systemd/system/fileaccessmonitor.service ]; then
    rm -rf /var/lib/fileaccessmonitor
fi
