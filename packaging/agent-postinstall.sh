#!/bin/sh
# After installing or upgrading the agent package (deb: $1 = configure; rpm: $1 = 1 install, 2 upgrade)
set -e
mkdir -p /var/lib/fileaccessmonitor
chmod 700 /var/lib/fileaccessmonitor
systemctl daemon-reload || true
if [ -f /var/lib/fileaccessmonitor/agent.json ]; then
    # Registered (an upgrade, or reinstalled): carry on with the new version
    systemctl enable fileaccessmonitor-agent >/dev/null 2>&1 || true
    systemctl restart fileaccessmonitor-agent || true
else
    echo "Register the agent with a connection string from Settings > Agents on the monitoring server:"
    echo "  sudo fileaccessmonitor-agent enroll <connection string>"
    echo "  sudo systemctl enable --now fileaccessmonitor-agent"
    echo "Restart Samba when convenient so that journald keeps all of its audit lines."
fi
