#!/bin/sh
# Before removing the agent package (deb: $1 = remove; rpm: $1 = 0). Not on upgrades.
set -e
if [ "$1" = remove ] || [ "$1" = 0 ]; then
    systemctl disable --now fileaccessmonitor-agent >/dev/null 2>&1 || true
fi
