# Monitoring server on Linux

English | [日本語](linux-server.ja.md)

The monitoring server (web GUI, database, notifications, agent port) also runs on Linux. It can show only what agents send, or also record the Samba accesses of the Linux machine it runs on.

Requirements: x86-64 Linux with systemd (tested on Rocky Linux 9.4; Ubuntu, Debian, RHEL and AlmaLinux work the same way), and root to install.

```sh
sudo dnf install ./fileaccessmonitor-server-<version>-1.x86_64.rpm   # RHEL, Rocky, Alma
sudo apt install ./fileaccessmonitor-server_<version>-1_amd64.deb    # Ubuntu, Debian
```

A new install is **monitoring only** and runs as the user `fileaccessmonitor`. The `fileaccessmonitor-server` command shows and changes how it runs:

```sh
fileaccessmonitor-server                        # mode, port and service state
sudo fileaccessmonitor-server --collect         # also record this machine's Samba accesses (collector service, runs as root)
sudo fileaccessmonitor-server --monitor-only    # back to monitoring only
sudo fileaccessmonitor-server --port 8090       # web GUI port (default 8080)
sudo fileaccessmonitor-server --https on|off    # HTTPS for the web GUI (see Security)
```

Without a package manager, use `FileAccessMonitor-<version>-linux-x64-server.tar.gz`: unpack it and run `sudo sh install.sh` (options: `--collect`, `--monitor-only`, `--port <number>`, `--https on|off`).

- The server is installed to `/opt/fileaccessmonitor` and runs as the systemd service `fileaccessmonitor`, as the unprivileged user `fileaccessmonitor` (log: `journalctl -u fileaccessmonitor`). With `--collect`, the systemd service `fileaccessmonitor-collector` runs as root and records the machine's Samba accesses (log: `journalctl -u fileaccessmonitor-collector`); upgrading from 1.10 or older replaces its former root drop-in with it. Records and settings are in `/var/lib/fileaccessmonitor`, readable by the service account only; the collector keeps its own state in `/var/lib/fileaccessmonitor/collector` (root only, except `key.hash`). The tamper-detection key `chain.key` and `chain-head.json` are there too: back them up with the database.
- Sign in at `https://<server>:8080` as `admin` (a new install uses HTTPS with a self-signed certificate; the browser warns once); the initial password is in `/var/lib/fileaccessmonitor/initial-admin-password.txt` (`sudo cat` it).
- Open TCP 8080 and 8443 in the firewall if it is on, for example `firewall-cmd --permanent --add-port=8080/tcp --add-port=8443/tcp && firewall-cmd --reload` or `ufw allow 8080/tcp && ufw allow 8443/tcp`. The packages do not change the firewall.
- Upgrades (installing a newer package, or running `install.sh` again) keep the mode and port.
- With `--collect`, add the machine's own folders on the **Settings** tab (it appears as a server like the agents) and auditing is set up the same way as on a [Linux agent](agents.md#linux-file-servers-samba-agent). A machine runs either the monitoring server or the agent, not both; installing one package replaces the other.
- The notification secrets (webhook URL, SMTP password) are encrypted with keys in `/var/lib/fileaccessmonitor/keys`, protected by the folder's permissions (on Windows the keys are also encrypted with the machine's DPAPI).
- To remove it: `sudo dnf remove fileaccessmonitor-server` or `sudo apt remove fileaccessmonitor-server`; records and settings are kept (`apt purge` deletes them). With the tar.gz, `sudo sh install.sh --uninstall` in the unpacked folder (`--purge` also deletes records and settings).
