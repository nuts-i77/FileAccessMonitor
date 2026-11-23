# Collect from several file servers (agents)

English | [日本語](agents.ja.md)

One install can show the records of several file servers. Install FileAccessMonitor normally on the server that will show the web GUI (the monitoring server); on each other file server, install it as an **agent**, which only collects and sends. The monitoring server can be one of the file servers, or a separate machine installed as **Monitoring server only** (on Windows or [Linux](linux-server.md)).

To switch an existing monitoring server between recording accesses on itself and monitoring only, run `FileAccessMonitor.exe local-collection off` (or `on`) in an elevated PowerShell in `C:\Program Files\FileAccessMonitor` and restart the service. The command only changes the setting; also enable or disable the collector service: `sc.exe config FileAccessMonitorCollector start= auto` and `sc.exe start FileAccessMonitorCollector` (or `start= disabled` and `sc.exe stop FileAccessMonitorCollector`); running the installer again does it for you. On Linux, `sudo fileaccessmonitor-server --collect` or `--monitor-only` does all of it. **Settings → App info** shows the current mode.

1. Make sure the file servers can reach the monitoring server on TCP port **8443** (the agent port). The monitoring server always listens on it, and the installer's firewall option allows it: the rule allows FileAccessMonitor.exe, so it covers both the web GUI port and the agent port.
2. Under **Settings → Agents**, choose **Issue registration code**. If the file servers reach the monitoring server by another name or by IP address, change the address there and choose **Apply**. Copy the connection string; it is valid for 24 hours and can be used once. This code registers a server that is not registered yet. To register an agent again (for example after reinstalling the file server), use the key button in that agent's row instead: that code registers only that agent. No code can register a server under the monitoring server's own name.
3. On the file server, run the installer, choose **Agent**, and paste the connection string. To turn an existing install into an agent, run in an elevated PowerShell:

   ```powershell
   & "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" enroll <connection string>
   Restart-Service FileAccessMonitor
   ```
4. On the file server, set up auditing of the shared folders in an elevated PowerShell. `-ExecutionPolicy Bypass` runs this one script even where scripts are disabled:

   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Program Files\FileAccessMonitor\scripts\setup-audit.ps1" -SharePaths "D:\Share"
   ```

How it works and limits:

- A 1.8 agent works with a 1.9 monitoring server. A 1.9 agent that talks to a 1.8 server sends records without the new data (refused access and permission changes are not sent, Create is sent as Write, no new paths); records waiting in the outbox are not rewritten, so they arrive in full once the server is upgraded.
- Agents connect to the monitoring server; the monitoring server never connects to them. The connection uses HTTPS with a certificate the monitoring server creates itself; agents trust exactly that certificate (its fingerprint is in the connection string), so no certificate authority is needed.
- Records are kept in a local outbox on the agent (`C:\ProgramData\FileAccessMonitor\outbox`, up to 2 GB) until the monitoring server has saved them, so nothing is lost while it is unreachable.
- When the outbox is full (2 GB), the agent does not drop records: collection on that server pauses and the agent checks every 30 seconds for room. The records stay in the Security log (Linux: the journal) and are collected after the monitoring server is reachable again and the agent has sent the waiting data. This works only as long as the log has not wrapped: if the Security log overwrites records first, the existing recording-gap notice reports the missing range (Linux agents notice a rotated journal when they start reading again). The agent reports the state in its heartbeat; the **Agents** tab shows **Send queue full**, and a notification is sent once (when notifications are on). Enlarge the Security log on busy servers (step 5) to give more room.
- When records come from more than one server, a server filter appears at the top of the web GUI, and lists get a **Server** column. To leave removed agents out of that filter, turn on the switch under **Settings → Agents** (their records stay, under **All servers**).
- Monitored folders and recording rules are set per server: pick the server above the menu of the **Settings** tab. An agent picks up changes within a minute. When a folder is added on an agent's server, the agent checks it exists and sets its audit entries (SACL); the **Unused Files** tab lists files on the chosen server through its agent. These need the agent to be online. Until folders are set for an agent's server, the agent records every audited access on it.
- Viewing scopes can name a server for each folder (or apply to the path on every server).
- The **Agents** list shows each agent's OS (Windows or Linux), last contact, version (flagged when it differs from the monitoring server's, with **How to update** showing the commands to run on that file server), batches waiting to be sent, and whether file access auditing is on. When notifications are on, an agent that has not been in touch for 15 minutes (configurable; 0 turns it off) is reported, and again when it is back.
- Alerts and notifications name the file server the accesses happened on.
- Record times come from each file server's clock; keep the servers' clocks synchronized (NTP; domain members do this by default).
- `FileAccessMonitor.exe unenroll` turns an agent back into a standalone install.

To change the agent port:

1. Add the following to `C:\ProgramData\FileAccessMonitor\settings.json` on the monitoring server. Keep the other settings in the file.

   ```json
   "Agents": { "Port": 9443 }
   ```
2. Restart the service with `Restart-Service FileAccessMonitor`. The firewall rule made by the installer allows the program, not a port, so it needs no change.
3. Registered agents keep the old address. Issue a new connection string and, on each file server, run `FileAccessMonitor.exe enroll <connection string>` and restart the service.

If you do not use agents and do not want the port open, set `"Agents": { "Enabled": false }` instead.

## Linux file servers (Samba agent)

A Linux file server that shares folders with Samba can send its records to the monitoring server too. The Linux agent reads the audit lines of Samba's `full_audit` module from the systemd journal; it records accesses through SMB shares (not NFS, and not changes made on the server itself).

Requirements: x86-64 Linux with systemd and Samba 4.x (tested on Ubuntu 24.04 with Samba 4.19 and Rocky Linux 9.4 with Samba 4.23; Debian, RHEL and AlmaLinux work the same way), and root.

1. Download the package for your distribution from the release page: `fileaccessmonitor-agent-<version>-1.x86_64.rpm` (RHEL, Rocky, Alma) or `fileaccessmonitor-agent_<version>-1_amd64.deb` (Ubuntu, Debian).
2. Issue a connection string under **Settings → Agents** on the monitoring server, then run as root:

   ```sh
   sudo dnf install ./fileaccessmonitor-agent-<version>-1.x86_64.rpm     # or: sudo apt install ./fileaccessmonitor-agent_<version>-1_amd64.deb
   sudo fileaccessmonitor-agent enroll <connection string>
   sudo systemctl enable --now fileaccessmonitor-agent
   ```
   Without a package manager, use `FileAccessMonitor-<version>-linux-x64-agent.tar.gz`: unpack it and run `sudo sh install.sh <connection string>`.

   The agent runs as the systemd service `fileaccessmonitor-agent` (log: `journalctl -u fileaccessmonitor-agent`); its data is in `/var/lib/fileaccessmonitor`. Upgrade it by installing the newer package (`dnf install` / `apt install` again).
3. Restart Samba once when convenient (`systemctl restart smbd`, or `smb` on RHEL). The installer adds a setting so that journald does not drop Samba's audit lines when there are many of them; it takes effect when Samba restarts.
4. On the **Settings** tab of the monitoring server, pick the Linux server and add folders by their Linux path, such as `/srv/share/docs`.

How it differs from Windows:

- Adding a folder turns on auditing for the Samba shares that hold it (or are inside it), by editing `smb.conf`: the agent checks the new configuration with `testparm`, keeps a backup (`smb.conf.fam-backup-<time>`), and reloads Samba. Its lines sit between `# FileAccessMonitor begin` and `# FileAccessMonitor end`; lines it replaced (a share's own `vfs objects` or `full_audit` settings) are kept as comments and come back when the folder is removed with **Stop monitoring + remove SACL**. Shares defined in included files or in the registry are not changed.
- Auditing starts with new connections to the share; clients that are already connected are recorded after they reconnect.
- Paths are case-sensitive. User names are those Samba logs in (`DOMAIN\user` on domain members); the client machine name comes from the SMB connection.
- Reads and writes are the access the client asked for when opening a file, as on Windows; deletions and renames are recorded when they happen. Refused access, permission changes, creation and the new path of renames are recorded too (see [Access type classification](how-it-works.md#access-type-classification-accessmask)). Shares that were set up by an earlier version need **Re-apply SACL** (the same button) once to get the failure and permission auditing; Samba then logs every failed open, so the journal grows faster. Turn off **Also record refused access** under Settings → Recording and re-apply to avoid that.
- To remove the agent: remove its folders on the monitoring server first, then `sudo dnf remove fileaccessmonitor-agent` or `sudo apt remove fileaccessmonitor-agent` (`apt purge` also deletes its registration and waiting records). With the tar.gz, run `sudo sh install.sh --uninstall` in the unpacked folder (add `--purge` to delete its data too).
