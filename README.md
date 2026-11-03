# FileAccessMonitor

English | [日本語](README.ja.md)

FileAccessMonitor collects file access events (read, write, delete) on a Windows file server's shared folders from the Windows Security audit log. It stores them in SQLite and shows them in a web GUI. Linux file servers that share folders with Samba can send their records too, through an agent.

![Dashboard](docs/images/dashboard-en.png)

> [!IMPORTANT]
> This tool records who accessed which file and when. If you use it in an organization, tell the people being monitored in advance, in line with your workplace rules and privacy policy.

## Requirements

- Windows Server 2016 or later (or Windows 10/11), running on the server that hosts the shared folders
- .NET 10 SDK, needed to build only. The app is published self-contained, so the server does not need the .NET runtime.
- Administrator rights, needed to read the Security log and to set SACLs

## Setup

### Install with the installer (recommended)

Download `FileAccessMonitor-Setup-<version>.exe` from [Releases](https://github.com/nuts-i77/FileAccessMonitor/releases) and run it on the file server. The installer does the following:

- Installs to `C:\Program Files\FileAccessMonitor`
- Registers and starts the `FileAccessMonitor` Windows service
- Lets you choose the web GUI port (default 8080) and, optionally, adds a firewall rule that allows FileAccessMonitor.exe (the web GUI port and the agent port 8443)

When you run a newer installer, it upgrades the existing install and keeps your settings. Then continue with [3. First sign-in](#3-first-sign-in).

> [!NOTE]
> The installer is not code-signed, so Windows SmartScreen may show a warning. Choose **More info** → **Run anyway**. To check that the download is genuine, see [Verifying downloads](#verifying-downloads).

To build from source instead, follow steps 1 and 2.

### 1. Build (on your development PC)

```powershell
.\build.ps1
```

A self-contained EXE is written to `publish\`.

### 2. Install the service (on the server, in an elevated PowerShell)

Copy `publish\` and `install-service.ps1` to the server, then run:

```powershell
.\install-service.ps1
```

This does two things:

- Registers and starts a Windows service named `FileAccessMonitor`, with automatic startup
- Adds a Windows Firewall inbound rule for FileAccessMonitor.exe (TCP 8080, and 8443 for agents)

If WinRM is available, you can build and deploy from your development PC in one step:

```powershell
.\deploy-remote.ps1 -ServerIP <server name or IP>
```

### 3. First sign-in

Open `http://<server>:8080` in a browser and sign in with:

- User name: `admin`
- Password: generated at random on first start and saved on the server in this file, which only SYSTEM and Administrators can read:

  ```
  C:\ProgramData\FileAccessMonitor\initial-admin-password.txt
  ```

After you sign in, open the user menu (top right) → **Change password** and set your own password. The file is deleted automatically when you change it.

### 4. Add folders to monitor

On the **Settings** tab, add a folder to monitor, for example `D:\Share`. When you add it, the tool does two things automatically:

- Enables the **File System** audit policy
- Sets audit entries (SACLs) on the folder and everything under it

The **File Share** audit policy, used to find the client IP address, is enabled automatically when the service starts.

To configure auditing with scripts instead, run `setup-audit.ps1 -SharePaths "D:\Share"`. To undo it, run `restore-audit.ps1 -SharePaths "D:\Share"`.

### 5. Enlarge the Security log (recommended)

By default the Windows Security log holds only about 20 MB. On a busy server, older events are overwritten within hours. FileAccessMonitor collects events in real time, so its own records are not lost. A larger log still lets you check the original events later.

```powershell
wevtutil sl Security /ms:1073741824   # 1 GB
```

### 6. Collect from several file servers (agents)

One install can show the records of several file servers. Install FileAccessMonitor normally on the server that will show the web GUI (the monitoring server); on each other file server, install it as an **agent**, which only collects and sends.

1. Make sure the file servers can reach the monitoring server on TCP port **8443** (the agent port). The monitoring server always listens on it, and the installer's firewall option allows it: the rule allows FileAccessMonitor.exe, so it covers both the web GUI port and the agent port.
2. Under **Settings → Agents**, choose **Issue registration code**. If the file servers reach the monitoring server by another name or by IP address, change the address there and choose **Apply**. Copy the connection string; it is valid for 24 hours and can be used once.
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

- Agents connect to the monitoring server; the monitoring server never connects to them. The connection uses HTTPS with a certificate the monitoring server creates itself; agents trust exactly that certificate (its fingerprint is in the connection string), so no certificate authority is needed.
- Records are kept in a local outbox on the agent (`C:\ProgramData\FileAccessMonitor\outbox`, up to 2 GB) until the monitoring server has saved them, so nothing is lost while it is unreachable.
- When records come from more than one server, a server filter appears at the top of the web GUI, and lists show the server name with the path.
- Monitored folders and recording rules are set per server: pick the server at the top of the **Settings** tab. An agent picks up changes within a minute. When a folder is added on an agent's server, the agent checks it exists and sets its audit entries (SACL); the **Unused Files** tab lists files on the chosen server through its agent. These need the agent to be online. Until folders are set for an agent's server, the agent records every audited access on it.
- Viewing scopes can name a server for each folder (or apply to the path on every server).
- The **Agents** list shows each agent's last contact, version (flagged when it differs from the monitoring server's), batches waiting to be sent, and whether file access auditing is on. When notifications are on, an agent that has not been in touch for 15 minutes (configurable; 0 turns it off) is reported, and again when it is back.
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

### 7. Linux file servers (Samba agent)

A Linux file server that shares folders with Samba can send its records to the monitoring server too. The Linux agent reads the audit lines of Samba's `full_audit` module from the systemd journal; it records accesses through SMB shares (not NFS, and not changes made on the server itself).

Requirements: x86-64 Linux with systemd and Samba 4.x (tested on Ubuntu 24.04 with Samba 4.19 and Rocky Linux 9.4 with Samba 4.23; Debian, RHEL and AlmaLinux work the same way), and root.

1. Download `FileAccessMonitor-<version>-linux-x64.tar.gz` from the release page and unpack it on the file server.
2. Issue a connection string under **Settings → Agents** on the monitoring server, then run as root:

   ```sh
   tar xzf FileAccessMonitor-<version>-linux-x64.tar.gz
   cd FileAccessMonitor-<version>-linux-x64
   sudo sh install.sh <connection string>
   ```
   The agent runs as the systemd service `fileaccessmonitor-agent` (log: `journalctl -u fileaccessmonitor-agent`); its data is in `/var/lib/fileaccessmonitor`.
3. Restart Samba once when convenient (`systemctl restart smbd`, or `smb` on RHEL). The installer adds a setting so that journald does not drop Samba's audit lines when there are many of them; it takes effect when Samba restarts.
4. On the **Settings** tab of the monitoring server, pick the Linux server and add folders by their Linux path, such as `/srv/share/docs`.

How it differs from Windows:

- Adding a folder turns on auditing for the Samba shares that hold it (or are inside it), by editing `smb.conf`: the agent checks the new configuration with `testparm`, keeps a backup (`smb.conf.fam-backup-<time>`), and reloads Samba. Its lines sit between `# FileAccessMonitor begin` and `# FileAccessMonitor end`; lines it replaced (a share's own `vfs objects` or `full_audit` settings) are kept as comments and come back when the folder is removed with **Stop monitoring + remove SACL**. Shares defined in included files or in the registry are not changed.
- Auditing starts with new connections to the share; clients that are already connected are recorded after they reconnect.
- Paths are case-sensitive. User names are those Samba logs in (`DOMAIN\user` on domain members); the client machine name comes from the SMB connection.
- Reads and writes are the access the client asked for when opening a file, as on Windows; deletions and renames are recorded when they happen.
- To remove the agent: remove its folders on the monitoring server first, then run `sudo sh install.sh --uninstall` in the unpacked folder (add `--purge` to delete its data too).

## Security

- **JWT signing key**: generated at random on first start and saved to `C:\ProgramData\FileAccessMonitor\jwt.key`, which only SYSTEM and Administrators can read. If you set a `Jwt:Key` of 32 bytes or more in `appsettings.json`, that key is used instead.
- **Sign-in lockout**: after 5 failed sign-ins in a row, the account is locked for 15 minutes.
- **Viewing scopes**: under **Settings → User Management**, an Admin can limit a Viewer to some folders, for example one department's share. That user then sees only records inside those folders, everywhere including CSV export and the Unused Files tab, and can be given an email address that receives alerts about those folders. Admins, and Viewers without folders, see everything. Changes apply on the user's next request.
- **Sign-in sessions**: a sign-in stays valid for `Jwt:ExpiresHours` (default 24 hours), but ends immediately when the user is deleted, their role changes, or their password is changed or reset.
- **Operation log**: sign-ins (including failures), user management, setting changes, CSV exports, and notifications sent are recorded and shown under **Settings → Operation Log** (Admin only).
- **Notification secrets**: the webhook URL and SMTP password are stored encrypted (ASP.NET Core Data Protection with machine DPAPI; keys in `C:\ProgramData\FileAccessMonitor\keys\`).
- **Transport encryption**: the default is plain HTTP. To use HTTPS, either add an HTTPS endpoint and certificate under `Kestrel.Endpoints`, or put the app behind a reverse proxy such as IIS, nginx, or Caddy. See [docs/https.md](docs/https.md) for sample configurations. Do this if the GUI is reachable from outside your LAN, or if passwords must not travel in clear text.
- **Roles**: `Admin` can change settings and manage users. `Viewer` can only view.

To report a vulnerability, please follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Configuration

### appsettings.json (in `publish\`)

| Setting | Description | Default |
|---|---|---|
| `Kestrel.Endpoints.Http.Url` | Listen URL | `http://0.0.0.0:8080` |
| `Jwt:ExpiresHours` | How long a sign-in stays valid, in hours | `24` |
| `Jwt:Key` | JWT signing key (usually not needed; see above) | Auto-generated |
| `ExcludeSystemAccounts` | Ignore access by SYSTEM and computer accounts (`xxx$`) | `true` |
| `ExcludeProcessNames` | Process names to ignore | `System`, `svchost.exe`, `SearchIndexer.exe` |

With the installer, `appsettings.json` is in `C:\Program Files\FileAccessMonitor\` and is replaced on upgrade. Put your own changes in `appsettings.Production.json` in the same folder instead. The installer creates that file with the port you chose, and your changes to it are kept on upgrade.

### Runtime settings and data (`C:\ProgramData\FileAccessMonitor\`)

| File | Contents |
|---|---|
| `settings.json` | Monitored folders, recorded access types, reverse-DNS server, retention, notifications (edited from the GUI) |
| `fileaccess.db` | Access records (SQLite) |
| `logs\app-YYYYMMDD.log` | Application log (kept for 14 days) |
| `jwt.key` | JWT signing key |

## Web GUI

| Tab | Contents |
|---|---|
| Dashboard | Access trend chart, breakdown by type, top files and folders |
| Files / Folders / Users | Rankings with detail dialogs |
| Recent | Access log with client IP and machine name |
| Search | Search by keyword, period, type, or IP; export the results as CSV (up to 200,000 rows, opens in Excel) |
| Unused Files | Files in a monitored folder that nobody read (or accessed) in a period, found by scanning the folder, with their size totaled per subfolder (Admin only; up to 100,000 files per scan) |
| Settings | Monitored folders, users, recording rules (exclusions and merging of repeated reads), reverse DNS, data retention, notifications, operation log |

Notifications (Teams, Slack, a webhook, or email) are sent when one user deletes, writes, or reads at least a set number of files within a few minutes (mass reads are off by default), and when recording was interrupted: Security log events were overwritten before they were collected, or the log was cleared (with the user who cleared it). If the internet is reached through a proxy, set it in the notification settings (webhooks only; the service runs as SYSTEM, so the Windows proxy setting does not apply).

The GUI is available in English and Japanese. Switch languages at the top right; on first visit the GUI follows the browser's language. Messages returned by the API use the selected language too.

**Recent access log** — who opened which file, on which file server, from which IP address and machine:

![Recent access log](docs/images/recent-en.png)

**Settings** — per-server monitored folders and recording rules (here for the agent FS01), then the settings for all servers:

![Settings](docs/images/settings-en.png)

The screenshots use fictional sample data.

## How it works

1. Subscribes to the Windows Security event log in real time (events 4663, 4659, and 4660).
2. Finds the client IP address and machine name from logon (4624) and share access (5140) events and from the list of SMB sessions.
3. Stores records in SQLite and aggregates them through an ASP.NET Core web API.
4. Displays them in the browser with Bootstrap and Chart.js.

### Access type classification (AccessMask)

| Type | Mask |
|---|---|
| Read | `0x1` (ReadData) / `0x80000000` (GENERIC_READ) |
| Write | `0x2` (WriteData) / `0x4` (AppendData) / `0x40000000` (GENERIC_WRITE) |
| Delete | `0x10000` (DELETE) followed by event 4660 (object deleted) for the same handle, and event 4659 |
| Rename | `0x10000` (DELETE) with no event 4660: the file was renamed or moved |

Renames and moves also open the file with DELETE access, so a DELETE access is held for up to 2 seconds until event 4660 shows whether the file was actually deleted. If it was not, and a file exists again at the same path (Office saves a document by renaming the old file away and a new file into its place), the access is recorded as a write. Renames are recorded for folders where Delete is selected.

Folders are recorded only when they are deleted or renamed, shown with a folder icon and marked in the CSV export. They are left out of the file ranking and of mass-deletion alerts, which already count the files inside. Opening a folder or adding files to it is not recorded.

### Recording rules

On the **Settings** tab, administrators can exclude file name patterns (`*` and `?` wildcards), users, and processes, and merge repeated reads: when the same user reads the same file again within the set time of the previous read (5 minutes by default), it is not recorded again. The window restarts with each read, so watching a long video with seeks counts as one read. By default `Thumbs.db`, `desktop.ini`, `~$*` (Office lock files), and `*.tmp` are excluded. The rules apply to accesses recorded after they are saved.

## Comparison with other tools

FileAccessMonitor aims at one job: letting a small team see who read, changed, or deleted files on a Windows file server, without building a log platform. If you need more than that, another tool is likely a better fit.

| | FileAccessMonitor | Commercial auditing products<br>(e.g. Netwrix Auditor, ManageEngine ADAudit Plus) | Wazuh |
|---|---|---|---|
| Cost | Free (MIT) | Paid licenses | Free (open source); paid cloud and support available |
| Setup | One installer on the file server | Installer; often needs a separate server and database | Wazuh server, indexer, and dashboard, plus an agent on each host |
| Scope | File access on one Windows file server | File servers, NAS, Active Directory, Microsoft 365, and more | Security monitoring (SIEM/XDR) across many hosts |
| Who **read** a file | Yes (Security log events 4663/4659) | Yes | File integrity monitoring covers changes only; reads need Security-log collection and your own rules |
| Multiple servers in one view | No (one instance and GUI per server) | Yes | Yes |
| Alerts | Mass delete / change / read, and gaps in recording, to Teams, Slack, a webhook, or email | Many built-in rules | Flexible rules and automated responses |
| Reports | Search and CSV export | Built-in compliance and scheduled reports | Dashboards and compliance mappings |
| Japanese UI | Yes | Varies by product | No |
| Support | Community (GitHub Issues), no SLA | Vendor support | Community, or paid vendor support |

**When to choose which**

- **FileAccessMonitor**: you have one or a few Windows file servers, want answers to "who deleted this file?" or "who opened this folder?", and do not want to run a log platform.
- **A commercial product**: you need to audit several servers, AD, or Microsoft 365 together, need compliance reports, or need vendor support.
- **Wazuh**: you are building organization-wide security monitoring and file access is one of many sources.

Product capabilities above are summarized from public information and may change. Check each vendor's documentation for details.

## Limitations

- **Operations that do not open a file are not recorded.** This includes reading only attributes or timestamps (`0x80` ReadAttributes and similar) and listing folders. For example, when an incremental backup tool finds a file unchanged and skips copying it, that file is not recorded.
- Events that occur while the service is stopped (for example during an upgrade or reboot) are collected when it starts again, as long as they are still in the Security log. If the log has already overwritten them, the gap is recorded in the operation log.
- The service must run on the file server it monitors. It cannot monitor remote servers.
- For renames and moves, only the old path is recorded. The Security log does not include the new path.
- A folder that is deleted or renamed is recognized as a folder when it is still there as the event is processed, or when accesses to files inside it were seen recently. Otherwise (for example an empty folder) it is recorded as a file.
- Times are stored in UTC. The GUI shows them, and groups them by day, in the browser's time zone.

## Development

```powershell
dotnet build FileAccessMonitor.csproj
dotnet test tests/FileAccessMonitor.Tests
```

To build the installer locally, install [Inno Setup 6](https://jrsoftware.org/isinfo.php) and run `.\build-installer.ps1 -Version 1.0.0`. The output goes to `dist\`.

To run a second instance for development or demos without touching an installed one, set the `FILEACCESSMONITOR_DATA` environment variable to another data folder (default `C:\ProgramData\FileAccessMonitor`) and another port, e.g. `$env:Kestrel__Endpoints__Http__Url = 'http://localhost:5099'`.

GitHub Actions (`.github/workflows/ci.yml`) builds, tests, and publishes the app on every push and pull request. Pushing a tag such as `v1.0.0` runs `.github/workflows/release.yml`, which builds the installer and a portable zip and publishes them as a GitHub Release.

## Uninstall

If you used the installer, uninstall **File Access Monitor** from **Settings → Apps**. The service and firewall rule are removed. Access records, settings, and keys stay in `C:\ProgramData\FileAccessMonitor\`; delete that folder if you no longer need them. To remove the audit entries (SACLs), run `C:\Program Files\FileAccessMonitor\scripts\restore-audit.ps1` before uninstalling.

If you installed from source:

```powershell
.\install-service.ps1 -Uninstall
.\restore-audit.ps1 -SharePaths "D:\Share"   # to remove the audit settings as well
```

## Verifying downloads

The release files are built by this repository's [release workflow](.github/workflows/release.yml) on GitHub Actions from the tagged source. Each release includes a GitHub [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations), so you can check that a file was built there and has not been modified. With the [GitHub CLI](https://cli.github.com/), run:

```powershell
gh attestation verify FileAccessMonitor-Setup-<version>.exe -R nuts-i77/FileAccessMonitor
```

Without the GitHub CLI, compare the output of `Get-FileHash <file>` with `SHA256SUMS.txt` on the release page.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it. It sends data to other systems only when an administrator configures it to: notifications go to the webhook URLs and mail servers set on the Settings tab, and reverse DNS lookups of client IP addresses go to the DNS servers set there. An agent sends its access records to the monitoring server it was registered with.

Update check: when an Admin opens the web GUI, at most once a day, the Admin's browser asks the GitHub API (`api.github.com`) for the latest release of this project. Like any web request, this reveals the browser's IP address and user agent to GitHub. No data about the file server or its records is sent, and the file server itself does not connect out. Turn it off under **Settings → App info**.

## License

[MIT License](LICENSE)

Bundled third-party libraries (`wwwroot/lib/`):

| Library | Version | License |
|---|---|---|
| [Bootstrap](https://getbootstrap.com/) | 5.3.3 | MIT |
| [Bootstrap Icons](https://icons.getbootstrap.com/) | 1.11.3 | MIT |
| [Chart.js](https://www.chartjs.org/) | 4.4.4 | MIT |

Each library's license text is in its folder under `wwwroot/lib/`.
