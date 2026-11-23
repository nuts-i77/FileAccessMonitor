# Security

English | [日本語](security.ja.md)

- **Privilege separation**: the web GUI, the API and the database never run with elevated rights (see [Which account runs what](#which-account-runs-what)). What needs them (reading the Security log, setting SACLs, scanning shares and ACLs) is done by a second process, the collector, which has no web interface and listens on no port. The two talk over the loopback address on the agent port, and the collector proves itself with a random secret that only SYSTEM (root) can read; the web service holds only its hash.
- **JWT signing key**: generated at random on first start and saved to `C:\ProgramData\FileAccessMonitor\jwt.key`, which only SYSTEM, Administrators and the web GUI service account can read. If you set a `Jwt:Key` of 32 bytes or more in `appsettings.json`, that key is used instead.
- **Sign-in limits**: after 5 failed sign-ins for a user from one client address within 15 minutes, sign-in for that user from that address is paused for 15 minutes; the same user can still sign in from other addresses, so nobody can lock another user out. An address with 20 failures (any user names) and a user name with 100 failures (any addresses) are paused too. Requests from loopback are not counted per address; behind a reverse proxy, list it in `ReverseProxy:KnownProxies` so the real client addresses are counted. The counts are kept in memory and start again when the service restarts.
- **Viewing scopes**: under **Settings → Users**, an Admin can limit a Viewer to some folders, for example one department's share. That user then sees only records inside those folders, everywhere including CSV export and the Unused Files tab, and can be given an email address that receives alerts about those folders. Admins see everything. A Viewer with no folders sees nothing; to let a Viewer see everything, choose **All folders** (Viewers that had no folders before 1.11 were set to All folders once on upgrade). Changes apply on the user's next request.
- **Sign-in sessions**: a sign-in stays valid for `Jwt:ExpiresHours` (default 8 hours; 24 before 1.11.1). **Sign out** ends that token on the server as well, so a copy of it cannot be used afterwards (the user's other sign-ins stay). A sign-in also ends immediately when the user is deleted, their role changes, or their password is changed or reset.
- **Operation log**: sign-ins (including failures), user management, setting changes, CSV exports, and notifications sent are recorded and shown under **Settings → Operation log** (Admin only).
- **Notification secrets**: the webhook URL and SMTP password are stored encrypted (ASP.NET Core Data Protection with machine DPAPI; keys in `C:\ProgramData\FileAccessMonitor\keys\`).
- **Tamper detection**: records changed, deleted or added outside the program are detected with the key in `chain.key` (and `chain-head.json`) in the data folder. Back both up with the database. Records saved before 1.10 are not protected, and restoring an older database shows as a finding to accept after checking it. Someone with administrator rights on the server who also has the key can rebuild the chain; copies of the daily anchors kept elsewhere (the report mail, a downloaded anchor file, a forwarded event log) show that. See **Settings → Tamper detection**.
- **Transport encryption**: the web GUI serves HTTPS itself, on the same port as before. A **new install** has it on, with a self-signed certificate that the server creates (it covers the machine name, its addresses and `localhost`, and is made again if one is missing); browsers warn about it once. An install upgraded from before 1.9 stays on HTTP until you switch (the Windows installer asks; silent installs use `/HTTPS=1` or `/HTTPS=0`). Switch with these commands, then restart the service; `status` shows the current setting:

  ```powershell
  # Windows, in C:\Program Files\FileAccessMonitor
  .\FileAccessMonitor.exe web-https on|off|status
  ```

  ```sh
  # Linux
  sudo fileaccessmonitor-server --https on|off
  ```

  To use your own certificate instead, give a PFX file: `FileAccessMonitor.exe web-https on --pfx cert.pfx --pfx-password <password>` (Linux: `sudo fileaccessmonitor-server --https on --pfx cert.pfx --pfx-password-file pw.txt`). The certificate needs a private key; a warning is printed if it does not match the machine name. `--redirect-port 8081` also opens a plain HTTP port that redirects browsers to the HTTPS port. After switching, old `http://` bookmarks stop working unless you use the redirect port. If the certificate cannot be loaded, the web GUI is served over HTTP on the machine itself only (`localhost`, never on other interfaces) so that you can still sign in there; the log says why and how to fix it (`FileAccessMonitor.exe web-https status`, a new PFX, or `web-https off` behind a reverse proxy), and **Settings** shows the reason. The redirect port stays closed in that case. **Settings** shows the certificate in use (read-only), and an Admin who opens the GUI over plain HTTP sees a warning. The agent port 8443 has its own certificate and is not affected. There is no HSTS header, so you can always accept the self-signed certificate. Behind a reverse proxy you can leave HTTPS off (see [docs/https.md](https.md)).
- **Roles**: `Admin` can change settings and manage users. `Viewer` can only view.

To report a vulnerability, please follow [SECURITY.md](../SECURITY.md) instead of opening a public issue.

## Which account runs what

| | Windows | Linux |
|---|---|---|
| Web GUI, API, database, notifications, agent port | Service `FileAccessMonitor`, virtual account `NT SERVICE\FileAccessMonitor` (no password, no privileges) | systemd `fileaccessmonitor`, user `fileaccessmonitor` |
| Recording on this server, setting up auditing, scanning folders and permissions (only while local collection is on) | Service `FileAccessMonitorCollector`, SYSTEM | systemd `fileaccessmonitor-collector`, root |
| Agent | Service `FileAccessMonitor`, SYSTEM (unchanged) | systemd `fileaccessmonitor-agent`, root |

The collector is the same program started with the argument `collector`. It works like a built-in agent: it sends its batches to `https://127.0.0.1:<agent port>` (trusting that certificate by its fingerprint), takes the monitored folders and recording rules from the web service, and runs the web GUI's jobs (setting SACLs, scanning for unused files, permission scans). It needs no registration. It shows in **Settings → Agents** as a row for this server (status only), and a stopped collector is notified like an offline agent. If it is not running, the GUI says so and records are not made until it is started again (the Security log keeps the events meanwhile, as when an agent is stopped). Its own state is in `collector\` below the data folder, which the web service cannot read.

If the web service does not stay running under `NT SERVICE\FileAccessMonitor` after an install or upgrade, the installer switches it back to LocalSystem (as in 1.10) so that it keeps working, and writes a warning to `logs\service-install.log`. Check the account with `Get-CimInstance Win32_Service -Filter "Name like 'FileAccessMonitor%'" | Select-Object Name, State, StartName`, find the cause in `logs\app-*.log` (or the Application event log), and run the installer again once it is fixed.

The separation limits what a flaw in the web part can do, but the web service still decides what the collector does: someone who takes over the web service account can change the monitored folders and ask the collector for folder and permission scans (file names, sizes and ACLs, not file contents), and can change or delete records. Treat the monitoring server as a system to protect: reach the web GUI from the management network only, keep it updated, and send the tamper-detection anchors off the server ([How tamper detection works](integrity.md)). The recommended layout is a monitoring server that only monitors (Linux, user `fileaccessmonitor`) with agents on the file servers.
