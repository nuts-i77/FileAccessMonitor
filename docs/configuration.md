# Configuration

English | [日本語](configuration.ja.md)

## appsettings.json (in `publish\`)

| Setting | Description | Default |
|---|---|---|
| `Kestrel.Endpoints.Http.Url` | Listen URL | `http://0.0.0.0:8080` |
| `Jwt:ExpiresHours` | How long a sign-in stays valid, in hours | `8` |
| `Jwt:Key` | JWT signing key (usually not needed; see above) | Auto-generated |
| `ExcludeSystemAccounts` | Ignore access by SYSTEM and computer accounts (`xxx$`) | `true` |
| `ExcludeProcessNames` | Process names to ignore | `System`, `svchost.exe`, `SearchIndexer.exe` |

With the installer, `appsettings.json` is in `C:\Program Files\FileAccessMonitor\` and is replaced on upgrade. Put your own changes in `appsettings.Production.json` in the same folder instead. The installer creates that file with the port you chose, and your changes to it are kept on upgrade.

## Runtime settings and data (`C:\ProgramData\FileAccessMonitor\`)

| File | Contents |
|---|---|
| `settings.json` | Monitored folders, recorded access types, reverse-DNS server, retention, notifications (edited from the GUI); whether this server records accesses on itself (`LocalCollection`); HTTPS for the web GUI (`Web:Https`, written by `web-https`) |
| `web-https.pfx` / `web-user.pfx` | The web GUI certificate (the self-signed one, or the certificate you gave with `--pfx`). Before 1.11 the self-signed one on Windows was kept in the machine certificate store; such a certificate is still used as long as it is there |
| `agent-endpoint.pfx` | The agent port certificate (self-signed; agents pin its fingerprint). A certificate that 1.10 or older made in the machine store keeps being used, so the fingerprint does not change |
| `fileaccess.db` | Access records (SQLite) |
| `logs\app-YYYYMMDD.log` | Application log of the web service (kept for 14 days) |
| `logs\service-install.log` | What the installer did to the services, accounts and folder permissions (look here when it says the service could not be registered or started) |
| `collector\` | State of the collector service, for SYSTEM and Administrators only (the web service may read `collector\key.hash`, the hash of the collector's secret): `key.secret`, `settings.json` (a copy of this server's monitored folders and recording rules), `outbox\`, `logs\collector-YYYYMMDD.log` |
| `jwt.key` | JWT signing key |
| `chain.key` | Key of the tamper-detection chains. Back it up with `fileaccess.db`; without it the old records cannot be verified |
| `chain-head.json` | Last verified end of each chain (tamper detection). Back it up with `fileaccess.db` |
| `permission-reports\` | Latest permission scan of each monitored folder (**Permissions** tab) |
| `backups\` | Backups of this folder (see [Backup and restore](backup.md)) |
| `version.txt` | The version this data was last used with (backups note it) |
| `backup-schedule.json` | What `backup-schedule` set up, for the web GUI to show (the task or timer is what runs) |

The data folder is open to SYSTEM, Administrators and the web service account only (on an agent: SYSTEM and Administrators); the installer sets this, since `ProgramData` would otherwise let every local user read it. Back it up with the built-in backup ([Backup and restore](backup.md)), which keeps each file's permissions. **Keep copies of it just as closed**: they hold every record, `chain.key` (with it the tamper-detection chain can be rebuilt) and `jwt.key` (with it anyone can make a valid sign-in, including as an Admin). Copying the folder with Explorer or `Copy-Item` gives the copy the permissions of where it lands (for example `C:\Temp`, which Users can read); copy with `robocopy <data folder> <backup folder> /E /COPYALL`, or into a folder that only Administrators can open.
