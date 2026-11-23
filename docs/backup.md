# Backup and restore

English | [日本語](backup.ja.md)

Since 1.13, FileAccessMonitor backs up its data folder itself: every day, by command, and before each upgrade. A backup holds the settings, the keys and the database, each file with its permissions, so the keys stay readable by the services and administrators only.

Backups are made, scheduled and restored with commands run as an administrator (Windows) or root (Linux). The web GUI only shows them: it runs without privileges, and a stolen sign-in must not be able to copy the keys somewhere else.

## What is backed up

Everything in the data folder (`C:\ProgramData\FileAccessMonitor`, or `/var/lib/fileaccessmonitor` on Linux) except the logs and earlier backups:

- `fileaccess.db`: the records, users and operation log. It is copied with SQLite's backup API, so the services keep running.
- `settings.json`, `jwt.key`, `chain.key`, `chain-head.json`, `keys\`, the certificates: the settings and keys. Without `chain.key`, tamper detection cannot verify the restored records.
- `collector\`: the collector's state (its secret, its read position and records not sent yet).

Each backup is a folder named by its time and kind (for example `20261123-020000-scheduled`), with `backup.json` listing the files, their SHA-256 and their permissions. A backup outside the data folder gets the data folder's permissions, not those of where it is put.

A backup on the same disk does not help when the disk fails: put the daily backups on another disk or a share (`--to`), or copy them elsewhere. Keep them as private as the data folder: they hold the same keys.

## The daily backup

The installer (the task that backs up the data folder every day, on by default) and the rpm/deb packages set up a daily backup at 2:00 that keeps the last 7, in the data folder's `backups` folder. Change it with `backup-schedule`:

```powershell
# Windows, elevated PowerShell
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule                       # show it
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule --time 03:00 --keep 14 --to D:\Backups\FileAccessMonitor
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule --off                 # stop it
```

```sh
# Linux
sudo /opt/fileaccessmonitor/FileAccessMonitor backup-schedule --time 03:00 --keep 14 --to /backup/fam
```

- Options left out keep their current value; `--to ""` goes back to the data folder.
- The folder is tried when you set it: the command creates a folder in it and sets its permissions.
- Windows: the task **FileAccessMonitor Backup** in Task Scheduler, run as SYSTEM. SYSTEM reaches a share as the computer's account (`DOMAIN\SERVER$`): allow that account to modify the share folder.
- Linux: `fileaccessmonitor-backup.timer` and `.service` in `/etc/systemd/system`, run as root. A run missed while the machine was off is made when it starts.
- The schedule lives in the task or timer, which only administrators can change. `backup-schedule.json` in the data folder only tells the web GUI what was set up.

## From the web GUI

**Settings → Backup** (Admin only) shows the daily backup, warns when the last backup is more than 2 days old, and lists the backups (hover over a date to see the folder). It also shows the commands above, and for each backup the command that restores or deletes it, ready to copy.

## Commands

Run these as an administrator (Windows, elevated PowerShell) or as root (Linux).

- `backup [--to <folder>] [--keep <n>]`: makes a backup now, in the folder of the daily backup (or `--to`). `--keep` deletes the oldest manual backups beyond that number.
- `backups [--to <folder>] [--delete <name>]`: lists the backups (in the folder of the daily backup and in the data folder), or deletes one.
- `restore <name or folder> [--force] [--no-service]`: see below.
- `backup-schedule ...`: see above.

## Restoring

`restore`:

1. Checks the backup's files against their SHA-256, and refuses a backup of data from a newer version than the program (it may need tables this version does not know; `--force` restores it anyway).
2. Stops the services (`FileAccessMonitorCollector` and `FileAccessMonitor`; on Linux `fileaccessmonitor-collector` and `fileaccessmonitor`).
3. Moves what is in the data folder now into a backup of its own, `<time>-before-restore`. Restoring that one undoes the restore.
4. Puts the backup's files in place with their permissions. When the backup has no collector folder, the current one is kept.
5. Starts the services that were running. The first start writes the restore to the operation log.

Records received after the backup was made are not in the restored database.

The restored database and `chain-head.json` match, so tamper detection verifies it as before. Anchors written after the backup (in the event log or syslog) are ahead of the restored records; comparing one shows "ahead".

## Going back after a failed update

The installer and the rpm/deb packages make a backup (kind **Before update**) before the new version first opens the data, and keep the last 3. It goes to the folder of the daily backup, or to the data folder when that cannot be reached. To go back:

1. Install the earlier version again (Windows: its installer; Linux: `dnf downgrade` or `apt install fileaccessmonitor-server=<version>-1`).
2. Restore the **Before update** backup of that upgrade: `restore <name>`.

The new version may have added tables or columns, which the earlier version cannot use. That is why the backup from before the upgrade is restored, not the current data.
