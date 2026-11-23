# How it works

English | [日本語](how-it-works.ja.md)

1. Subscribes to the Windows Security event log in real time (events 4663, 4659, 4660, 4670 for permission changes, and failed 4656 for refused opens), and reads the NTFS change journal for creations and new names.
2. Finds the client IP address and machine name from logon (4624) and share access (5140) events and from the list of SMB sessions.
3. Stores records in SQLite and aggregates them through an ASP.NET Core web API.
4. Displays them in the browser with Bootstrap and Chart.js.

Agents on other Windows file servers do steps 1 and 2 and send the records to the monitoring server over HTTPS. Linux agents read Samba's audit lines from the systemd journal instead (see [Linux file servers](agents.md#linux-file-servers-samba-agent)).

## Access type classification (AccessMask)

| Type | Mask |
|---|---|
| Read | `0x1` (ReadData) / `0x80000000` (GENERIC_READ) |
| Write | `0x2` (WriteData) / `0x4` (AppendData) / `0x40000000` (GENERIC_WRITE) |
| Delete | `0x10000` (DELETE) followed by event 4660 (object deleted) for the same handle, and event 4659 |
| Rename | `0x10000` (DELETE) with no event 4660: the file was renamed or moved. The new path comes from the USN journal when available |
| Create | A write that created the file, found through the USN journal (see [Create and renames on Windows](install.md#create-and-renames-on-windows-usn-journal)); without the journal it is a Write |
| Permission | Event 4670 (permissions or owner changed); the record shows the change (owner, added and removed entries, inheritance) |
| Denied | Not a type of its own: a refused read, write or delete (event 4656 with Audit Failure) is a record of that type marked **Denied** |

Refused access is recorded for files and for folders (opening or listing a forbidden folder), merged per user, path and type within 60 seconds. Denied records are not counted as accesses in rankings, statistics, unused-file detection or the read, write and delete alerts. They can be turned off under **Settings → Recording**. On Windows a refused rename shows as a refused Delete.

On Linux (Samba), a refused open is logged by Samba as a failed `create_file` and the same for delete and rename; to find refusals the agent records a failed open when the error is "Permission denied" or "Operation not permitted", and also when it says "No such file or directory" but the path exists (Samba checks access itself and leaves an old error code behind). A failed open of a path that does not exist is not recorded. Create is recorded only for create-only opens (clients that "create or open" are recorded as Write), a rename shows its new path, and a permission change (`fset_nt_acl`) is recorded without before/after details.

Renames and moves also open the file with DELETE access, so a DELETE access is held for up to 2 seconds until event 4660 shows whether the file was actually deleted. A write or rename is then held a few more seconds while it is matched with the USN journal (see above). If it was not, and a file exists again at the same path (Office saves a document by renaming the old file away and a new file into its place), the access is recorded as a write. Renames are recorded for folders where Delete is selected; Create is recorded where Write is selected.

Saves through temporary names are recorded as one write of the document, on Windows and on Linux: a file renamed from an excluded name (such as `~WRD0001.tmp`) to a recorded one is a write of the new name, and on Linux a rename of the document to an excluded name that is followed within 5 seconds by a file renamed into its place is part of that save (otherwise it is recorded as a rename). Writes of one file by one user within 2 seconds are recorded once (a save often opens the file for writing more than once). A rename that only changes the case of a name is a rename.

Folders are recorded only when they are deleted, renamed or have their permissions changed (and, when refused, when opened), shown with a folder icon and marked in the CSV export. They are left out of the file ranking and of mass-deletion alerts, which already count the files inside. Opening a folder or adding files to it is not recorded.

## Recording rules

On the **Settings** tab, administrators can exclude file name patterns (`*` and `?` wildcards), users, and processes, and merge repeated reads: when the same user reads the same file again within the set time of the previous read (5 minutes by default), it is not recorded again. The window restarts with each read, so watching a long video with seeks counts as one read. By default `Thumbs.db`, `desktop.ini`, `~$*` (Office lock files), and `*.tmp` are excluded. The rules apply to accesses recorded after they are saved.

## Limitations

- **Operations that do not open a file are not recorded.** This includes reading only attributes or timestamps (`0x80` ReadAttributes and similar) and listing folders (a refused listing of a folder is recorded). For example, when an incremental backup tool finds a file unchanged and skips copying it, that file is not recorded.
- Events that occur while the service is stopped (for example during an upgrade or reboot) are collected when it starts again, as long as they are still in the Security log (the journal on Linux). If they are already gone, the gap is recorded in the operation log and notified.
- Each file server needs FileAccessMonitor installed (standalone, or as an agent). Servers without it, and NAS appliances, cannot be monitored.
- On Linux, only accesses through Samba (SMB) shares are recorded; NFS and changes made on the server itself are not.
- Renames and moves record the new path where it is available: on Windows from the NTFS USN journal (volumes without one, FAT, exFAT and network paths record only the old path), on Linux from Samba. A move into a monitored folder from outside it is not recorded, because the old path is not monitored; a move to another volume is a delete plus a create.
- On Windows, writing only to an alternate data stream (`file.txt:stream`) is not recorded: streams are left out because Windows adds one (`Zone.Identifier`) to every downloaded file.
- On Windows, the Security log shows only the rights actually used, so it has nothing for creating an empty file (for example **New → Text Document** in Explorer) or for emptying a file by opening it to be overwritten. Since 1.11.2 these are taken from the USN journal: a Create or Write that no logged write explains within 30 seconds is recorded with the user **(unknown)**. To record who it was, turn on **Settings → Recording → Also record who creates empty files**: every open is then audited (Handle Manipulation, success; about twice the Security log events, so enlarge the log) and the user, client IP and machine come from it. Without that setting, empty files that a service or a system account creates without writing to them are recorded as (unknown) too. Without the USN journal (FAT, exFAT, network paths) none of this is recorded.
- On Linux, Samba logs the access a client asks for when it opens a file, not what it does with it: a Write means the file was opened for writing. Changing only the timestamp or attributes through such an open is recorded as a Write, and a file opened for reading and writing is recorded as a Write only. Windows records the rights actually used.
- Create is recorded only with the USN journal on Windows, and only for create-only opens on Linux; otherwise it is a Write. Copying a file on Windows (also over an existing file, and robocopy for the folders it makes) can record one Permission change for the target, because Windows sets its security while copying; with the USN journal such a record is labelled **set at creation** and is not counted as a permission change in the scheduled report (records made before 1.10.2 are not labelled). A refused rename on Windows is recorded as a refused Delete.
- Tamper detection cannot vouch for records saved before 1.10, and cannot stop an administrator who also has `chain.key`; only anchors kept off the server show that.
- Permission reports show the POSIX view on Linux and do not read Samba NT ACLs (shares that use `acl_xattr` or `acl_tdb` get a warning). Groups are not expanded, and a scan is a snapshot as of its date.
- Ransomware-like detection uses fixed thresholds (in `settings.json`, `Alerts`) and takes no action: slow encryption below the window is missed, and a bulk move that changes many extensions can raise a false alert. Refused-access detection on Linux depends on Samba's error text and on its language (English and Japanese texts are known).
- A folder that is deleted or renamed is recognized as a folder when it is still there as the event is processed, or when accesses to files inside it were seen recently. Otherwise (for example an empty folder) it is recorded as a file.
- Times are stored in UTC. The GUI shows them, and groups them by day, in the browser's time zone.
