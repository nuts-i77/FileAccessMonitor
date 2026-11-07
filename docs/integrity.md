# How tamper detection works

English | [日本語](integrity.ja.md)

Since 1.10, FileAccessMonitor checks whether stored access records and operation-log entries have been changed after they were written. This page explains how it works, what it can and cannot detect, and what to take care of in operation.

You manage it under **Settings → Tamper detection**.

---

## 1. Overview

- Records are stored as a **chain**: each row is linked to the row before it by a keyed hash.
- Changing, deleting or inserting a record breaks the chain, and verification finds it.
- The hash uses a **key (`chain.key`)** kept in a file outside the database. Someone who only has the database file cannot rebuild the chain.
- Every day the end of the chain (the **anchor**) is written to the Windows event log / syslog and to the report e-mail. Comparing it with a copy kept off the server also finds a chain rebuilt by someone with administrator rights on the server.

There are two independent chains:

| Chain | Covers |
|---|---|
| `access` | Access records (reads, writes, deletes and so on) |
| `audit` | Operation log (setting changes, sign-ins, notifications sent and so on) |

---

## 2. How records are linked

When a new row is saved, FileAccessMonitor adds:

```
position (ChainSeq) = position of the previous row + 1
seal (ChainHash)    = HMAC-SHA256( key, seal of the previous row + content of this row )
```

```
 [row 1]         [row 2]         [row 3]         …   [row n]  ← chain end (written as the anchor)
 position 1      position 2      position 3          position n
 seal h1 ──────▶ seal h2 ──────▶ seal h3 ──────▶ … ▶ seal hn
 (= HMAC(key, start + row 1))  (= HMAC(key, h1 + row 2))
```

- **The content of a row** is the server name, time, type, denied flag, folder flag, user, path, file name, folder, client IP and machine name, the new path of a rename and the detail of a permission change (operation log: time, user, action, detail, client IP). Changing any of them by a single character breaks the seal of that row.
- The display label "set at creation" (1.10.2 and later) is not sealed.
- Positions run 1, 2, 3, … without gaps. Rows are saved one at a time in order, and a position cannot be used twice (the database enforces it too).
- The chain end (last position and seal) is stored in the database (`ChainHeads`) and also in `chain-head.json` in the data folder, which is itself protected with the key.

### Key files

| File | Contents |
|---|---|
| `chain.key` | 32 random bytes, created at the first start. Readable by SYSTEM, Administrators and the web service account `NT SERVICE\FileAccessMonitor` only (Linux: the user `fileaccessmonitor` and root) |
| `chain-head.json` | The chain end last confirmed. Used to find a database that was put back to an older state |

They are in `C:\ProgramData\FileAccessMonitor\` on Windows and `/var/lib/fileaccessmonitor/` on Linux.

---

## 3. Verification

| When | Range |
|---|---|
| Every 15 minutes | Records added since the last check (**new records only**) |
| Daily at 03:30 (server time) | The whole chain (**full check**) |
| **Verify now** | The whole chain |

Verification reads 5,000 rows at a time, so recording continues while it runs.

### What it finds

| Shown as | Meaning | Typical cause |
|---|---|---|
| Record changed | The content of a row does not match its seal | A record was edited |
| Records deleted | Positions are missing | Records in the middle were deleted |
| Newest records deleted | The chain ends before its recorded end | The newest records were deleted |
| Chain end changed | The stored chain end does not match the last row | The chain end was edited |
| Older database | The database is older than `chain-head.json` | Restored from a backup, or replaced by an older copy |
| Record added outside the program | A new row has no position | A row was inserted into the database directly |
| Checkpoint changed | A deletion or acceptance record was edited | See "Checkpoints" below |
| Key changed | `chain.key` is not the key the records were sealed with | The key file was lost or replaced |
| Duplicate position | Two rows have the same position | Direct database changes |

Each finding shows the range of positions, the row IDs and the times of the good records before and after it, so you can tell which period was affected. One edit is reported as one finding; the rows after it are not all reported as broken.

### When something is found

- A red bar appears at the top of the page (Admins only).
- If notifications are on, a high-priority e-mail / webhook notification is sent, repeated every 24 hours until it is accepted.
- `integrity.break` is written to the operation log.

---

## 4. Accepting a finding

After you have investigated and decided the cause is understood (for example, you restored a backup yourself), select **Accept** next to the finding and enter a note on what you checked.

- The chain then **starts again from its current state**; later checks start from that point.
- Accepted findings stay in the list, with who accepted them, when, and the note. `integrity.accept` is written to the operation log.
- Accepting records that you accept the state at that time. It does not restore changed records.

---

## 5. Retention and checkpoints

Deleting old records by retention (**Settings → Data Retention Policy**) removes the start of the chain. To tell this apart from tampering, a **checkpoint** is written before the deletion.

- A checkpoint holds the last position deleted, the seal at that point, the number of rows deleted and the time, protected with the key. The checkpoints form a chain of their own.
- Verification starts from the row after the latest checkpoint.
- Rows are deleted **in the order they were recorded** (by position). When an agent delivers records late, some records older than the retention period may stay a little longer, because only a leading part of the chain can be removed.
- Checkpoints are written for retention (`retention`), acceptance (`accepted`) and the start of tamper detection (`genesis`).

---

## 6. Anchors: a copy kept off the server

Someone who controls both the key and the database (administrator rights on the monitoring server) can change records and rebuild the whole chain. To find that, keep the chain end **off the server** and compare later.

An anchor looks like this:

```
FAM-ANCHOR v1 server=STORAGE chain=access seq=12345 hash=9f2c…(64 hex digits) time=2026-11-07T15:05:00Z audit-seq=678 audit-hash=1ab4…
```

| Written to | When | Notes |
|---|---|---|
| Windows event log (Application, source `FileAccessMonitor`, event ID 1100) / Linux syslog (tag `fileaccessmonitor`) | Daily at 00:05 | Always on. Useful **when the logs are forwarded to another server** |
| Scheduled report e-mail (Admin report) | With each report | When the scheduled report is on. The e-mail stays off the server |
| **Download anchor** | Manual | A JSON file with a MAC computed with the key. Store it somewhere else |
| Anchor-only notification e-mail / webhook | Daily | Off by default. Turn it on with `"Integrity": { "AnchorNotify": true }` in `settings.json` |

### Checking an anchor

Paste a stored `FAM-ANCHOR` line, or the content of a downloaded anchor file, into **Check an anchor** and select **Check**.

| Result | Meaning |
|---|---|
| matches | The records up to that point are unchanged in the current database |
| does NOT match | Records up to that point have changed (the chain may have been rebuilt) |
| is newer than this database | The database is older than when the anchor was taken (restored or replaced) |
| was deleted by retention | That position was removed by retention; it is compared with the checkpoint |

---

## 7. What it protects, and its limits

| What an attacker can do | Detected |
|---|---|
| Edit, delete or replace only the database file | **Yes** (without the key the chain cannot be rebuilt) |
| Put the database back to an old backup | **Yes** (compared with `chain-head.json`) |
| Has administrator rights on the monitoring server, or has taken over the web service account (both can read the key and change the database) | **Yes, if** anchors are kept **off the server** and checked; otherwise no |
| Delete events before they are recorded (Windows Security log, Samba log) | **Out of scope.** A gap in collection is still reported by the "recording gap" notification |

- Records saved before 1.10 are not in the chain and not protected. The page says "N records from before tamper detection started (date) are not protected." They are deleted by date when their retention period ends, as before.
- Tamper detection **finds** changes. It does not prevent or undo them; for that you need backups.
- The key and the database are on the same monitoring server, so this alone is not storage that an administrator cannot change. If you rely on it as an audit trail, send the anchors (and preferably the original event log / syslog) to **a separate store that administrators of the monitoring server cannot rewrite**: an append-only log server, a SIEM, WORM storage, or a mailbox managed by someone else. Do not keep the credentials for that store on the monitoring server.

---

## 8. Operational notes

- **Backups**: back up `chain.key` and `chain-head.json` together with `fileaccess.db`. Without `chain.key`, the earlier records cannot be verified ("Key changed"; you then accept and start again).
- **Restoring a backup**: a restored database shows "Older database". If you restored it on purpose, check and **Accept**.
- **Forwarding logs**: an anchor in the local Windows event log / syslog can be erased by an administrator of the same server. Forward the logs to a log server or SIEM, or keep the report e-mails or downloaded anchors elsewhere.
- **Event source**: the service creates the event source `FileAccessMonitor` at its first anchor. If it cannot, it writes under the source "Application" and logs a warning; then run `New-EventLog -LogName Application -Source FileAccessMonitor` once as administrator.
- **Regular checks**: checking a stored anchor with **Check an anchor**, for example once a month, also finds a chain rebuilt with administrator rights.

---

## See also

- "Tamper detection" and the data folder table in the README
- [Release notes v1.10.0](releases/v1.10.0.md)
