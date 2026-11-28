# バックアップと復元

[English](backup.md) | 日本語

1.13 から、FileAccessMonitor はデータフォルダを自分でバックアップします。毎日、コマンドから、そして更新のたびに更新前に行います。バックアップには設定・鍵・データベースが入り、各ファイルを権限ごと保存するため、鍵は引き続きサービスと管理者だけが読めます。

バックアップの作成・自動バックアップの設定・復元は、管理者（Windows）または root（Linux）がコマンドで行います。Web GUI は表示だけです。Web GUI は権限のないアカウントで動いており、ログイン情報が盗まれても鍵を別の場所へコピーされないようにするためです。

## バックアップする内容

データフォルダ（`C:\ProgramData\FileAccessMonitor`、Linux では `/var/lib/fileaccessmonitor`）の中身のうち、ログと過去のバックアップを除くすべてです。

- `fileaccess.db`: 記録、ユーザー、操作ログ。SQLite のバックアップ機能でコピーするため、サービスは止まりません。
- `settings.json`、`jwt.key`、`chain.key`、`chain-head.json`、`keys\`、証明書: 設定と鍵。`chain.key` がないと、復元した記録を改ざん検知で検証できません。
- `collector\`: コレクターの状態（秘密鍵、読み取り位置、まだ送っていない記録）。

各バックアップは、時刻と種類の名前（例: `20261123-020000-scheduled`）のフォルダです。`backup.json` に、ファイルの一覧、SHA-256、権限を記録します。データフォルダの外に置くバックアップには、置き場所の権限ではなく、データフォルダと同じ権限を付けます。

同じディスク上のバックアップは、ディスクの故障には役立ちません。毎日のバックアップは別のディスクや共有フォルダに置くか（`--to`）、別の場所にコピーしてください。同じ鍵が入っているため、データフォルダと同じように限られた人だけが読めるようにしてください。

## 毎日のバックアップ

インストーラー（毎日バックアップするタスク。既定でオン）と rpm・deb パッケージは、毎日 2:00 にバックアップし、直近の 7 個をデータフォルダの `backups` に残すように設定します。変更は `backup-schedule` で行います。

```powershell
# Windows（管理者の PowerShell）
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule                       # 今の設定を表示
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule --time 03:00 --keep 14 --to D:\Backups\FileAccessMonitor
& "C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe" backup-schedule --off                 # 止める
```

```sh
# Linux
sudo /opt/fileaccessmonitor/FileAccessMonitor backup-schedule --time 03:00 --keep 14 --to /backup/fam
```

- 指定しなかった項目は、今の値のままです。`--to ""` でデータフォルダに戻します。
- 保存先は、設定するときに実際にフォルダを作り、権限を設定できるかを確認します。
- Windows では、タスク スケジューラのタスク **FileAccessMonitor Backup**（SYSTEM で実行）です。SYSTEM は共有フォルダにコンピューターアカウント（`ドメイン\サーバー名$`）で接続するため、そのアカウントに共有フォルダの変更の権限を付けてください。
- Linux では、`/etc/systemd/system` の `fileaccessmonitor-backup.timer` と `.service`（root で実行）です。マシンが止まっていて実行できなかった分は、起動時に実行します。
- 設定はタスクやタイマーの側にあり、管理者しか変更できません。データフォルダの `backup-schedule.json` は、設定した内容を Web GUI に伝えるためだけのものです。

## Web GUI から

**設定 → バックアップ**（Admin のみ）に、毎日のバックアップの設定と、バックアップの一覧を表示します（日時にマウスを重ねると保存先を表示）。最後のバックアップが 2 日以上前の場合は警告します。上のコマンドと、各バックアップの復元・削除のコマンドを、コピーできる形で表示します。

## コマンド

管理者（Windows では管理者の PowerShell）または root（Linux）で実行します。

- `backup [--to <フォルダ>] [--keep <数>]`: 今すぐバックアップします。保存先は毎日のバックアップと同じフォルダ（または `--to`）です。`--keep` を付けると、手動のバックアップのうち古いものをその数を超えた分だけ削除します。
- `backups [--to <フォルダ>] [--delete <名前>]`: バックアップの一覧を表示します（毎日のバックアップの保存先と、データフォルダ）。`--delete` で 1 つ削除します。
- `restore <名前またはフォルダ> [--force] [--no-service]`: 次の節を参照してください。
- `backup-schedule ...`: 前の節を参照してください。

## 復元

`restore` は次の順に行います。

1. バックアップの各ファイルを SHA-256 で検証します。プログラムより新しいバージョンのデータのバックアップは、このバージョンが知らないテーブルを使っている場合があるため拒否します（`--force` で強制できます）。
2. サービスを停止します（`FileAccessMonitorCollector` と `FileAccessMonitor`。Linux では `fileaccessmonitor-collector` と `fileaccessmonitor`）。
3. 今のデータフォルダの中身を、`<時刻>-before-restore` というバックアップに移します。これを復元すると、復元を取り消せます。
4. バックアップのファイルを権限ごと戻します。バックアップにコレクターのフォルダがない場合は、今のものを残します。
5. 動いていたサービスを開始します。最初の起動で、復元したことを操作ログに記録します。

バックアップの作成後に届いた記録は、復元したデータベースには含まれません。

復元したデータベースと `chain-head.json` は対応しているため、改ざん検知はこれまでどおり検証します。バックアップより後に書かれたアンカー（イベントログや syslog）は、復元した記録より先に進んでいるため、照合すると「ahead」と表示されます。

## 更新に失敗したときに戻す

インストーラーと rpm・deb パッケージは、新しいバージョンが最初にデータを開く前にバックアップ（種類 **更新前**）を作り、直近の 3 個を残します。保存先は毎日のバックアップと同じフォルダで、届かない場合はデータフォルダです。戻すには:

1. 以前のバージョンを入れ直します（Windows はそのバージョンのインストーラー、Linux は `dnf downgrade` または `apt install fileaccessmonitor-server=<バージョン>-1`）。
2. その更新の **更新前** のバックアップを復元します: `restore <名前>`。

新しいバージョンはテーブルや列を追加している場合があり、以前のバージョンでは使えません。そのため、今のデータではなく、更新前のバックアップを復元します。
