# 設定

[English](configuration.md) | 日本語

## appsettings.json（`publish\` 内）

| 設定項目 | 説明 | 既定値 |
|---|---|---|
| `Kestrel.Endpoints.Http.Url` | 待ち受け URL | `http://0.0.0.0:8080` |
| `Jwt:ExpiresHours` | ログインの有効期間（時間） | `8` |
| `Jwt:Key` | JWT 署名鍵（通常は指定不要。上記参照） | 自動生成 |
| `ExcludeSystemAccounts` | SYSTEM やコンピューターアカウント（`xxx$`）のアクセスを除外 | `true` |
| `ExcludeProcessNames` | 除外するプロセス名 | `System`, `svchost.exe`, `SearchIndexer.exe` |

インストーラーで導入した場合、`appsettings.json` は `C:\Program Files\FileAccessMonitor\` にあり、更新時に上書きされます。独自の設定は同じフォルダの `appsettings.Production.json` に書いてください。このファイルはインストーラーが指定ポートで作成し、更新時も内容が保持されます。

## 実行時の設定・データ（`C:\ProgramData\FileAccessMonitor\`）

| ファイル | 内容 |
|---|---|
| `settings.json` | 監視フォルダ・記録するイベント種別・逆引き DNS サーバー・保持期間・通知設定（GUI から変更）、このサーバー自身のアクセスを記録するか（`LocalCollection`）、Web GUI の HTTPS（`Web:Https`。`web-https` が書き込み） |
| `web-https.pfx` / `web-user.pfx` | Web GUI の証明書（自己署名証明書と、`--pfx` で指定した証明書）。1.10 以前の Windows では自己署名証明書をマシンの証明書ストアに保存していました。ストアに残っている証明書は、そのまま使用されます |
| `agent-endpoint.pfx` | エージェント用ポートの証明書（自己署名。エージェントはフィンガープリントで固定します）。1.10 以前がマシンの証明書ストアに作成した証明書もそのまま使用されるため、フィンガープリントは変わりません |
| `fileaccess.db` | アクセス記録（SQLite） |
| `logs\app-YYYYMMDD.log` | Web サービスのアプリケーションログ（14 日保持） |
| `logs\service-install.log` | インストーラーがサービス・アカウント・フォルダのアクセス権に対して行った処理の記録（サービスの登録や起動に失敗したと表示された場合に確認します） |
| `collector\` | コレクターのサービスの状態。SYSTEM と Administrators のみアクセス可（Web サービスは、コレクターの秘密情報のハッシュ `collector\key.hash` だけ読めます）: `key.secret`、`settings.json`（このサーバーの監視フォルダと記録ルールの写し）、`outbox\`、`logs\collector-YYYYMMDD.log` |
| `jwt.key` | JWT 署名鍵 |
| `chain.key` | 改ざん検知の鍵。`fileaccess.db` と一緒にバックアップしてください（なければ古い記録を検証できません） |
| `chain-head.json` | 改ざん検知が最後に確認したチェーンの末尾。`fileaccess.db` と一緒にバックアップしてください |
| `permission-reports\` | 監視フォルダごとの権限スキャンの最新結果（**アクセス権** タブ） |
| `backups\` | このフォルダのバックアップ（[バックアップと復元](backup.ja.md) を参照） |
| `version.txt` | このデータを最後に使ったバージョン（バックアップに記録します） |
| `backup-schedule.json` | `backup-schedule` で設定した内容（Web GUI の表示用。実際に動くのはタスクやタイマー） |

データフォルダにアクセスできるのは、SYSTEM、Administrators、Web サービスのアカウントだけです（エージェントでは SYSTEM と Administrators）。`ProgramData` のままでは、ローカルのすべてのユーザーが読めてしまうため、インストーラーがこのように設定します。バックアップには、各ファイルの権限を保つ組み込みのバックアップ（[バックアップと復元](backup.ja.md)）を使ってください。**コピーも同じように閉じた場所に保管してください**。バックアップには、すべての記録に加え、`chain.key`（改ざん検知の鎖を作り直せる鍵）と `jwt.key`（Admin を含む任意のユーザーとしてサインインした状態を作れる鍵）が含まれます。エクスプローラーや `Copy-Item` でコピーすると、コピー先のアクセス権（たとえば Users が読める `C:\Temp`）になります。`robocopy <データフォルダ> <バックアップ先> /E /COPYALL` でコピーするか、Administrators だけが開けるフォルダにコピーしてください。
