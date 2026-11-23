# アンインストール

[English](uninstall.md) | 日本語

インストーラーで導入した場合は、**設定 → アプリ** から **File Access Monitor** をアンインストールします。サービス（コレクターを含む）とファイアウォール規則は削除されます。アクセス記録・設定・鍵は `C:\ProgramData\FileAccessMonitor\` に残るので、不要であればそのフォルダを削除してください。監査エントリ (SACL) も削除する場合は、アンインストールの前に `C:\Program Files\FileAccessMonitor\scripts\restore-audit.ps1` を実行してください。

ソースから導入した場合:

```powershell
.\install-service.ps1 -Uninstall
.\restore-audit.ps1 -SharePaths "D:\Share"   # 監査設定を元に戻す場合
```

Linux エージェントと Linux の監視サーバーの削除は、[Linux のファイルサーバー](agents.ja.md#linux-のファイルサーバーsamba-エージェント)と[Linux の監視サーバー](linux-server.ja.md)を参照してください。
