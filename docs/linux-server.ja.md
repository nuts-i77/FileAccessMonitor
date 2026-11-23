# Linux の監視サーバー

[English](linux-server.md) | 日本語

監視サーバー（Web GUI、データベース、通知、エージェント用ポート）は Linux でも動きます。エージェントから届いた記録だけを表示することも、動いている Linux 自身の Samba のアクセスを記録することもできます。

必要なもの: systemd が動く x86-64 の Linux（Rocky Linux 9.4 で確認。Ubuntu、Debian、RHEL、AlmaLinux も同じ手順）と、導入時の root 権限

```sh
sudo dnf install ./fileaccessmonitor-server-<バージョン>-1.x86_64.rpm   # RHEL・Rocky・Alma
sudo apt install ./fileaccessmonitor-server_<バージョン>-1_amd64.deb    # Ubuntu・Debian
```

新しく入れた場合は **監視専用** で、ユーザー `fileaccessmonitor` で動きます。動かし方の確認と変更は `fileaccessmonitor-server` コマンドで行います。

```sh
fileaccessmonitor-server                        # モード、ポート、サービスの状態を表示
sudo fileaccessmonitor-server --collect         # このマシンの Samba のアクセスも記録（コレクターのサービスが root で動きます）
sudo fileaccessmonitor-server --monitor-only    # 監視専用に戻す
sudo fileaccessmonitor-server --port 8090       # Web GUI のポート（既定は 8080）
sudo fileaccessmonitor-server --https on|off    # Web GUI の HTTPS（セキュリティの項を参照）
```

パッケージ管理を使わない場合は `FileAccessMonitor-<バージョン>-linux-x64-server.tar.gz` を展開し、`sudo sh install.sh` を実行します（オプション: `--collect`、`--monitor-only`、`--port <番号>`、`--https on|off`）。

- `/opt/fileaccessmonitor` に導入され、systemd のサービス `fileaccessmonitor` として、権限のない専用ユーザー `fileaccessmonitor` で動きます（ログ: `journalctl -u fileaccessmonitor`）。`--collect` を指定すると、systemd のサービス `fileaccessmonitor-collector` が root で動き、このマシンの Samba のアクセスを記録します（ログ: `journalctl -u fileaccessmonitor-collector`）。1.10 以前で `--collect` にしていた場合は、更新時に以前の root 用 drop-in がこのサービスに置き換わります。記録と設定は `/var/lib/fileaccessmonitor` にあり、サービスのアカウントだけが読めます。コレクターの状態は `/var/lib/fileaccessmonitor/collector` にあります（`key.hash` を除き root のみ）。改ざん検知の鍵 `chain.key` と `chain-head.json` もここにあるため、データベースと一緒にバックアップしてください
- `https://<サーバー>:8080` を開き、`admin` でログインします（新規インストールは自己署名証明書の HTTPS で、ブラウザーに警告が一度表示されます）。初期パスワードは `/var/lib/fileaccessmonitor/initial-admin-password.txt` にあります（`sudo cat` で表示）
- ファイアウォールが有効な場合は TCP 8080 と 8443 を開けてください（例: `firewall-cmd --permanent --add-port=8080/tcp --add-port=8443/tcp && firewall-cmd --reload`、`ufw allow 8080/tcp && ufw allow 8443/tcp`）。パッケージはファイアウォールを変更しません
- 更新（新しいパッケージを入れる、または `install.sh` をもう一度実行）では、モードとポートを引き継ぎます
- `--collect` の場合、このマシンはエージェントと同じようにサーバーの一覧に出ます。**設定** タブで監視フォルダを追加すると、[Linux エージェント](agents.ja.md#linux-のファイルサーバーsamba-エージェント)と同じ方法で監査を設定します。1 台のマシンには、監視サーバーとエージェントのどちらか一方だけを入れます（一方のパッケージを入れると、もう一方は置き換えられます）
- 通知の秘密情報（Webhook の URL、SMTP のパスワード）は `/var/lib/fileaccessmonitor/keys` の鍵で暗号化し、その鍵はフォルダの権限で保護します（Windows では、鍵自体もマシンの DPAPI で暗号化します）
- 削除は `sudo dnf remove fileaccessmonitor-server` または `sudo apt remove fileaccessmonitor-server` です。記録と設定は残ります（`apt purge` では削除します）。tar.gz で導入した場合は、展開したフォルダで `sudo sh install.sh --uninstall` を実行します（`--purge` を付けると記録と設定も削除します）
