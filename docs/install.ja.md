# インストールの詳細

[English](install.md) | 日本語

## ビルド（開発 PC）

```powershell
.\build.ps1
```

`publish\` フォルダに自己完結型の EXE が出力されます。

## サービスのインストール（サーバー上、管理者 PowerShell）

`publish\` と `install-service.ps1` をサーバーへコピーして実行します。

```powershell
.\install-service.ps1
```

- Windows サービス `FileAccessMonitor` と `FileAccessMonitorCollector` として登録・自動起動（[どのアカウントが何を実行するか](security.ja.md#どのアカウントが何を実行するか)を参照）
- FileAccessMonitor.exe のファイアウォール受信規則を追加（TCP 8080、エージェント用の 8443）

WinRM が使える環境では、開発 PC からビルドとデプロイを一度に行えます。

```powershell
.\deploy-remote.ps1 -ServerIP <サーバー名または IP>
```

## Windows での作成と名前変更（USN ジャーナル）

Security ログには、ファイルの作成も、名前変更後の名前も含まれません。FileAccessMonitor は、監視フォルダのあるボリュームの NTFS 変更ジャーナル（USN ジャーナル）からこれらを読み取ります。これにより、アクセスで作られたファイルは書き込みではなく **作成（Create）** として記録し、名前変更・移動では新しいパスも表示します。FileAccessMonitor はジャーナルを**作りません**。ジャーナルのないボリューム（および FAT、exFAT、ネットワークのパス）は、これまでと同じ動作（書き込み、名前変更は変更前のパスのみ）で、その旨をボリュームごとに 1 回サービスのログに出します。ジャーナルとの突き合わせのため、記録の保存はこれまでより数秒遅れます。

ボリュームの確認と、これらの記録が必要な場合のジャーナルの有効化は次のとおりです（管理者 PowerShell。システムの変更で、最大 32MB を使います）。

```powershell
fsutil usn queryjournal D:
fsutil usn createjournal m=33554432 a=8388608 D:
```

## Security ログのサイズを拡張する（推奨）

Windows の Security ログは既定で 20MB 程度しかなく、アクセスの多い環境では数時間で古いイベントが上書きされます。本ツールはリアルタイムで収集するため記録自体は残りますが、サービスの停止中に上書きされた分は記録できず、調査時に元イベントも確認できないため、拡張を推奨します。導入ウィザードの Security ログの手順か、**設定** の「サーバーごとの設定」にある **Security ログ** で、サーバーごとに設定できます（エージェントのサーバーも、監視サーバーの画面から設定できます。1.12 以降の Windows エージェントが必要）。コマンドで行う場合は次のとおりです。

```powershell
wevtutil sl Security /ms:1073741824   # 1GB
```

## ダウンロードしたファイルの検証

リリースのファイルは、このリポジトリの[リリース用ワークフロー](../.github/workflows/release.yml)が GitHub Actions 上でタグ付きのソースからビルドしています。各リリースには GitHub の[ビルド証明（artifact attestation）](https://docs.github.com/ja/actions/security-for-github-actions/using-artifact-attestations)が付いており、ファイルがこのワークフローでビルドされ、改ざんされていないことを確認できます。[GitHub CLI](https://cli.github.com/) で次のように実行してください。

```powershell
gh attestation verify FileAccessMonitor-Setup-<バージョン>.exe -R nuts-i77/FileAccessMonitor
```

GitHub CLI を使わない場合は、`Get-FileHash <ファイル>`（Linux では `sha256sum <ファイル>`）の結果をリリースページの `SHA256SUMS.txt` と照合してください。Linux では、ダウンロードしたフォルダで `sha256sum -c --ignore-missing SHA256SUMS.txt` を実行すると、まとめて照合できます（1.11.2 より前のリリースはファイルの改行が Windows 形式のため、先に `sed -i 's/\r$//' SHA256SUMS.txt` を実行してください）。

## 開発

```powershell
dotnet build FileAccessMonitor.csproj
dotnet test tests/FileAccessMonitor.Tests
dotnet test linux-agent/tests            # Linux エージェント（Windows 上でも実行できます）
```

Linux エージェントは `linux-agent/` のプロジェクトで、エージェントの通信・送信待ち・記録ルールを Windows のサービスと共有しています（ソースファイルをリンク）。`dotnet publish linux-agent/FileAccessMonitor.Agent.Linux.csproj -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true` でビルドします。監視サーバーの Linux 版はメインのプロジェクトから `dotnet publish FileAccessMonitor.csproj -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:InvariantGlobalization=true /p:PredefinedCulturesOnly=false` でビルドします（`linux-server/` のインストーラーと一緒に配布）。

インストーラーを手元で作る場合は、[Inno Setup 6](https://jrsoftware.org/isinfo.php) をインストールしてから `.\build-installer.ps1 -Version 1.0.0` を実行します。`dist\` に出力されます。

開発やデモのために、インストール済みの環境に影響を与えず別のインスタンスを動かす場合は、環境変数 `FILEACCESSMONITOR_DATA` で別のデータフォルダ（既定は `C:\ProgramData\FileAccessMonitor`）を、`$env:Kestrel__Endpoints__Http__Url = 'http://localhost:5099'` などで別のポートを指定します。

GitHub Actions（`.github/workflows/ci.yml`）で push / Pull Request ごとにビルド・テスト・発行を実行します。`v1.0.0` のようなタグを push すると、`.github/workflows/release.yml` がインストーラー、zip 版、Linux エージェントと Linux 監視サーバーの tar.gz を作成し、GitHub Releases に公開します。
