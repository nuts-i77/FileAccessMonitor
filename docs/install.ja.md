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

Security ログには、ファイルの作成も、名前変更後の名前も含まれません。FileAccessMonitor は、監視フォルダのあるドライブの変更ジャーナル（USN ジャーナル）から、これらを読み取ります。これにより、アクセスで作られたファイルは書き込みではなく **作成（Create）** として記録し、名前変更・移動では新しいパスも表示します。ジャーナルとの突き合わせのため、記録の保存は数秒遅れます。

ジャーナルを持てるのは、**NTFS と ReFS** のドライブです。FAT32、exFAT、ネットワークのパスにはありません。ジャーナルのないドライブでは、作成は「書き込み」、名前変更は変更前のパスだけで記録します。FileAccessMonitor がジャーナルを自動で作ることはありません。作るのは、管理者が画面の［変更ジャーナルを有効にする］を押すか、下のコマンドを実行したときだけです。

**設定 → 監視フォルダ** には、フォルダごとに、そのドライブのジャーナルの有無を表示します。ジャーナルが無効なドライブがあると、画面上部の通知欄（Admin のみ）にも表示します。ジャーナルのないドライブは、管理者がそこで［変更ジャーナルを有効にする］を押して有効にできます（下のコマンドと同じ操作です。実行前に確認があり、操作ログに記録します）。同じことをするコマンドも表示します。Windows のエージェントでは、1.13.1 から表示と［変更ジャーナルを有効にする］に対応します。Web 画面から、ジャーナルを無効にしたり、サイズを変えたりはできません。

### ジャーナルの有無を確認する

ファイルサーバーの管理者の PowerShell で、監視フォルダのあるドライブごとに実行します（`D:` はドライブ文字に置き換えます）。

```powershell
fsutil usn queryjournal D:
```

- 「USN ジャーナル ID」「最大サイズ」などが表示されれば、ジャーナルは**有効**です。何もする必要はありません。
- 「エラー 1179: ボリューム変更ジャーナルは、アクティブではありません。」と表示されれば、**無効**です。

### コマンドでジャーナルを有効にする

```powershell
fsutil usn createjournal m=33554432 a=8388608 D:
```

- `m=33554432` は、ジャーナルの最大サイズ（32 MB）です。いっぱいになると Windows が古い記録から消すため、これ以上は大きくなりません。
- `a=8388608` は、Windows が一度に増やす・減らす量（8 MB）です。
- 再起動は不要です。FileAccessMonitor は、ジャーナルのないドライブを 1 分ごとに確認し、作成されたジャーナルを 1 分以内に読み始めます。読み始めると、サービスのログに `Reading the USN change journal of volume D:` と出て、**設定 → 監視フォルダ** の表示も「有効」に変わります。
- 実行するのは、ジャーナルが無効なドライブだけにしてください。すでに有効なドライブで実行すると、ジャーナルのサイズが変わります。そのサイズは、ほかのソフト（バックアップ、検索、同期など）が決めたものかもしれません。
- 無効に戻すには `fsutil usn deletejournal /d D:` を実行します。ほかのソフトがジャーナルを使っていないときだけにしてください。

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
