# HTTPS 化とリバースプロキシ

[English](https.md) | 日本語

FileAccessMonitor は既定でポート 8080 の HTTP で動作します。そのため、ログイン時のパスワードや JWT が暗号化されずにネットワークを流れます。HTTPS にする方法は次の 2 つです。

- [方法 A](#方法-a-アプリ自身で-https-にするkestrel): アプリ自身で HTTPS にする（いちばん手軽）
- [方法 B](#方法-b-リバースプロキシ): リバースプロキシ経由にする（IIS・nginx・Caddy などを既に使っている場合）

以下の設定は、`FileAccessMonitor.exe` と同じフォルダにある `appsettings.Production.json` に書きます。インストーラーで導入した場合は `C:\Program Files\FileAccessMonitor\` です。このファイルは更新時も保持されます。編集したらサービスを再起動してください。

```powershell
Restart-Service FileAccessMonitor
```

> [!NOTE]
> Web GUI は絶対パス（`/api/...`、`/login.html`）を使っています。そのため、`https://fam.example.com/` のようにサイトのルートで公開する必要があります。`https://intranet.example.com/fam/` のようなサブパスでは動作しません。

---

## 方法 A: アプリ自身で HTTPS にする（Kestrel）

**ローカル コンピューター → 個人** の証明書ストアに、秘密鍵付きの証明書が必要です。証明書の発行先は、利用者がブラウザーに入力する名前（例: `fam.example.com`）にしてください。サービスは LocalSystem で動くため、秘密鍵を読み取れます。

`appsettings.Production.json`:

```json
{
  "Kestrel": {
    "Endpoints": {
      "Http": { "Url": "http://0.0.0.0:8080" },
      "Https": {
        "Url": "https://0.0.0.0:8443",
        "Certificate": {
          "Subject": "fam.example.com",
          "Store": "My",
          "Location": "LocalMachine",
          "AllowInvalid": false
        }
      }
    }
  }
}
```

- **HTTPS のみにする**場合は、`Http` の行を削除します。そのうえで、HTTP 用のファイアウォール規則を HTTPS 用に置き換えます。

  ```powershell
  Remove-NetFirewallRule -DisplayName "File Access Monitor Web"
  New-NetFirewallRule -DisplayName "File Access Monitor HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
  ```

- 証明書ストアの代わりに `.pfx` ファイルを使う場合は、`Certificate` を次のように書き換えます。

  ```json
  "Certificate": { "Path": "C:\\ProgramData\\FileAccessMonitor\\fam.pfx", "Password": "<pfx のパスワード>" }
  ```

  `.pfx` は、SYSTEM と Administrators だけが読める場所に置いてください（`C:\ProgramData\FileAccessMonitor\` の機密ファイルも同じ制限にしています）。

- 動作確認だけなら、自己署名証明書でも試せます。信頼済みにするまで、ブラウザーに警告が出ます。

  ```powershell
  New-SelfSignedCertificate -DnsName fam.example.com -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
  ```

---

## 方法 B: リバースプロキシ

**アプリと同じサーバー上にプロキシを置く場合（IIS など）:** アプリはループバックだけで待ち受け、プロキシ以外から直接つながらないようにします。8080 番のファイアウォール規則も削除します。

```json
{
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://127.0.0.1:8080" } } }
}
```

```powershell
Remove-NetFirewallRule -DisplayName "File Access Monitor Web"
```

**アプリとは別のマシンにプロキシを置く場合（Linux 上の nginx・Caddy など）:** 待ち受け URL は既定のままにします。8080 番へは、プロキシの IP アドレスからだけ接続できるように制限します。

```powershell
Set-NetFirewallRule -DisplayName "File Access Monitor Web" -RemoteAddress 192.0.2.5   # プロキシの IP
```

アプリは接続元の IP アドレスやスキーム（http/https）を使っていません。そのため、プロキシで `X-Forwarded-*` ヘッダーを特別に設定する必要はありません。CSP などのセキュリティヘッダーはアプリが付け、プロキシはそのまま中継します。

### IIS（URL Rewrite + Application Request Routing）

1. [URL Rewrite](https://www.iis.net/downloads/microsoft/url-rewrite) と [Application Request Routing (ARR)](https://www.iis.net/downloads/microsoft/application-request-routing) をインストールします。
2. ARR のプロキシ機能を有効にします。

   ```powershell
   Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -Value 'True'
   ```

3. サイトを作成します（例: サイト名 `FileAccessMonitor`、物理パス `C:\inetpub\fam` の空フォルダー）。証明書を指定して HTTPS バインドを追加します。
4. そのフォルダーに次の `web.config` を置きます。

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <configuration>
     <system.webServer>
       <rewrite>
         <rules>
           <!-- HTTP を HTTPS へリダイレクト（サイトに HTTP バインドもある場合のみ必要） -->
           <rule name="Redirect to HTTPS" stopProcessing="true">
             <match url="(.*)" />
             <conditions>
               <add input="{HTTPS}" pattern="off" />
             </conditions>
             <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
           </rule>
           <rule name="FileAccessMonitor" stopProcessing="true">
             <match url="(.*)" />
             <action type="Rewrite" url="http://127.0.0.1:8080/{R:1}" />
           </rule>
         </rules>
       </rewrite>
       <httpProtocol>
         <customHeaders>
           <add name="Strict-Transport-Security" value="max-age=31536000" />
         </customHeaders>
       </httpProtocol>
     </system.webServer>
   </configuration>
   ```

### nginx

```nginx
server {
    listen 80;
    server_name fam.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    http2 on;
    server_name fam.example.com;

    ssl_certificate     /etc/ssl/certs/fam.example.com.crt;
    ssl_certificate_key /etc/ssl/private/fam.example.com.key;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://192.0.2.10:8080;   # FileAccessMonitor のサーバー
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

Caddy は証明書を自動で取得・更新します。社内 LAN の中でしか名前解決できないホスト名の場合は、`tls internal` を追加すると Caddy 自身の CA で証明書を発行します。

```caddy
fam.example.com {
    reverse_proxy 192.0.2.10:8080
    header Strict-Transport-Security "max-age=31536000"
}
```
