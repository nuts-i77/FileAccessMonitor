# HTTPS and reverse proxy

English | [日本語](https.ja.md)

By default FileAccessMonitor serves plain HTTP on port 8080, so sign-in passwords and JWTs cross the network unencrypted. This page shows two ways to add HTTPS:

- [Option A](#option-a-https-in-the-app-kestrel): let the app serve HTTPS itself. This is the simplest option.
- [Option B](#option-b-reverse-proxy): put the app behind a reverse proxy. Use this if you already run IIS, nginx, or Caddy.

All settings below go in `appsettings.Production.json`, in the same folder as `FileAccessMonitor.exe`. With the installer, that folder is `C:\Program Files\FileAccessMonitor\`. The file is kept on upgrade. After editing it, restart the service:

```powershell
Restart-Service FileAccessMonitor
```

> [!NOTE]
> The web GUI uses absolute paths (`/api/...`, `/login.html`), so it must be served at the root of a site, for example `https://fam.example.com/`. A sub-path such as `https://intranet.example.com/fam/` does not work.

---

## Option A: HTTPS in the app (Kestrel)

You need a certificate with a private key in the **Local Computer → Personal** certificate store, issued to the name users type in the browser, for example `fam.example.com`. The service runs as LocalSystem, so it can read the private key.

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

- To serve **HTTPS only**, delete the `Http` entry. Then remove the old firewall rule and allow the HTTPS port instead:

  ```powershell
  Remove-NetFirewallRule -DisplayName "File Access Monitor Web"
  New-NetFirewallRule -DisplayName "File Access Monitor HTTPS" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
  ```

- To use a `.pfx` file instead of the certificate store, replace the `Certificate` block:

  ```json
  "Certificate": { "Path": "C:\\ProgramData\\FileAccessMonitor\\fam.pfx", "Password": "<pfx password>" }
  ```

  Keep the `.pfx` somewhere only SYSTEM and Administrators can read. `C:\ProgramData\FileAccessMonitor\` already has that restriction for its secret files.

- For testing only, you can create a self-signed certificate. Browsers will warn until it is trusted:

  ```powershell
  New-SelfSignedCertificate -DnsName fam.example.com -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
  ```

---

## Option B: Reverse proxy

**On the same server as the app (for example, IIS):** make the app listen on loopback only, so the proxy is the only way in, and remove the firewall rule for port 8080.

```json
{
  "Kestrel": { "Endpoints": { "Http": { "Url": "http://127.0.0.1:8080" } } }
}
```

```powershell
Remove-NetFirewallRule -DisplayName "File Access Monitor Web"
```

**On a different machine from the app (for example, nginx or Caddy on Linux):** keep the default listen URL, and limit port 8080 to the proxy's IP address:

```powershell
Set-NetFirewallRule -DisplayName "File Access Monitor Web" -RemoteAddress 192.0.2.5   # the proxy's IP
```

The app sets its own security headers, including CSP, and the proxy passes them through.

The operation log records the client IP address of each request. Behind a proxy, that is the proxy's address unless you list the proxy in `appsettings.Production.json`; the app then takes the real client IP from the `X-Forwarded-For` header that the proxy sends (the nginx sample below sends it; IIS ARR and Caddy send it by default):

```json
{
  "ReverseProxy": { "KnownProxies": [ "127.0.0.1" ] }
}
```

Use `127.0.0.1` for a proxy on the same server, or the proxy's IP address otherwise. Only list proxies you control, because a listed address can claim any client IP.

### IIS (URL Rewrite + Application Request Routing)

1. Install the [URL Rewrite](https://www.iis.net/downloads/microsoft/url-rewrite) and [Application Request Routing (ARR)](https://www.iis.net/downloads/microsoft/application-request-routing) modules.
2. Turn on ARR's proxy feature:

   ```powershell
   Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/proxy' -Name 'enabled' -Value 'True'
   ```

3. Create a site, for example `FileAccessMonitor`, with an empty folder such as `C:\inetpub\fam` as its physical path. Add an HTTPS binding with your certificate.
4. Put this `web.config` in that folder:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <configuration>
     <system.webServer>
       <rewrite>
         <rules>
           <!-- Redirect HTTP to HTTPS (only needed if the site also has an HTTP binding) -->
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
        proxy_pass http://192.0.2.10:8080;   # FileAccessMonitor server
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Caddy

Caddy obtains and renews certificates automatically. For a name that is only resolvable inside your LAN, add `tls internal` to use Caddy's own local CA.

```caddy
fam.example.com {
    reverse_proxy 192.0.2.10:8080
    header Strict-Transport-Security "max-age=31536000"
}
```
