# Uninstall

English | [日本語](uninstall.ja.md)

If you used the installer, uninstall **File Access Monitor** from **Settings → Apps**. The services and firewall rule are removed. Access records, settings, and keys stay in `C:\ProgramData\FileAccessMonitor\`; delete that folder if you no longer need them. To remove the audit entries (SACLs), run `C:\Program Files\FileAccessMonitor\scripts\restore-audit.ps1` before uninstalling.

If you installed from source:

```powershell
.\install-service.ps1 -Uninstall
.\restore-audit.ps1 -SharePaths "D:\Share"   # to remove the audit settings as well
```

To remove a Linux agent or a Linux monitoring server, see [Linux file servers](agents.md#linux-file-servers-samba-agent) and [Monitoring server on Linux](linux-server.md).
