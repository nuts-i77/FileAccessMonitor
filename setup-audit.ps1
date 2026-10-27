#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enables Windows Security auditing and sets SACL on shared folders
    for FileAccessMonitor.

.PARAMETER SharePaths
    Target shared folder paths to monitor (one or more).

.EXAMPLE
    .\setup-audit.ps1 -SharePaths "D:\Share1","E:\Share2"
#>
param(
    [string[]]$SharePaths = @()
)

$ErrorActionPreference = 'Stop'

Write-Host "=== FileAccessMonitor Setup ===" -ForegroundColor Cyan

# 1. Enable Object Access audit policy
Write-Host "`n[1/3] Enabling File System audit policy..." -ForegroundColor Yellow

# Use GUID for "File System" subcategory to avoid locale-dependent name issues
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "auditpol returned exit code $LASTEXITCODE. Check permissions."
} else {
    Write-Host "  -> Audit policy enabled." -ForegroundColor Green
}

# 2. Prompt for folders if not specified
if ($SharePaths.Count -eq 0) {
    Write-Host "`n[2/3] Enter target folder paths (empty line to finish):"
    while ($true) {
        $p = Read-Host "  Folder path"
        if ([string]::IsNullOrWhiteSpace($p)) { break }
        $SharePaths += $p
    }
}

if ($SharePaths.Count -eq 0) {
    Write-Warning "No folder paths specified. Skipping SACL configuration."
} else {
    Write-Host "`n[2/3] Configuring SACL (audit entries)..." -ForegroundColor Yellow

    foreach ($path in $SharePaths) {
        if (-not (Test-Path $path)) {
            Write-Warning "Path not found, skipping: $path"
            continue
        }
        Write-Host "  Configuring: $path"

        try {
            $identity   = New-Object System.Security.Principal.NTAccount("Everyone")
            # Only content read / write / append / delete. Read/Write would also audit
            # attribute and permission reads, flooding the Security log with no benefit.
            $rights     = [System.Security.AccessControl.FileSystemRights]::ReadData `
                        -bor [System.Security.AccessControl.FileSystemRights]::WriteData `
                        -bor [System.Security.AccessControl.FileSystemRights]::AppendData `
                        -bor [System.Security.AccessControl.FileSystemRights]::Delete
            $auditType  = [System.Security.AccessControl.AuditFlags]::Success

            # Rule for the root folder itself (with inheritance to future children)
            $folderRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                $identity, $rights,
                ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                 [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                [System.Security.AccessControl.PropagationFlags]::None,
                $auditType)

            # Rule for existing files (no inheritance flags needed on files)
            $fileRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                $identity, $rights,
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::None,
                $auditType)

            # Apply to root folder
            # Replace any existing Everyone audit entry (e.g. a broader one from an older version)
            $acl = Get-Acl -Path $path -Audit
            $acl.RemoveAuditRuleAll($folderRule)
            $acl.AddAuditRule($folderRule)
            Set-Acl -Path $path -AclObject $acl
            Write-Host "    -> SACL configured on folder: $path" -ForegroundColor Green

            # Apply to all existing files and subfolders recursively
            Write-Host "    -> Propagating SACL to existing files..." -ForegroundColor Gray
            $count = 0
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $childAcl = Get-Acl -Path $_.FullName -Audit
                    $childAcl.RemoveAuditRuleAll($fileRule)
                    $childAcl.AddAuditRule($fileRule)
                    Set-Acl -Path $_.FullName -AclObject $childAcl
                    $count++
                } catch { }
            }
            Write-Host "    -> Applied to $count existing items." -ForegroundColor Green
        } catch {
            Write-Warning "    Failed to configure SACL for ${path}: $_"
        }
    }
}

# 3. Update appsettings.json
Write-Host "`n[3/3] Updating appsettings.json..." -ForegroundColor Yellow
$settingsPath = Join-Path $PSScriptRoot "appsettings.json"

if (Test-Path $settingsPath) {
    $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
    $settings.MonitoredPaths = $SharePaths
    $settings | ConvertTo-Json -Depth 10 | Out-File $settingsPath -Encoding utf8
    Write-Host "  -> MonitoredPaths updated." -ForegroundColor Green
} else {
    Write-Warning "appsettings.json not found: $settingsPath"
}

Write-Host "`n=== Setup complete ===" -ForegroundColor Cyan
Write-Host "Next: run .\install-service.ps1 to install as a Windows Service."
