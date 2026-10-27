#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reverts changes made by setup-audit.ps1:
    - Removes SACL (audit entries) from monitored folders
    - Disables File System audit policy
    - Clears MonitoredPaths in appsettings.json

.PARAMETER SharePaths
    Folders to remove SACL from. If omitted, read from appsettings.json.

.EXAMPLE
    .\restore-audit.ps1
    .\restore-audit.ps1 -SharePaths "D:\Share","E:\Data"
#>
param(
    [string[]]$SharePaths = @()
)

$ErrorActionPreference = 'Stop'

Write-Host "=== FileAccessMonitor Restore ===" -ForegroundColor Cyan

# Load paths from appsettings.json if not specified
if ($SharePaths.Count -eq 0) {
    $settingsPath = Join-Path $PSScriptRoot "appsettings.json"
    if (Test-Path $settingsPath) {
        $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
        $SharePaths = @($settings.MonitoredPaths)
        if ($SharePaths.Count -gt 0) {
            Write-Host "Loaded target folders from appsettings.json:"
            $SharePaths | ForEach-Object { Write-Host "  $_" }
        }
    }
}

# 1. Remove SACL
if ($SharePaths.Count -gt 0) {
    Write-Host "`n[1/3] Removing SACL (audit entries)..." -ForegroundColor Yellow

    foreach ($path in $SharePaths) {
        if (-not (Test-Path $path)) {
            Write-Warning "Path not found, skipping: $path"
            continue
        }
        Write-Host "  Processing: $path"
        try {
            $acl   = Get-Acl -Path $path -Audit
            $rules = $acl.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])
            if ($rules.Count -eq 0) {
                Write-Host "    -> No audit entries found. Skipping."
                continue
            }
            foreach ($rule in $rules) {
                $acl.RemoveAuditRule($rule) | Out-Null
            }
            Set-Acl -Path $path -AclObject $acl
            Write-Host "    -> SACL removed." -ForegroundColor Green
        } catch {
            Write-Warning "    Failed to remove SACL for ${path}: $_"
        }
    }
} else {
    Write-Host "`n[1/3] No folder paths specified. Skipping SACL removal." -ForegroundColor Yellow
}

# 2. Disable audit policy
Write-Host "`n[2/3] Disabling File System audit policy..." -ForegroundColor Yellow
try {
    auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "auditpol returned exit code $LASTEXITCODE."
    } else {
        Write-Host "  -> Audit policy disabled." -ForegroundColor Green
    }
} catch {
    Write-Warning "  Failed to disable audit policy: $_"
}

# 3. Reset appsettings.json
Write-Host "`n[3/3] Resetting MonitoredPaths in appsettings.json..." -ForegroundColor Yellow
$settingsPath = Join-Path $PSScriptRoot "appsettings.json"
if (Test-Path $settingsPath) {
    $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
    $settings.MonitoredPaths = @()
    $settings | ConvertTo-Json -Depth 10 | Out-File $settingsPath -Encoding utf8
    Write-Host "  -> MonitoredPaths cleared." -ForegroundColor Green
} else {
    Write-Warning "appsettings.json not found: $settingsPath"
}

Write-Host "`n=== Restore complete ===" -ForegroundColor Cyan
Write-Host "If the service is still running, stop it with:"
Write-Host "  Stop-Service FileAccessMonitor"
