#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers FileAccessMonitor.exe (from .\publish\) as Windows services:
    File Access Monitor (web GUI and database, as the virtual account NT SERVICE\FileAccessMonitor) and
    File Access Monitor Collector (records accesses on this server, as LocalSystem).
    .NET runtime is NOT required on this machine (self-contained binary).
    Use -Uninstall to stop and remove the services.

.EXAMPLE
    .\install-service.ps1            # Install and start
    .\install-service.ps1 -Uninstall # Stop and remove
#>
param(
    [switch]$Uninstall
)

$PublishDir = Join-Path $PSScriptRoot "publish"
$ExePath    = Join-Path $PublishDir "FileAccessMonitor.exe"
$Script     = Join-Path $PSScriptRoot "installer\service.ps1"

# The same script as the installer runs: accounts, folder permissions, event log source, firewall rule
if ($Uninstall) {
    Write-Host "Stopping and removing the services..." -ForegroundColor Yellow
    & $Script -Action Uninstall -ExePath $ExePath
    return
}

# Check that the binary exists
if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found: $ExePath`nBuild on your developer PC first with .\build.ps1, then copy the publish\ folder here."
    exit 1
}

Write-Host "Registering the services..." -ForegroundColor Yellow
& $Script -Action Install -Firewall -ExePath $ExePath

foreach ($name in "FileAccessMonitor", "FileAccessMonitorCollector") {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { continue }
    $color = if ($svc.Status -eq 'Running') { 'Green' } elseif ($svc.StartType -eq 'Disabled') { 'Gray' } else { 'Red' }
    Write-Host "$name : $($svc.Status) (start type: $($svc.StartType))" -ForegroundColor $color
}

Write-Host "`n=== Installation complete ===" -ForegroundColor Cyan
Write-Host "Web GUI: http://localhost:8080"
Write-Host "Remote:  http://<server-ip>:8080"
Write-Host "To use HTTPS: .\publish\FileAccessMonitor.exe web-https on, then Restart-Service FileAccessMonitor"
Write-Host "Not collecting on this server (monitoring only): .\publish\FileAccessMonitor.exe local-collection off, then run this script again"
