#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registers FileAccessMonitor.exe (from .\publish\) as a Windows Service.
    .NET runtime is NOT required on this machine (self-contained binary).
    Use -Uninstall to stop and remove the service.

.EXAMPLE
    .\install-service.ps1            # Install and start
    .\install-service.ps1 -Uninstall # Stop and remove
#>
param(
    [switch]$Uninstall
)

$ServiceName    = "FileAccessMonitor"
$ServiceDisplay = "File Access Monitor"
$ServiceDesc    = "Monitors and aggregates file access on shared directories."
$PublishDir     = Join-Path $PSScriptRoot "publish"
$ExePath        = Join-Path $PublishDir "FileAccessMonitor.exe"

if ($Uninstall) {
    Write-Host "Stopping and removing service..." -ForegroundColor Yellow
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Host "Removed: $ServiceName" -ForegroundColor Green
    } else {
        Write-Host "Service not found: $ServiceName"
    }
    return
}

# Check that the binary exists
if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found: $ExePath`nBuild on your developer PC first with .\build.ps1, then copy the publish\ folder here."
    exit 1
}

# Remove existing service if present
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "Removing existing service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Register service
Write-Host "Registering service..." -ForegroundColor Yellow
New-Service -Name $ServiceName `
            -DisplayName $ServiceDisplay `
            -Description $ServiceDesc `
            -BinaryPathName "`"$ExePath`"" `
            -StartupType Automatic | Out-Null

# Start service
Start-Service -Name $ServiceName
$svc   = Get-Service -Name $ServiceName
$color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
Write-Host "Service status: $($svc.Status)" -ForegroundColor $color

# Firewall rule
Write-Host "Adding firewall rule (TCP 8080)..."
$fwRule = Get-NetFirewallRule -DisplayName "$ServiceDisplay Web" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -DisplayName "$ServiceDisplay Web" `
        -Direction Inbound -Protocol TCP -LocalPort 8080 `
        -Action Allow -Profile Any | Out-Null
    Write-Host "  -> Firewall rule added." -ForegroundColor Green
} else {
    Write-Host "  -> Firewall rule already exists. Skipped."
}

Write-Host "`n=== Installation complete ===" -ForegroundColor Cyan
Write-Host "Web GUI: http://localhost:8080"
Write-Host "Remote:  http://<server-ip>:8080"
