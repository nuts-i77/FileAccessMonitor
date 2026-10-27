<#
.SYNOPSIS
    Builds locally and deploys to the remote Windows Server in one step.
    Requires WinRM (PowerShell Remoting) enabled on the server.

.PARAMETER ServerIP
    Target server IP or hostname (required).

.PARAMETER RemotePath
    Install folder on the server. Default: C:\FileAccessMonitor

.PARAMETER Credential
    PSCredential for the remote server. Prompted if omitted.

.PARAMETER TailLog
    Stream the log file after deploying (Ctrl+C to stop).

.EXAMPLE
    .\deploy-remote.ps1 -ServerIP fileserver01
    .\deploy-remote.ps1 -ServerIP 192.0.2.10 -TailLog
    .\deploy-remote.ps1 -ServerIP 192.0.2.10 -RemotePath C:\FileAccessMonitor
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIP,
    [string]$RemotePath = "C:\FileAccessMonitor",
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$TailLog
)

$ErrorActionPreference = "Stop"

# 1. Build
Write-Host "[1/4] Building..." -ForegroundColor Cyan
& "$PSScriptRoot\build.ps1"
if ($LASTEXITCODE -ne 0) { Write-Error "Build failed."; exit 1 }

# 2. Connect (add to TrustedHosts if connecting by IP without domain)
Write-Host "[2/4] Connecting to $ServerIP ..." -ForegroundColor Cyan
$current = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
if ($current -notmatch [regex]::Escape($ServerIP)) {
    $newValue = if ($current) { "$current,$ServerIP" } else { $ServerIP }
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $newValue -Force
    Write-Host "  -> Added $ServerIP to TrustedHosts." -ForegroundColor Gray
}
$sessionParams = @{ ComputerName = $ServerIP }
if ($Credential) { $sessionParams.Credential = $Credential }
$session = New-PSSession @sessionParams

# 3. Stop service, copy files, start service
Write-Host "[3/4] Deploying..." -ForegroundColor Cyan

Invoke-Command -Session $session -ScriptBlock {
    param($RemotePath)
    Stop-Service FileAccessMonitor -Force -ErrorAction SilentlyContinue
    # Wait until the process actually exits (up to 30s)
    $waited = 0
    while ($waited -lt 30) {
        $proc = Get-Process -Name FileAccessMonitor -ErrorAction SilentlyContinue
        if (-not $proc) { break }
        Start-Sleep -Seconds 1
        $waited++
    }
    # Force-kill if still running
    Get-Process -Name FileAccessMonitor -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    New-Item -ItemType Directory -Force "$RemotePath\publish" | Out-Null
} -ArgumentList $RemotePath

Copy-Item -Path "$PSScriptRoot\publish\*" `
          -Destination "$RemotePath\publish\" `
          -ToSession $session -Recurse -Force

$status = Invoke-Command -Session $session -ScriptBlock {
    param($RemotePath)
    # Remove old appsettings.json outside publish/ (legacy location that could override paths)
    $oldConfig = "$RemotePath\appsettings.json"
    if (Test-Path $oldConfig) { Remove-Item $oldConfig -Force }
    Start-Service FileAccessMonitor
    Start-Sleep -Seconds 2
    (Get-Service FileAccessMonitor).Status
} -ArgumentList $RemotePath

$color = if ($status -eq "Running") { "Green" } else { "Red" }
Write-Host "  Service status: $status" -ForegroundColor $color

# 4. Show recent log
Write-Host "[4/4] Recent log entries:" -ForegroundColor Cyan
Invoke-Command -Session $session -ScriptBlock {
    $logDir = "C:\ProgramData\FileAccessMonitor\logs"
    $latest = Get-ChildItem $logDir -Filter "app-*.log" -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latest) {
        Get-Content $latest.FullName -Tail 20
    } else {
        Write-Host "(No log file yet)"
    }
}

if ($TailLog) {
    Write-Host "`nStreaming log... (Ctrl+C to stop)" -ForegroundColor Yellow
    Invoke-Command -Session $session -ScriptBlock {
        $logDir = "C:\ProgramData\FileAccessMonitor\logs"
        $latest = Get-ChildItem $logDir -Filter "app-*.log" |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { Get-Content $latest.FullName -Wait -Tail 0 }
    }
}

Remove-PSSession $session
Write-Host "`nDeploy complete. Web GUI: http://${ServerIP}:8080" -ForegroundColor Green
