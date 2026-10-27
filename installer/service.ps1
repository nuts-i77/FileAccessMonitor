<#
.SYNOPSIS
    Called by the installer (setup.exe) to register / remove the Windows service
    and the firewall rule. Not intended to be run by hand; use install-service.ps1
    when deploying from a source checkout.
#>
param(
    [Parameter(Mandatory = $true)] [ValidateSet('Install', 'Uninstall', 'Stop')] [string]$Action,
    [int]$Port = 8080,
    [switch]$Firewall
)

$ErrorActionPreference = 'Stop'
$ServiceName    = 'FileAccessMonitor'
$ServiceDisplay = 'File Access Monitor'
$ServiceDesc    = 'Monitors and aggregates file access on shared directories.'
$FirewallRule   = "$ServiceDisplay Web"   # same name as install-service.ps1
$ExePath        = Join-Path $PSScriptRoot 'FileAccessMonitor.exe'

function Stop-MonitorService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    # The exe stays locked until the process has actually exited
    for ($i = 0; $i -lt 30 -and (Get-Process -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Seconds 1
    }
}

switch ($Action) {
    'Stop' {
        Stop-MonitorService
    }

    'Install' {
        $binPath = "`"$ExePath`""
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            # Upgrade, or a service registered earlier by install-service.ps1 from another folder
            Stop-MonitorService
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -Name ImagePath -Value $binPath
            Set-Service -Name $ServiceName -StartupType Automatic
        } else {
            New-Service -Name $ServiceName -DisplayName $ServiceDisplay -Description $ServiceDesc `
                        -BinaryPathName $binPath -StartupType Automatic | Out-Null
        }

        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        if ($Firewall) {
            New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Protocol TCP `
                                -LocalPort $Port -Action Allow -Profile Any | Out-Null
        }

        Start-Service -Name $ServiceName
    }

    'Uninstall' {
        Stop-MonitorService
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            sc.exe delete $ServiceName | Out-Null
        }
        Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}
