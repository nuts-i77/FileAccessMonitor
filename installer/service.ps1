<#
.SYNOPSIS
    Called by the installer (setup.exe) to register / remove the Windows service
    and the firewall rule. Not intended to be run by hand; use install-service.ps1
    when deploying from a source checkout.
#>
param(
    [Parameter(Mandatory = $true)] [ValidateSet('Install', 'Uninstall', 'Stop')] [string]$Action,
    [switch]$Firewall
)

$ErrorActionPreference = 'Stop'
$ServiceName    = 'FileAccessMonitor'
$ServiceDisplay = 'File Access Monitor'
$ServiceDesc    = 'Monitors and aggregates file access on shared directories.'
$FirewallRule   = $ServiceDisplay   # same name as install-service.ps1
# Port rules made by v1.5.1 and earlier (or by hand under these names); replaced by $FirewallRule
$OldRules       = "$ServiceDisplay Web", "$ServiceDisplay Agents"
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

        # One rule for the program, so the web GUI port and the agent port are both covered, also
        # after a port is changed. An upgrade keeps an earlier rule even when the task was not
        # ticked this time (silent upgrades only remember the tasks of the last install).
        # A firewall problem must not keep the service from starting.
        try {
            $old = Get-NetFirewallRule -DisplayName $OldRules -ErrorAction SilentlyContinue
            $rule = Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
            if ($rule) {
                # the install folder may have changed
                $rule | Get-NetFirewallApplicationFilter | Set-NetFirewallApplicationFilter -Program $ExePath
            } elseif ($Firewall -or $old) {
                New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Protocol TCP `
                                    -Program $ExePath -Action Allow -Profile Any | Out-Null
            }
            if ($old) { $old | Remove-NetFirewallRule }
        } catch {
            Write-Warning "Could not update the firewall rule: $($_.Exception.Message)"
        }

        Start-Service -Name $ServiceName
    }

    'Uninstall' {
        Stop-MonitorService
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            sc.exe delete $ServiceName | Out-Null
        }
        Get-NetFirewallRule -DisplayName (@($FirewallRule) + $OldRules) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}
