<#
.SYNOPSIS
    Called by the installer (setup.exe) to register / remove the Windows services
    and the firewall rule. Not intended to be run by hand; use install-service.ps1
    when deploying from a source checkout.

    A monitoring server / standalone install has two services:
      FileAccessMonitor           the web GUI, API and database, as the virtual account
                                  NT SERVICE\FileAccessMonitor (no password, no privileges)
      FileAccessMonitorCollector  records accesses on this server and sets up auditing, as LocalSystem;
                                  start type Automatic while local collection is on, Disabled otherwise
    An agent (agent.json in the data folder) has the one service FileAccessMonitor, as LocalSystem.
#>
param(
    [Parameter(Mandatory = $true)] [ValidateSet('Install', 'Uninstall', 'Stop')] [string]$Action,
    [switch]$Firewall,
    # Default: FileAccessMonitor.exe next to this script (set below: $PSScriptRoot is empty in parameter defaults
    # when PowerShell 5.1 runs a script with -File)
    [string]$ExePath
)

$ErrorActionPreference = 'Stop'
if (-not $ExePath) { $ExePath = Join-Path $PSScriptRoot 'FileAccessMonitor.exe' }
$ServiceName    = 'FileAccessMonitor'
$ServiceDisplay = 'File Access Monitor'
$ServiceDesc    = 'Monitors and aggregates file access on shared directories.'
$CollectorName    = 'FileAccessMonitorCollector'
$CollectorDisplay = 'File Access Monitor Collector'
$CollectorDesc    = 'Records file accesses on this server for File Access Monitor (runs with the privileges that reading the Security log needs; the web GUI service runs without).'
$WebAccount     = 'NT SERVICE\FileAccessMonitor'
$DataDir        = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'FileAccessMonitor'
$FirewallRule   = $ServiceDisplay   # same name as install-service.ps1
# Port rules made by v1.5.1 and earlier (or by hand under these names); replaced by $FirewallRule
$OldRules       = "$ServiceDisplay Web", "$ServiceDisplay Agents"
# SYSTEM and Administrators by SID, so that the names of other languages do not matter
$SystemSid      = '*S-1-5-18'
$AdminsSid      = '*S-1-5-32-544'

function Stop-One([string]$Name) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Stopped') {
        Stop-Service -Name $Name -Force
        $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}

# Both services run the same exe, which stays locked until the processes have actually exited
function Stop-MonitorService {
    Stop-One $CollectorName
    Stop-One $ServiceName
    for ($i = 0; $i -lt 30 -and (Get-Process -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Seconds 1
    }
}

function Remove-Service([string]$Name) {
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        sc.exe delete $Name | Out-Null
    }
}

# The account of a service, only when it changes (an agent stays LocalSystem). Neither a virtual account nor
# LocalSystem has a password, and sc.exe needs none for them (Win32_Service.Change refuses a virtual account).
function Set-ServiceAccount([string]$Name, [string]$Account) {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    $current = if ($svc.StartName -in 'LocalSystem', 'NT AUTHORITY\SYSTEM', '.\LocalSystem') { 'LocalSystem' } else { $svc.StartName }
    if ($current -eq $Account) { return }
    $out = sc.exe config $Name obj= $Account
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config $Name obj= $Account failed (exit code $LASTEXITCODE): $out" }
    Write-Output "Account of $Name set to $Account."
}

# Starts the service and waits until it has stayed up for a while (a web service that cannot use its certificate or
# its files stops again within seconds). False when it is not running then.
function Start-AndCheck([string]$Name, [int]$Seconds = 30) {
    try { Start-Service -Name $Name } catch { Write-Warning "Starting $Name failed: $($_.Exception.Message)" }
    Start-Sleep -Seconds $Seconds
    return ((Get-Service -Name $Name).Status -eq 'Running')
}

# Creates the service, or updates one that exists (an upgrade, or one registered earlier by
# install-service.ps1 from another folder)
function Set-MonitorService([string]$Name, [string]$Display, [string]$Description, [string]$BinPath, [string]$Account, [string]$Start) {
    if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name ImagePath -Value $BinPath
        Set-Service -Name $Name -DisplayName $Display -Description $Description
    } else {
        New-Service -Name $Name -DisplayName $Display -Description $Description `
                    -BinaryPathName $BinPath -StartupType Manual | Out-Null
    }
    Set-ServiceAccount $Name $Account
    $out = sc.exe config $Name start= $Start
    if ($LASTEXITCODE -ne 0) { throw "sc.exe config $Name start= $Start failed (exit code $LASTEXITCODE): $out" }
    # Come back after a crash
    $out = sc.exe failure $Name reset= 86400 actions= restart/60000/restart/60000/restart/60000
    if ($LASTEXITCODE -ne 0) { Write-Warning "sc.exe failure $Name failed (exit code $LASTEXITCODE): $out" }
}

# Whether this machine records accesses on itself ("LocalCollection": false in settings.json turns it off)
function Test-LocalCollection {
    $file = Join-Path $DataDir 'settings.json'
    if (-not (Test-Path $file)) { return $true }
    try {
        $settings = Get-Content -Raw -Path $file | ConvertFrom-Json
        return -not ($settings.PSObject.Properties['LocalCollection'] -and $settings.LocalCollection -eq $false)
    } catch {
        return $true
    }
}

function Invoke-Icacls {
    $out = icacls.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Warning "icacls $($args -join ' ') failed (exit code $LASTEXITCODE): $out" }
}

# The data folder holds every record, so it is not left readable by Users (as ProgramData would make it): SYSTEM,
# Administrators and, on a monitoring server, the web service account, which works in it (database, settings, logs,
# keys, certificates). The collector\ folder is the exception: SYSTEM and Administrators only, plus read on key.hash
# (set by the collector itself).
function Set-DataFolderAccess([switch]$Web) {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $grants = @("${SystemSid}:(OI)(CI)F", "${AdminsSid}:(OI)(CI)F")
    if ($Web) { $grants += "${WebAccount}:(OI)(CI)M" }
    Invoke-Icacls $DataDir /inheritance:r /grant:r @grants /C /Q
    if (-not $Web) { return }

    $collectorDir = Join-Path $DataDir 'collector'
    New-Item -ItemType Directory -Force -Path $collectorDir | Out-Null
    Invoke-Icacls $collectorDir /inheritance:r /grant:r "${SystemSid}:(OI)(CI)F" "${AdminsSid}:(OI)(CI)F" /C /Q

    # Files that carry their own protected ACL (the keys, certificates, the initial password: SYSTEM and
    # Administrators only before 1.11) do not inherit, so they get the entry themselves. Inheritance flags are for
    # folders only: a file given (OI)(CI) is refused.
    foreach ($item in Get-ChildItem -LiteralPath $DataDir -Force | Where-Object { $_.Name -ne 'collector' }) {
        if ($item.PSIsContainer) {
            Invoke-Icacls $item.FullName /grant "${WebAccount}:(OI)(CI)M" /C /Q
            Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Force | ForEach-Object { Invoke-Icacls $_.FullName /grant "${WebAccount}:M" /C /Q }
        } else {
            Invoke-Icacls $item.FullName /grant "${WebAccount}:M" /C /Q
        }
    }
}

# Certificates that earlier versions (service as LocalSystem) put in the machine store: their private keys are only
# open to SYSTEM and Administrators. The web service account is allowed to read them, so that the agent endpoint
# certificate (which agents pin by fingerprint) and the web GUI's self-signed one stay the same on an upgrade.
function Grant-CertificateKeyAccess {
    foreach ($cert in Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -in 'CN=FileAccessMonitor Agent Endpoint', 'CN=FileAccessMonitor Web GUI' }) {
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if ($null -eq $rsa) { continue }
            $keyName = if ($rsa -is [System.Security.Cryptography.RSACng]) { $rsa.Key.UniqueName } else { $rsa.CspKeyContainerInfo.UniqueKeyContainerName }
            foreach ($dir in (Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'), (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys')) {
                $keyFile = Join-Path $dir $keyName
                if (Test-Path -LiteralPath $keyFile) { icacls.exe $keyFile /grant "${WebAccount}:R" /C /Q | Out-Null }
            }
        } catch {
            Write-Warning "Could not give $WebAccount access to the key of '$($cert.Subject)': $($_.Exception.Message)"
        }
    }
}

# The service account cannot create an event source, so it is done here (the daily anchor line goes to it)
function Initialize-EventSource {
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists('FileAccessMonitor')) {
            New-EventLog -LogName Application -Source 'FileAccessMonitor'
        }
    } catch {
        Write-Warning "Could not create the event log source FileAccessMonitor: $($_.Exception.Message)"
    }
}

# The installer runs this hidden: what happened goes to logs\service-install.log ("check the logs" in its message)
try {
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'logs') | Out-Null
    Start-Transcript -Path (Join-Path $DataDir 'logs\service-install.log') -Append | Out-Null
} catch { }
trap {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output $_.ScriptStackTrace
    # An install that went wrong half way must not leave the service stopped
    if ($Action -eq 'Install') {
        try { Start-Service -Name $ServiceName -ErrorAction Stop } catch { Write-Output "Starting $ServiceName failed too: $($_.Exception.Message)" }
    }
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

switch ($Action) {
    'Stop' {
        Stop-MonitorService
    }

    'Install' {
        $binPath = "`"$ExePath`""
        $isAgent = Test-Path (Join-Path $DataDir 'agent.json')
        Stop-MonitorService

        if ($isAgent) {
            # An agent only collects and sends; it keeps LocalSystem. It has no collector service.
            Set-MonitorService $ServiceName $ServiceDisplay $ServiceDesc $binPath 'LocalSystem' 'auto'
            Remove-Service $CollectorName
            Set-DataFolderAccess
        } else {
            # The web GUI and database run without privileges. 1.10 and older ran everything as LocalSystem, so an
            # upgrade switches the account here.
            # If the account cannot be changed, the service keeps LocalSystem and still works (as in 1.10).
            Set-MonitorService $ServiceName $ServiceDisplay $ServiceDesc $binPath 'LocalSystem' 'auto'
            try {
                Set-ServiceAccount $ServiceName $WebAccount
            } catch {
                Write-Warning "The web service keeps running as LocalSystem: $($_.Exception.Message)"
            }
            sc.exe sidtype $ServiceName unrestricted | Out-Null
            Set-DataFolderAccess -Web
            Grant-CertificateKeyAccess
            Initialize-EventSource

            # Recording on this machine is the collector's job. It stays registered while local collection is off
            # (disabled), so that "local-collection on" only has to enable it.
            $collect = Test-LocalCollection
            Set-MonitorService $CollectorName $CollectorDisplay $CollectorDesc "$binPath collector" 'LocalSystem' $(if ($collect) { 'auto' } else { 'disabled' })
        }

        # One rule for the program, so the web GUI port and the agent port are both covered, also
        # after a port is changed. An upgrade keeps an earlier rule even when the task was not
        # ticked this time (silent upgrades only remember the tasks of the last install).
        # The collector listens on nothing. A firewall problem must not keep the service from starting.
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

        # The web service first: it makes the certificate the collector trusts. Should it not stay up under its own
        # account, it goes back to LocalSystem (as in 1.10), so that an upgrade never leaves it stopped.
        if ($isAgent) {
            Start-Service -Name $ServiceName
        } elseif (-not (Start-AndCheck $ServiceName)) {
            Write-Warning "$ServiceName did not stay running as $WebAccount; going back to LocalSystem. See logs\app-*.log."
            Stop-One $ServiceName
            Set-ServiceAccount $ServiceName 'LocalSystem'
            if (-not (Start-AndCheck $ServiceName)) { throw "$ServiceName does not start; see logs\app-*.log." }
        }
        if (-not $isAgent -and (Test-LocalCollection)) {
            Start-Service -Name $CollectorName
        }
    }

    'Uninstall' {
        Stop-MonitorService
        Remove-Service $CollectorName
        Remove-Service $ServiceName
        Get-NetFirewallRule -DisplayName (@($FirewallRule) + $OldRules) -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
}

try { Stop-Transcript | Out-Null } catch { }
