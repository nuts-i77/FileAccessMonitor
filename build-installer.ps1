<#
.SYNOPSIS
    Builds publish\ (via build.ps1) and then the installer dist\FileAccessMonitor-Setup-<version>.exe.
    Requires Inno Setup 6 (https://jrsoftware.org/isinfo.php, or: winget install JRSoftware.InnoSetup).

.EXAMPLE
    .\build-installer.ps1 -Version 1.0.0
#>
param(
    [Parameter(Mandatory = $true)] [string]$Version,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$iscc = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source,
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) { throw "ISCC.exe (Inno Setup 6) not found. Install it with: winget install JRSoftware.InnoSetup" }

if (-not $SkipBuild) {
    & "$PSScriptRoot\build.ps1" -Version $Version
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $iscc "/DAppVersion=$Version" "$PSScriptRoot\installer\FileAccessMonitor.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed (exit code $LASTEXITCODE)." }

Get-ChildItem "$PSScriptRoot\dist\FileAccessMonitor-Setup-$Version.exe"
