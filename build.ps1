<#
.SYNOPSIS
    Builds FileAccessMonitor and outputs a self-contained package to .\publish\.
    Run this on a developer PC that has .NET SDK 10 installed.
    Copy the entire publish\ folder to the target server, then run install-service.ps1 there.
    To build the setup.exe installer instead, use build-installer.ps1.
#>
param(
    [string]$Version = "0.0.0"
)

$PublishDir = Join-Path $PSScriptRoot "publish"

Write-Host "Building FileAccessMonitor $Version (self-contained, win-x64)..." -ForegroundColor Cyan

# Start clean so files removed from the project don't linger in publish\ (and the installer)
if (Test-Path $PublishDir) { Remove-Item $PublishDir -Recurse -Force }

Push-Location $PSScriptRoot
dotnet publish FileAccessMonitor.csproj -c Release -r win-x64 --self-contained true -o $PublishDir `
    /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true /p:Version=$Version `
    /p:DebugType=None /p:IsTransformWebConfigDisabled=true
$exitCode = $LASTEXITCODE
Pop-Location

if ($exitCode -ne 0) {
    Write-Error "Build failed (exit code $exitCode)."
    exit 1
}

# Copy config alongside the exe so it can be edited on the server
$srcConfig = Join-Path $PSScriptRoot "appsettings.json"
if (Test-Path $srcConfig) {
    Copy-Item $srcConfig $PublishDir -Force
}

Write-Host "`nBuild succeeded. Output: $PublishDir" -ForegroundColor Green
Write-Host "Copy the publish\ folder to the server, then run:"
Write-Host "  .\install-service.ps1"
