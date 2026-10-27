<#
.SYNOPSIS
    Builds FileAccessMonitor and outputs a self-contained package to .\publish\.
    Run this on a developer PC that has .NET SDK 10 installed.
    Copy the entire publish\ folder to the target server, then run install-service.ps1 there.
#>

$PublishDir = Join-Path $PSScriptRoot "publish"

Write-Host "Building FileAccessMonitor (self-contained, win-x64)..." -ForegroundColor Cyan

Push-Location $PSScriptRoot
dotnet publish -c Release -r win-x64 --self-contained true -o $PublishDir `
    /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
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
