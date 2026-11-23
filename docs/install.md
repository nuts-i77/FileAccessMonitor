# Installation details

English | [日本語](install.ja.md)

## Build (on your development PC)

```powershell
.\build.ps1
```

A self-contained EXE is written to `publish\`.

## Install the service (on the server, in an elevated PowerShell)

Copy `publish\` and `install-service.ps1` to the server, then run:

```powershell
.\install-service.ps1
```

This does two things:

- Registers and starts the Windows services `FileAccessMonitor` and `FileAccessMonitorCollector`, with automatic startup (see [Which account runs what](security.md#which-account-runs-what))
- Adds a Windows Firewall inbound rule for FileAccessMonitor.exe (TCP 8080, and 8443 for agents)

If WinRM is available, you can build and deploy from your development PC in one step:

```powershell
.\deploy-remote.ps1 -ServerIP <server name or IP>
```

## Create and renames on Windows (USN journal)

The Security log has neither the creation of a file nor the new name after a rename. FileAccessMonitor reads them from the NTFS change journal (USN journal) of the volume that holds a monitored folder: a file created by an access is then recorded as **Create** instead of Write, and a rename or move shows the new path. FileAccessMonitor does **not** create the journal. On a volume without one (and on FAT, exFAT and network paths) everything works as before: Write, and Rename with the old path only; the service log says so once per volume. Records are saved a few seconds later than before because they are matched with the journal first.

To check a volume and, if you want these records, enable the journal (elevated PowerShell; this is a system change that uses up to 32 MB):

```powershell
fsutil usn queryjournal D:
fsutil usn createjournal m=33554432 a=8388608 D:
```

## Enlarge the Security log (recommended)

By default the Windows Security log holds only about 20 MB. On a busy server, older events are overwritten within hours. FileAccessMonitor collects events in real time, but events overwritten while the service was stopped cannot be recorded, and a larger log lets you check the original events later. The Security log step of the setup wizard, or the **Security log** card under the per-server settings on the **Settings** tab, sets it per server (for an agent's server too, from the monitoring server's GUI; that needs a Windows agent of 1.12 or later). By command:

```powershell
wevtutil sl Security /ms:1073741824   # 1 GB
```

## Verifying downloads

The release files are built by this repository's [release workflow](../.github/workflows/release.yml) on GitHub Actions from the tagged source. Each release includes a GitHub [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations), so you can check that a file was built there and has not been modified. With the [GitHub CLI](https://cli.github.com/), run:

```powershell
gh attestation verify FileAccessMonitor-Setup-<version>.exe -R nuts-i77/FileAccessMonitor
```

Without the GitHub CLI, compare the output of `Get-FileHash <file>` (on Linux, `sha256sum <file>`) with `SHA256SUMS.txt` on the release page. On Linux, `sha256sum -c --ignore-missing SHA256SUMS.txt` in the download folder checks them all (for releases before 1.11.2, whose file has Windows line ends, run `sed -i 's/\r$//' SHA256SUMS.txt` first).

## Development

```powershell
dotnet build FileAccessMonitor.csproj
dotnet test tests/FileAccessMonitor.Tests
dotnet test linux-agent/tests            # Linux agent (runs on Windows too)
```

The Linux agent is the project in `linux-agent/`; it shares the agent protocol, outbox, and recording rules with the Windows service (linked source files). Build it with `dotnet publish linux-agent/FileAccessMonitor.Agent.Linux.csproj -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true`. The monitoring server builds for Linux from the main project: `dotnet publish FileAccessMonitor.csproj -c Release -r linux-x64 --self-contained true /p:PublishSingleFile=true /p:InvariantGlobalization=true /p:PredefinedCulturesOnly=false` (the files for the `linux-server/` installer).

To build the installer locally, install [Inno Setup 6](https://jrsoftware.org/isinfo.php) and run `.\build-installer.ps1 -Version 1.0.0`. The output goes to `dist\`.

To run a second instance for development or demos without touching an installed one, set the `FILEACCESSMONITOR_DATA` environment variable to another data folder (default `C:\ProgramData\FileAccessMonitor`) and another port, e.g. `$env:Kestrel__Endpoints__Http__Url = 'http://localhost:5099'`.

GitHub Actions (`.github/workflows/ci.yml`) builds, tests, and publishes the app on every push and pull request. Pushing a tag such as `v1.0.0` runs `.github/workflows/release.yml`, which builds the installer, a portable zip, and the Linux agent's and monitoring server's tar.gz and publishes them as a GitHub Release.
