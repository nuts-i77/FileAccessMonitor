using System.Diagnostics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FileAccessMonitor.Services;

// Jobs from the monitoring server on a Samba file server. "applySacl" / "removeSacl" turn Samba's
// audit module on or off for the shares that hold the folder (the job names come from Windows,
// where they set the folder's SACL).
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public class SambaPlatform(ILogger<SambaPlatform> logger) : IAgentPlatform
{
    private static readonly object Gate = new();

    public bool? AuditOk()
    {
        try
        {
            // Nothing to audit until folders are added on the monitoring server
            var monitored = MonitoredPathList.Parse(SettingsStore.Load()).Select(p => p.Path).ToList();
            if (monitored.Count == 0) return null;
            var config = Samba.Load();
            var shares = config.Shares();
            // Every monitored folder is in, or holds, an audited share
            return monitored.All(path => SharesFor(shares, path).Any(config.IsAudited));
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Could not read the Samba configuration.");
            return false;
        }
    }

    public JsonObject RunJob(AgentJob job, CancellationToken ct)
    {
        var path = AgentJobRunner.PathOf(job).TrimEnd('/');
        if (path.Length == 0) path = "/";
        if (!Directory.Exists(path)) return new JsonObject { ["exists"] = false };
        logger.LogInformation("Running {Type} for {Path} as asked by the monitoring server.", job.Type, path);

        switch (job.Type)
        {
            case "applySacl":
                return SetAudit(path, on: true);
            case "removeSacl":
                return SetAudit(path, on: false);
            case "scan":
            {
                var rules = new RecordingRules(RecordingSettings.Load());
                var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = 0 };
                var files = new List<(string, long, DateTime)>();
                var scanned = 0;
                foreach (var info in new DirectoryInfo(path).EnumerateFiles("*", options))
                {
                    ct.ThrowIfCancellationRequested();
                    if (++scanned > MaxScannedFiles) return AgentJobRunner.ScanResult(files, MaxScannedFiles, true);
                    if (!rules.IsExcludedFile(info.Name)) files.Add((info.FullName, info.Length, info.LastWriteTimeUtc));
                }
                return AgentJobRunner.ScanResult(files, scanned, false);
            }
            case PermissionContract.JobType:
                return PermissionScanLinux.Scan(path, PermissionContract.OptionsFrom(job.Args), ct);
            default:
                return new JsonObject { ["error"] = $"Unknown job {job.Type}; update the agent." };
        }
    }

    // Same limit as the monitoring server's own listing
    private const int MaxScannedFiles = 100_000;

    private JsonObject SetAudit(string path, bool on)
    {
        lock (Gate)
        {
            var config = Samba.Load();
            var shares = config.Shares();
            var targets = SharesFor(shares, path).ToList();
            if (targets.Count == 0)
                return AgentJobRunner.AuditResult(0, [$"{path} is not shared by Samba (no share in {Samba.ConfigFile} holds it or is inside it)."]);

            if (!on)
            {
                // Keep auditing a share that another monitored folder still needs
                var others = MonitoredPathList.Parse(SettingsStore.Load()).Select(p => p.Path.TrimEnd('/'))
                    .Where(p => p != path).ToList();
                targets = targets.Where(s => !others.Any(o => SharesFor(shares, o).Contains(s))).ToList();
            }

            var before = config.ToString();
            if (on)
            {
                // Also for shares that are audited already: a block written by an earlier version is
                // replaced by one with the current operations (refused accesses, permission changes)
                var options = new AuditOptions(RecordingSettings.Load().RecordDenied, SambaOps.Available());
                var samba414 = Samba.Is414OrLater();
                foreach (var share in targets) config.EnableAudit(share, samba414, options);
            }
            else
            {
                foreach (var share in targets.Where(config.IsAudited)) config.DisableAudit(share);
            }
            if (config.ToString() != before) Samba.Save(config, logger);
            logger.LogInformation("Samba auditing {State} for shares: {Shares}.", on ? "on" : "off", string.Join(", ", targets));
            var result = AgentJobRunner.AuditResult(targets.Count, []);
            result["kind"] = "samba"; // the monitoring server words its message for shares, not SACLs
            return result;
        }
    }

    // Shares that hold the folder, or are inside it
    internal static IEnumerable<string> SharesFor(Dictionary<string, string> shares, string folder) =>
        shares.Where(s => SambaAuditCollector.IsUnderPath(folder, s.Value) || SambaAuditCollector.IsUnderPath(s.Value.TrimEnd('/'), folder))
            .Select(s => s.Key);
}

public static class Samba
{
    // smb.conf as smbd uses it ("smbd -b" prints CONFIGFILE)
    public static string ConfigFile => _configFile ??=
        Regex.Match(Run("smbd", "-b").Output, @"CONFIGFILE:\s*(\S+)") is { Success: true } m ? m.Groups[1].Value : "/etc/samba/smb.conf";

    private static string? _configFile;

    public static SambaConfigText Load() => new(File.ReadAllText(ConfigFile));

    // Checks the new configuration with testparm, keeps a backup, writes it and tells smbd to reload.
    // Open connections keep their modules; auditing starts for new connections to the share.
    public static void Save(SambaConfigText config, ILogger logger)
    {
        var file = ConfigFile;
        var candidate = file + ".fam-new";
        File.WriteAllText(candidate, config.ToString());
        var check = Run("testparm", "-s", candidate);
        if (check.ExitCode != 0)
        {
            File.Delete(candidate);
            throw new InvalidOperationException($"testparm rejected the new configuration: {check.Error.Trim()}");
        }
        File.Copy(file, $"{file}.fam-backup-{DateTime.Now:yyyyMMddHHmmss}", overwrite: true);
        File.Move(candidate, file, overwrite: true);
        var reload = Run("smbcontrol", "smbd", "reload-config");
        if (reload.ExitCode != 0)
            logger.LogWarning("smbcontrol reload-config failed ({Error}); restart smbd to apply.", reload.Error.Trim());
    }

    public static bool Is414OrLater()
    {
        var m = Regex.Match(Run("smbd", "--version").Output, @"(\d+)\.(\d+)");
        return !m.Success || (int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value)) is var (major, minor)
            && (major > 4 || (major == 4 && minor >= 14));
    }

    // A command whose output the agent reads. It does not inherit the service's systemd notify
    // socket: only the agent itself may tell systemd it is ready.
    public static ProcessStartInfo StartInfo(string file, IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment.Remove("NOTIFY_SOCKET");
        return psi;
    }

    public static (int ExitCode, string Output, string Error) Run(string file, params string[] args)
    {
        var psi = StartInfo(file, args);
        try
        {
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEndAsync();
            var error = p.StandardError.ReadToEnd();
            p.WaitForExit();
            return (p.ExitCode, output.Result, error);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return (-1, "", $"{file}: {ex.Message}");
        }
    }
}
