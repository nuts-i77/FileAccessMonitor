using System.Text.Json.Nodes;
using FileAccessMonitor.Models;
using Serilog;

namespace FileAccessMonitor.Services;

// The Windows agent: the collector reads the Security log as on a standalone install and hands its
// batches to the outbox (AgentCore.cs has the parts shared with the Linux agent).

// Checks folders, sets or removes their SACL, lists files for the Unused Files tab,
// reads the permissions below a folder
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class WindowsAgentPlatform(SaclManagerService sacl, ILogger<WindowsAgentPlatform> logger) : IAgentPlatform
{
    public bool? AuditOk()
    {
        try { return SaclManagerService.IsFileSystemAuditOn(); }
        catch (Exception ex)
        {
            // Not elevated (a manual run): unknown, not a failed heartbeat
            logger.LogDebug(ex, "Could not query the audit policy.");
            return null;
        }
    }

    public JsonObject RunJob(AgentJob job, CancellationToken ct)
    {
        var path = AgentJobRunner.PathOf(job);
        if (!Directory.Exists(path)) return new JsonObject { ["exists"] = false };
        logger.LogInformation("Running {Type} for {Path} as asked by the monitoring server.", job.Type, path);

        switch (job.Type)
        {
            case "applySacl":
            {
                sacl.EnableAuditPolicy();
                var (count, errors) = sacl.ApplySacl(path);
                return AgentJobRunner.AuditResult(count, errors);
            }
            case "removeSacl":
            {
                var (count, errors) = sacl.RemoveSacl(path);
                return AgentJobRunner.AuditResult(count, errors);
            }
            case "scan":
            {
                var (files, scanned, truncated) = Controllers.UnusedFilesController.Scan(
                    path, new HashSet<string>(), new RecordingRules(RecordingSettings.Load()), ct);
                return AgentJobRunner.ScanResult(files.Select(f => (f.Path, f.Size, f.ModifiedUtc)), scanned, truncated);
            }
            case PermissionContract.JobType:
                return PermissionScanWindows.Scan(path, PermissionContract.OptionsFrom(job.Args), ct);
            default:
                return new JsonObject { ["error"] = $"Unknown job {job.Type}; update the agent." };
        }
    }
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class AgentHost
{
    // "FileAccessMonitor.exe enroll <connection string>" / "unenroll"
    public static Task<int> RunCommandAsync(string[] args) =>
        AgentCommands.RunCommandAsync(args, "FileAccessMonitor.exe",
            args[0] == "unenroll" ? "Restart the service to run standalone." : "Restart the service to start sending.");

    public static async Task RunAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSerilog();
        builder.Configuration.AddJsonFile(Path.Combine(AgentConfig.DataDir, "settings.json"), optional: true, reloadOnChange: true);
        builder.Services.AddWindowsService(options => options.ServiceName = "FileAccessMonitor");

        var config = AgentConfig.Load();
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(new AgentOutbox());
        builder.Services.AddSingleton<DnsResolverService>();
        builder.Services.AddSingleton<IRecordSink, RemoteRecordSink>();
        builder.Services.AddSingleton<SaclManagerService>();
        builder.Services.AddSingleton<IAgentPlatform, WindowsAgentPlatform>();
        builder.Services.AddHostedService<AgentSender>();
        builder.Services.AddHostedService<AgentJobRunner>();
        builder.Services.AddHostedService<EventLogCollectorService>();

        var host = builder.Build();
        host.Services.GetRequiredService<DnsResolverService>().SetDnsServer(builder.Configuration["DnsServer"]);
        Log.Information("Starting as an agent of {Server}.", config.ServerUrl);
        await host.RunAsync();
    }
}
