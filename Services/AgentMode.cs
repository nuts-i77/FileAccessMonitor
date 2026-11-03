using System.Text.Json.Nodes;
using FileAccessMonitor.Models;
using Serilog;

namespace FileAccessMonitor.Services;

// The Windows agent: the collector reads the Security log as on a standalone install and hands its
// batches to the outbox (AgentCore.cs has the parts shared with the Linux agent).

// The agent's record sink: puts batches in the outbox for AgentSender to deliver
public class RemoteRecordSink(AgentOutbox outbox, ILogger<RemoteRecordSink> logger) : IRecordSink
{
    public Task<bool> SaveAsync(IReadOnlyList<AccessRecord> batch, long lastRecordId)
    {
        try
        {
            if (batch.Count > 0 && !outbox.Add(new AgentBatch { Records = batch.Select(AgentRecord.From).ToList() }))
            {
                logger.LogError("The outbox is full ({Max} bytes); dropping {Count} records. Is the monitoring server reachable?",
                    AgentOutbox.MaxBytes, batch.Count);
                return Task.FromResult(false);
            }
            outbox.SavePosition(lastRecordId.ToString());
            return Task.FromResult(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogError(ex, "Could not write {Count} records to the outbox.", batch.Count);
            return Task.FromResult(false);
        }
    }

    public Task<long> LoadPositionAsync() => Task.FromResult(long.TryParse(outbox.Position, out var id) ? id : 0);

    public Task ReportGapAsync(string auditDetail, string messageKey, params object[] args)
    {
        outbox.Add(new AgentBatch
        {
            Gap = new AgentGap
            {
                AuditDetail = auditDetail, MessageKey = messageKey,
                Args = args.Select(a => Convert.ToString(a, System.Globalization.CultureInfo.InvariantCulture) ?? "").ToList(),
            },
        });
        return Task.CompletedTask;
    }
}

// Checks folders, sets or removes their SACL, lists files for the Unused Files tab
public class WindowsAgentPlatform(SaclManagerService sacl, ILogger<WindowsAgentPlatform> logger) : IAgentPlatform
{
    public bool? AuditOk() => SaclManagerService.IsFileSystemAuditOn();

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
            default:
                return new JsonObject { ["error"] = $"Unknown job {job.Type}; update the agent." };
        }
    }
}

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
