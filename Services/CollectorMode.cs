using System.Net.Http.Json;
using Serilog;

namespace FileAccessMonitor.Services;

// "FileAccessMonitor collector": the privileged process that records accesses on this machine for the
// web service (which runs without privileges). It is a built-in agent of this server: the same collector,
// outbox, sender and job runner as an agent's, reporting to the server's own agent port over loopback.
// What makes it different from a registered agent (LocalCollector has the details): it needs no
// registration, because it proves itself with a secret that only SYSTEM / root can read (the web service
// holds the secret's hash), and its state lives in the "collector" folder of the data folder, which the
// web service cannot read. Windows: service "FileAccessMonitorCollector" (LocalSystem). Linux: systemd
// unit fileaccessmonitor-collector.service (root). It exists only while local collection is on.
public static class CollectorHost
{
    public static async Task<int> RunAsync(string[] args)
    {
        // The server's own settings (port, LocalCollection, exclusions), read only. The collector's settings
        // (monitored folders, recording rules) are copied from the web service into collector\settings.json.
        var serverSettings = Path.Combine(AppPaths.BaseDataDir, "settings.json");
        var serverConfig = new ConfigurationBuilder()
            .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true)
            .AddJsonFile(serverSettings, optional: true)
            .AddEnvironmentVariables() // as the web service reads them (Agents__Port)
            .Build();
        if (!serverConfig.GetValue(ServerConfigService.LocalCollectionKey, true))
        {
            Log.Information("Local collection is off ({File}); the collector has nothing to do. Turn it on with: FileAccessMonitor local-collection on", serverSettings);
            return 0;
        }

        var secret = LocalCollector.GetOrCreateSecret();
        var fingerprint = new FingerprintCache(() => AgentEndpoint.ReadFingerprint());
        var config = new AgentConfig
        {
            ServerUrl = $"https://127.0.0.1:{AgentEndpoint.Port(serverConfig)}",
            Key = $"{LocalCollector.AgentId}.{secret}",
            FingerprintSource = fingerprint.Get,
        };

        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSerilog();
        builder.Configuration.AddJsonFile(serverSettings, optional: true, reloadOnChange: true);
        builder.Configuration.AddJsonFile(Path.Combine(AppPaths.DataDir, "settings.json"), optional: true, reloadOnChange: true);
        builder.Services.AddWindowsService(options => options.ServiceName = "FileAccessMonitorCollector");
        builder.Services.AddSystemd();

        var outbox = new AgentOutbox();
        builder.Services.AddSingleton(config);
        builder.Services.AddSingleton(outbox);
        builder.Services.AddSingleton<DnsResolverService>();
        builder.Services.AddSingleton<IRecordSink, RemoteRecordSink>();
        if (OperatingSystem.IsWindows())
        {
            builder.Services.AddSingleton<SaclManagerService>();
            builder.Services.AddSingleton<IAgentPlatform, WindowsAgentPlatform>();
        }
        else if (OperatingSystem.IsLinux())
        {
            builder.Services.AddSingleton<IAgentPlatform, SambaPlatform>();
        }
        // Takes over the position of the collector that used to run inside the web service, before collecting starts
        builder.Services.AddHostedService(sp => new CollectorSeed(config, outbox, sp.GetRequiredService<ILogger<CollectorSeed>>()));
        builder.Services.AddHostedService<AgentSender>();
        builder.Services.AddHostedService<AgentJobRunner>();
        if (OperatingSystem.IsWindows()) builder.Services.AddHostedService<EventLogCollectorService>();
        else if (OperatingSystem.IsLinux()) builder.Services.AddHostedService<SambaAuditCollector>();

        var host = builder.Build();
        host.Services.GetRequiredService<DnsResolverService>().SetDnsServer(builder.Configuration["DnsServer"]);
        Log.Information("Starting the collector of {Server} {Version}; reporting to {Url}.", ServerConfigService.LocalName, AppInfo.Version, config.ServerUrl);
        await host.RunAsync();
        return 0;
    }
}

// The server's certificate fingerprint, read again after a minute (the web service makes the certificate
// on its first start, which may come after the collector's)
public class FingerprintCache(Func<string?> read)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(1);
    private readonly object _gate = new();
    private string? _value;
    private DateTime _readAt = DateTime.MinValue;

    public string? Get()
    {
        lock (_gate)
        {
            if (_value == null || DateTime.UtcNow - _readAt >= Lifetime)
            {
                _value = read();
                _readAt = DateTime.UtcNow;
            }
            return _value;
        }
    }
}

// Before the first start of the collector, once: when a collector inside the web service (1.10 and older)
// had recorded up to some position, continue there, so nothing between that and now is missed; and take
// the monitored folders so that collecting starts with them. Gives up after a few seconds: the collector
// then starts with live events, and the settings come with the first heartbeat as usual.
public class CollectorSeed(AgentConfig config, AgentOutbox outbox, ILogger<CollectorSeed> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var client = config.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", config.Key);
        client.Timeout = TimeSpan.FromSeconds(4);
        for (var attempt = 1; attempt <= 3 && !cancellationToken.IsCancellationRequested; attempt++)
        {
            try
            {
                await AgentSettingsSync.FetchAsync(client, logger, cancellationToken);
                if (outbox.Position.Length == 0)
                {
                    var reply = await client.GetFromJsonAsync<System.Text.Json.Nodes.JsonObject>("api/agent/config", cancellationToken);
                    if (reply?["position"]?.GetValue<string>() is { Length: > 0 } position)
                    {
                        outbox.SavePosition(position);
                        logger.LogInformation("Continuing from position {Position} of the collector that ran in the web service.", position);
                    }
                }
                return;
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or OperationCanceledException)
            {
                if (cancellationToken.IsCancellationRequested) return;
                if (attempt < 3) await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            }
        }
        logger.LogInformation("The web service did not answer yet; starting with live events. Settings follow when it does.");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
