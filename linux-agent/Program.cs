using FileAccessMonitor.Services;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("linux")]

// fileaccessmonitor-agent enroll <connection string> | unenroll | (no arguments: run as the service)
if (args.Length > 0 && args[0] is "enroll" or "unenroll")
    return await AgentCommands.RunCommandAsync(args, "fileaccessmonitor-agent",
        "Run: systemctl restart fileaccessmonitor-agent");
if (args.Length > 0 && args[0] is "--version" or "version")
{
    Console.WriteLine(AppInfo.Version);
    return 0;
}

if (!AgentConfig.Exists)
{
    Console.Error.WriteLine($"Not registered ({AgentConfig.FilePath} is missing). Run: fileaccessmonitor-agent enroll <connection string>");
    return 1;
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddSystemd();
builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.TimestampFormat = null; });

var config = AgentConfig.Load();
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(new AgentOutbox());
builder.Services.AddSingleton<IRecordSink, RemoteRecordSink>();
builder.Services.AddSingleton<IAgentPlatform, SambaPlatform>();
builder.Services.AddHostedService<AgentSender>();
builder.Services.AddHostedService<AgentJobRunner>();
builder.Services.AddHostedService<SambaAuditCollector>();

var host = builder.Build();
host.Services.GetRequiredService<ILogger<AgentConfig>>()
    .LogInformation("Starting fileaccessmonitor-agent {Version} as an agent of {Server}.", AppInfo.Version, config.ServerUrl);
await host.RunAsync();
return 0;
