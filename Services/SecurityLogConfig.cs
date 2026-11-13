using System.Diagnostics.Eventing.Reader;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

// The size of a Windows file server's Security log, for the setup wizard. Windows overwrites the oldest
// events when the log is full; at the default 20 MB a busy file server wraps in hours, and a stop of the
// collector then loses records (a recording gap). The limits and the job name are usable everywhere;
// reading and setting the size (SecurityLogConfig) is a job of the collector or the agent, as it needs
// administrator rights.
public static class SecurityLogSize
{
    public const string JobType = "securityLog";
    // The first agent version that knows the job
    public static readonly Version SinceVersion = new(1, 12);
    public const long MinBytes = 20L * 1024 * 1024;
    public const long MaxBytes = 64L * 1024 * 1024 * 1024;
    public const long RecommendedBytes = 1L << 30;
    // Windows keeps the size a multiple of 64 KB
    private const long Granule = 64 * 1024;

    public static bool InRange(long bytes) => bytes >= MinBytes && bytes <= MaxBytes;

    public static long Round(long bytes) => (bytes + Granule - 1) / Granule * Granule;

    // The size a job asks for ("maxBytes"), or null for a query. The value is a parsed JSON number on the
    // agent, but may be a .NET int or long when the object was built in this process.
    public static long? Wanted(JsonObject args) => args["maxBytes"] switch
    {
        JsonValue v when v.TryGetValue<long>(out var l) => l,
        JsonValue v when v.TryGetValue<int>(out var i) => i,
        JsonValue v when v.TryGetValue<double>(out var d) => (long)d,
        _ => null,
    };
}

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public static class SecurityLogConfig
{
    // Sets the maximum size when the job asks for one, and answers with the log's state
    public static JsonObject Run(JsonObject args)
    {
        var wanted = SecurityLogSize.Wanted(args);
        if (wanted is { } w && !SecurityLogSize.InRange(w))
            throw new ArgumentOutOfRangeException(nameof(args),
                $"The Security log size must be between {SecurityLogSize.MinBytes >> 20} MB and {SecurityLogSize.MaxBytes >> 30} GB.");
        // Opening the configuration needs administrator rights (the collector and the agent run as SYSTEM)
        using var config = new EventLogConfiguration("Security");
        if (wanted is { } bytes)
        {
            config.MaximumSizeInBytes = SecurityLogSize.Round(bytes);
            config.SaveChanges();
        }
        var result = new JsonObject
        {
            ["maxBytes"] = config.MaximumSizeInBytes,
            ["mode"] = config.LogMode.ToString(),
            ["recommendedBytes"] = SecurityLogSize.RecommendedBytes,
        };
        try
        {
            using var session = new EventLogSession();
            var info = session.GetLogInformation("Security", PathType.LogName);
            result["usedBytes"] = info.FileSize;
            result["records"] = info.RecordCount;
        }
        catch (EventLogException) { /* the size is what matters */ }
        return result;
    }
}
