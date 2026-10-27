using FileAccessMonitor.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace FileAccessMonitor.Services;

public class RetentionService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RetentionService> _logger;

    private static readonly string SettingsFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "FileAccessMonitor", "settings.json");

    public RetentionService(IServiceScopeFactory scopeFactory, ILogger<RetentionService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // First run: 5 minutes after startup
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunCleanup(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            { _logger.LogError(ex, "Retention cleanup failed."); }

            await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
        }
    }

    public async Task<int> RunCleanup(CancellationToken cancellationToken = default)
    {
        var days = GetRetentionDays();
        if (days <= 0) return 0;

        var cutoff = DateTime.UtcNow.AddDays(-days);

        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        var deleted = await db.AccessRecords
            .Where(r => r.AccessTime < cutoff)
            .ExecuteDeleteAsync(cancellationToken);

        if (deleted > 0)
            _logger.LogInformation(
                "Retention cleanup: deleted {Count} records older than {Days} days (cutoff {Cutoff:yyyy-MM-dd}).",
                deleted, days, cutoff);

        return deleted;
    }

    public static int GetRetentionDays()
    {
        if (!File.Exists(SettingsFile)) return 0;
        try
        {
            var json = File.ReadAllText(SettingsFile);
            var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("RetentionDays", out var val))
                return val.GetInt32();
        }
        catch { }
        return 0;
    }

    public static void SaveRetentionDays(int days)
    {
        // Read existing MonitoredPaths to preserve them
        string[] paths = [];
        if (File.Exists(SettingsFile))
        {
            try
            {
                var existing = File.ReadAllText(SettingsFile);
                var doc = JsonDocument.Parse(existing);
                if (doc.RootElement.TryGetProperty("MonitoredPaths", out var arr))
                    paths = arr.EnumerateArray()
                               .Select(e => e.GetString() ?? "")
                               .Where(s => s.Length > 0)
                               .ToArray();
            }
            catch { }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(SettingsFile)!);
        var json = JsonSerializer.Serialize(
            new { MonitoredPaths = paths, RetentionDays = days },
            new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(SettingsFile, json);
    }
}
