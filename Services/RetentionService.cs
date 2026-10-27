using FileAccessMonitor.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

public class RetentionService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RetentionService> _logger;

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

    public static int GetRetentionDays() =>
        SettingsStore.Load()["RetentionDays"] is JsonValue v && v.TryGetValue<int>(out var days) ? days : 0;

    public static void SaveRetentionDays(int days) =>
        SettingsStore.Update(root => root["RetentionDays"] = days);
}
