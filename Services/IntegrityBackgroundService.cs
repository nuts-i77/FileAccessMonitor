namespace FileAccessMonitor.Services;

// Verifies the chains (new records every 15 minutes, everything nightly at 03:30 local time) and writes the
// daily anchor at 00:05 local time (also after a restart that missed it).
public class IntegrityBackgroundService(IntegrityService integrity, ILogger<IntegrityBackgroundService> logger) : BackgroundService
{
    private static readonly TimeSpan IncrementalEvery = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan AnchorAt = new(0, 5, 0);
    private static readonly TimeSpan FullAt = new(3, 30, 0);

    private DateTime _lastIncremental = DateTime.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);   // let the start-up work finish first
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await TickAsync(DateTime.Now, DateTime.UtcNow, stoppingToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                { logger.LogError(ex, "Integrity check failed."); }
                await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken);
            }
        }
        catch (OperationCanceledException) { }
    }

    internal async Task TickAsync(DateTime localNow, DateTime utcNow, CancellationToken ct)
    {
        if (localNow.TimeOfDay >= AnchorAt && !await integrity.AnchorDoneTodayAsync(localNow, ct)
            && await integrity.WriteAnchorAsync(ct))
            await integrity.MarkAnchorDoneAsync(localNow, ct);

        if (localNow.TimeOfDay >= FullAt && !await integrity.FullDoneTodayAsync(localNow, ct))
        {
            if (await integrity.VerifyAsync(full: true, ct) != null)
            {
                await integrity.MarkFullDoneAsync(localNow, ct);
                _lastIncremental = utcNow;
            }
        }
        else if (utcNow - _lastIncremental >= IncrementalEvery)
        {
            if (await integrity.VerifyAsync(full: false, ct) != null) _lastIncremental = utcNow;
        }

        await integrity.UpdateHeadFileAsync(false, ct);
    }
}
