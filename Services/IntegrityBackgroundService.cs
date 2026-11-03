namespace FileAccessMonitor.Services;

// Verifies the chains and writes the daily anchor. Step-0 stub; filled in by the tamper-detection work.
public class IntegrityBackgroundService : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => Task.CompletedTask;
}
