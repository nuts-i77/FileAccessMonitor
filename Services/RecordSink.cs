using FileAccessMonitor.Data;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// The monitoring server's record sink (IRecordSink is in AgentCore.cs): the local database
public class LocalRecordSink(IServiceScopeFactory scopeFactory, AlertService alerts, AuditLog audit,
    ILogger<LocalRecordSink> logger) : IRecordSink
{
    // Where the collector got to (Security log record id, or journal cursor on Linux); the key keeps its old name
    private const string PositionKey = "LastRecordId";

    public async Task<bool> SaveAsync(IReadOnlyList<AccessRecord> batch, string position, CancellationToken ct = default)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                db.AccessRecords.AddRange(batch);

                var state = await db.CollectorStates.FindAsync(PositionKey);
                if (state == null)
                    db.CollectorStates.Add(new CollectorState { Key = PositionKey, Value = position });
                else
                    state.Value = position;

                await db.SaveChangesAsync(); // one implicit transaction
                if (batch.Count > 0)
                {
                    logger.LogDebug("Recorded {Count} accesses (up to position {Position}).", batch.Count, position);
                    alerts.Observe(batch.ToArray()); // the caller reuses the list
                }
                return true;
            }
            catch (Exception ex) when (attempt < 3)
            {
                logger.LogWarning(ex, "Saving {Count} access records failed (attempt {Attempt}); retrying.", batch.Count, attempt);
                await Task.Delay(TimeSpan.FromSeconds(attempt));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Dropping {Count} access records that could not be saved.", batch.Count);
                return false;
            }
        }
    }

    public async Task<string> LoadPositionAsync()
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var state = await db.CollectorStates.FindAsync(PositionKey);
            return state?.Value ?? "";
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read the collector position; starting with live events.");
            return "";
        }
    }

    public async Task ReportGapAsync(string auditDetail, string messageKey, params object[] args)
    {
        await audit.WriteAsync(AuditLog.SystemUser, "collector.gap", auditDetail);
        _ = Task.Run(() => alerts.NotifyGapAsync(ServerConfigService.LocalName, messageKey, args));
    }
}
