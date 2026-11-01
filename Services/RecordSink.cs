using FileAccessMonitor.Data;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Where the collector hands what it found. A standalone install or the monitoring server keeps it
// in the local database; an agent will send it to the monitoring server instead.
public interface IRecordSink
{
    // Saves the records together with the Security log position they were collected up to,
    // so that neither is saved without the other. False when the batch had to be dropped.
    Task<bool> SaveAsync(IReadOnlyList<AccessRecord> batch, long lastRecordId);

    // Security log record id to resume after (0 = start with live events)
    Task<long> LoadPositionAsync();

    // Recording was interrupted (log overwritten or cleared): log it and notify
    Task ReportGapAsync(string auditDetail, string messageKey, params object[] args);
}

public class LocalRecordSink(IServiceScopeFactory scopeFactory, AlertService alerts, AuditLog audit,
    ILogger<LocalRecordSink> logger) : IRecordSink
{
    private const string LastRecordIdKey = "LastRecordId";

    public async Task<bool> SaveAsync(IReadOnlyList<AccessRecord> batch, long lastRecordId)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                db.AccessRecords.AddRange(batch);

                var state = await db.CollectorStates.FindAsync(LastRecordIdKey);
                if (state == null)
                    db.CollectorStates.Add(new CollectorState { Key = LastRecordIdKey, Value = lastRecordId.ToString() });
                else
                    state.Value = lastRecordId.ToString();

                await db.SaveChangesAsync(); // one implicit transaction
                if (batch.Count > 0)
                {
                    logger.LogDebug("Recorded {Count} accesses (up to record {RecordId}).", batch.Count, lastRecordId);
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

    public async Task<long> LoadPositionAsync()
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var state = await db.CollectorStates.FindAsync(LastRecordIdKey);
            return state != null && long.TryParse(state.Value, out var id) ? id : 0;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Could not read the collector position; starting with live events.");
            return 0;
        }
    }

    public async Task ReportGapAsync(string auditDetail, string messageKey, params object[] args)
    {
        await audit.WriteAsync(AuditLog.SystemUser, "collector.gap", auditDetail);
        _ = Task.Run(() => alerts.NotifyGapAsync(messageKey, args));
    }
}
