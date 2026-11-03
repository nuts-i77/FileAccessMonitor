using FileAccessMonitor.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json.Nodes;

namespace FileAccessMonitor.Services;

public class RetentionService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ChainInterceptor _chain;
    private readonly ILogger<RetentionService> _logger;

    public RetentionService(IServiceScopeFactory scopeFactory, ChainInterceptor chain, ILogger<RetentionService> logger)
    {
        _scopeFactory = scopeFactory;
        _chain = chain;
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
        var deleted = await CleanupAsync(cutoff, cancellationToken);

        if (deleted > 0)
            _logger.LogInformation(
                "Retention cleanup: deleted {Count} records older than {Days} days (cutoff {Cutoff:yyyy-MM-dd}).",
                deleted, days, cutoff);

        return deleted;
    }

    // Tamper detection keeps the chain verifiable: records go in chain order (a prefix), because agents upload
    // late and AccessTime is not the order of the chain. N = the seq before the first record that is recent
    // enough to keep; everything up to N is deleted and a checkpoint (linked by MAC) remembers where the chain
    // continues. Records a little older than the cutoff that come after a kept one stay until the prefix passes
    // them. Records saved before tamper detection (no ChainSeq) are deleted by time as before.
    internal async Task<int> CleanupAsync(DateTime cutoff, CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();

        var key = _chain.Key;
        if (key == null)
            return await db.AccessRecords.Where(r => r.AccessTime < cutoff).ExecuteDeleteAsync(ct);

        using var hold = await _chain.AcquireAsync(ct);   // no record is saved while the prefix is cut off
        SchemaV110Integrity.EnsureGenesis(db, key);
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        var head = await db.ChainHeads.AsNoTracking().FirstAsync(h => h.Chain == ChainHasher.Access, ct);
        var latest = await db.ChainCheckpoints.AsNoTracking().Where(c => c.Chain == ChainHasher.Access)
            .OrderByDescending(c => c.Id).FirstOrDefaultAsync(ct);
        var floor = latest?.UpToSeq ?? 0;

        // The first record in chain order that is recent enough (a date far in the future is a bogus clock and does not count)
        var future = DateTime.UtcNow.AddDays(1);
        List<long> firstKept;
        try
        {
            firstKept = await db.Database.SqlQueryRaw<long>(
                @"SELECT ""ChainSeq"" AS ""Value"" FROM ""AccessRecords"" INDEXED BY ""IX_AccessRecords_ChainSeq""
WHERE ""ChainSeq"" > {0} AND ""AccessTime"" >= {1} AND ""AccessTime"" <= {2} ORDER BY ""ChainSeq"" LIMIT 1",
                floor, cutoff, future).ToListAsync(ct);
        }
        catch (Microsoft.Data.Sqlite.SqliteException)   // the unique index is missing: verification reports it
        {
            firstKept = await db.AccessRecords.Where(r => r.ChainSeq > floor && r.AccessTime >= cutoff && r.AccessTime <= future)
                .OrderBy(r => r.ChainSeq).Select(r => r.ChainSeq!.Value).Take(1).ToListAsync(ct);
        }
        var upTo = firstKept.Count > 0 ? firstKept[0] - 1 : head.Seq;

        var deleted = 0;
        if (upTo > floor)
        {
            // The newest record that still exists up to there (a hole is already a finding of its own)
            var last = await db.AccessRecords.Where(r => r.ChainSeq > floor && r.ChainSeq <= upTo)
                .OrderByDescending(r => r.ChainSeq).Select(r => new { r.ChainSeq, r.ChainHash }).FirstOrDefaultAsync(ct);
            if (last?.ChainHash != null)
            {
                var chained = await db.AccessRecords.Where(r => r.ChainSeq != null && r.ChainSeq <= last.ChainSeq)
                    .ExecuteDeleteAsync(ct);
                if (chained > 0)
                {
                    using var hasher = new ChainHasher(key);
                    var checkpoint = new ChainCheckpoint
                    {
                        Chain = ChainHasher.Access, UpToSeq = last.ChainSeq!.Value, Hash = last.ChainHash, DeletedRows = chained,
                        CreatedAt = DateTime.UtcNow, Reason = "retention", KeyId = ChainHasher.KeyId(key),
                    };
                    checkpoint.Mac = hasher.CheckpointMac(checkpoint, latest?.Mac ?? []);
                    db.ChainCheckpoints.Add(checkpoint);   // no chained row is added, so this save takes no lock
                    await db.SaveChangesAsync(ct);
                }
                deleted += chained;
            }
        }

        deleted += await db.AccessRecords
            .Where(r => r.ChainSeq == null && r.Id <= head.LegacyMaxId && r.AccessTime < cutoff)
            .ExecuteDeleteAsync(ct);

        await tx.CommitAsync(ct);
        return deleted;
    }

    public static int GetRetentionDays() =>
        SettingsStore.Load()["RetentionDays"] is JsonValue v && v.TryGetValue<int>(out var days) ? days : 0;

    public static void SaveRetentionDays(int days) =>
        SettingsStore.Update(root => root["RetentionDays"] = days);
}
