using System.Runtime.CompilerServices;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace FileAccessMonitor.Services;

// Tamper detection: gives every new AccessRecord / AuditLogEntry its place in the hash chain.
// Rows saved together get one contiguous block of ChainSeq values, in the order they were added; the
// head (ChainHeads) is updated in the same save, so rows and head commit in one transaction.
// A process-wide lock keeps the blocks of concurrent saves apart: it is taken before the save starts and
// released when it succeeded, failed or was canceled (a watchdog frees it if no callback ever comes).
// Nothing is saved from inside the lock except this one save, and the save writes no AuditLogs, so the
// operation log can be written from anywhere without a deadlock.
public class ChainInterceptor : SaveChangesInterceptor
{
    private readonly TimeSpan _watchdog = TimeSpan.FromSeconds(30);
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly ConditionalWeakTable<DbContext, Hold> _holds = new();
    private readonly ILogger? _logger;
    private byte[]? _key;
    private bool _keyTried;
    private ChainHasher? _hasher;
    // The newest link of each chain as last saved; null = read it from the database again
    private volatile Dictionary<string, ChainHead>? _heads;

    public ChainInterceptor(ILogger<ChainInterceptor> logger) { _logger = logger; }

    // Tests: a given key and no logging
    internal ChainInterceptor(byte[] key, TimeSpan? watchdog = null)
    {
        _key = key;
        _keyTried = true;
        if (watchdog != null) _watchdog = watchdog.Value;
    }

    // The HMAC key; null when it cannot be read (records are then saved unchained and reported as such)
    public byte[]? Key
    {
        get
        {
            if (_keyTried) return _key;
            lock (_holds)
            {
                if (_keyTried) return _key;
                try { _key = SecretStore.GetOrCreateChainKey(); }
                catch (Exception ex) { _logger?.LogError(ex, "Tamper detection is off: the chain key cannot be read."); }
                _keyTried = true;
                return _key;
            }
        }
    }

    // Holds the chain lock, e.g. for retention (which must not run between a block of seq values and its save)
    public async Task<IDisposable> AcquireAsync(CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        var hold = new Hold(this);
        hold.Start();
        return hold;
    }

    // After something else changed the heads in the database (accepting a break): read them again on the next save
    public void ResetHeads() => _heads = null;

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        if (eventData.Context is { } ctx && HasChainable(ctx))
        {
            TakeLock(ctx, async: false, default).GetAwaiter().GetResult();
            Prepare(ctx, sync: true, default).GetAwaiter().GetResult();
        }
        return result;
    }

    public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
        InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        if (eventData.Context is { } ctx && HasChainable(ctx))
        {
            await TakeLock(ctx, async: true, cancellationToken);
            await Prepare(ctx, sync: false, cancellationToken);
        }
        return result;
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        Release(eventData.Context, failed: false);
        return result;
    }

    public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result,
        CancellationToken cancellationToken = default)
    {
        Release(eventData.Context, failed: false);
        return ValueTask.FromResult(result);
    }

    public override void SaveChangesFailed(DbContextErrorEventData eventData) => Release(eventData.Context, failed: true);

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
    {
        Release(eventData.Context, failed: true);
        return Task.CompletedTask;
    }

    public override void SaveChangesCanceled(DbContextEventData eventData) => Release(eventData.Context, failed: true);

    public override Task SaveChangesCanceledAsync(DbContextEventData eventData, CancellationToken cancellationToken = default)
    {
        Release(eventData.Context, failed: true);
        return Task.CompletedTask;
    }

    private static bool HasChainable(DbContext ctx) =>
        ctx.ChangeTracker.Entries().Any(e => e.State == EntityState.Added && e.Entity is AccessRecord or AuditLogEntry);

    private async Task<Hold> TakeLock(DbContext ctx, bool async, CancellationToken ct)
    {
        Release(ctx, failed: true);   // a context saving again after a callback went missing
        if (async) await _lock.WaitAsync(ct); else _lock.Wait(ct);
        var hold = new Hold(this);
        hold.Start();
        _holds.AddOrUpdate(ctx, hold);
        return hold;
    }

    private void Release(DbContext? ctx, bool failed)
    {
        if (ctx == null || !_holds.TryGetValue(ctx, out var hold)) return;
        _holds.Remove(ctx);
        if (failed) _heads = null;
        hold.Dispose();
    }

    // Assigns ChainSeq and ChainHash to the added rows and moves the head; the lock is given back if anything throws
    private async Task Prepare(DbContext ctx, bool sync, CancellationToken ct)
    {
        try
        {
            var key = Key;
            if (key == null) { Release(ctx, failed: false); return; }   // unchained rows; verification reports them
            var db = (AccessDbContext)ctx;
            var heads = _heads ?? LoadHeads(db, key);
            _hasher ??= new ChainHasher(key);

            var added = ctx.ChangeTracker.Entries().Where(e => e.State == EntityState.Added).Select(e => e.Entity).ToList();
            var touched = new HashSet<string>();
            foreach (var entity in added)
            {
                switch (entity)
                {
                    case AccessRecord r:
                        var a = heads[ChainHasher.Access];
                        r.ChainSeq = ++a.Seq;
                        r.ChainHash = a.Hash = _hasher.Hash(a.Hash, a.Seq, r);
                        touched.Add(ChainHasher.Access);
                        break;
                    case AuditLogEntry e:
                        var u = heads[ChainHasher.Audit];
                        e.ChainSeq = ++u.Seq;
                        e.ChainHash = u.Hash = _hasher.Hash(u.Hash, u.Seq, e);
                        touched.Add(ChainHasher.Audit);
                        break;
                }
            }

            // The head goes in the same save as the rows
            var now = DateTime.UtcNow;
            foreach (var chain in touched)
            {
                var cached = heads[chain];
                cached.UpdatedAt = now;
                var tracked = db.ChainHeads.Local.FirstOrDefault(h => h.Chain == chain)
                    ?? (sync ? db.ChainHeads.Find(chain) : await db.ChainHeads.FindAsync([chain], ct));
                if (tracked == null)
                {
                    db.ChainHeads.Add(new ChainHead
                    {
                        Chain = chain, Seq = cached.Seq, Hash = cached.Hash, UpdatedAt = now, LegacyMaxId = cached.LegacyMaxId,
                        LegacyCount = cached.LegacyCount, StartedAt = cached.StartedAt,
                    });
                    _logger?.LogWarning("The {Chain} chain head row was missing and has been written again.", chain);
                }
                else
                {
                    tracked.Seq = cached.Seq;
                    tracked.Hash = cached.Hash;
                    tracked.UpdatedAt = now;
                }
            }
            _heads = heads;
        }
        catch
        {
            Release(ctx, failed: true);
            throw;
        }
    }

    // The heads as stored; a chain without one is started now
    private Dictionary<string, ChainHead> LoadHeads(AccessDbContext db, byte[] key)
    {
        var rows = db.ChainHeads.AsNoTracking().ToList();
        if (ChainHasher.Chains.Any(c => rows.All(h => h.Chain != c)))
        {
            SchemaV110Integrity.EnsureGenesis(db, key);
            rows = db.ChainHeads.AsNoTracking().ToList();
        }
        return rows.ToDictionary(h => h.Chain);
    }

    // The lock of one save; frees itself after 30 s if no completion callback arrives
    private sealed class Hold : IDisposable
    {
        private readonly ChainInterceptor _owner;
        private Timer? _timer;
        private int _released;

        public Hold(ChainInterceptor owner) => _owner = owner;

        public void Start() => _timer = new Timer(_ =>
        {
            if (Interlocked.CompareExchange(ref _released, 1, 0) != 0) return;
            _owner._logger?.LogWarning("The chain lock was held for more than {Seconds} s without a save result; released.", _owner._watchdog.TotalSeconds);
            _owner._heads = null;
            _timer?.Dispose();
            _owner._lock.Release();
        }, null, _owner._watchdog, Timeout.InfiniteTimeSpan);

        public void Dispose()
        {
            if (Interlocked.CompareExchange(ref _released, 1, 0) != 0) return;
            _timer?.Dispose();
            _owner._lock.Release();
        }
    }
}
