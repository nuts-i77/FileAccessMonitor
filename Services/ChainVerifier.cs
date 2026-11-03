using System.Data;
using System.Globalization;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// What one verification of one chain found and where it got to
public sealed record ChainRun(string Chain, bool Initialized, List<IntegrityBreak> Breaks, long Rows,
    long LastSeq, byte[]? LastHash, long LastId, DateTime? LastTime);

// Tamper detection: walks a chain in short pages and recomputes every link.
// One edit is reported as one finding: after a bad row the stored hash is used as the link to the next.
public static class ChainVerifier
{
    public const int PageSize = 5000;

    // Where the chain stood when it was last known outside the database (restored backups show up as older)
    public sealed record KnownHead(long Seq, byte[] Hash);

    // full: from the latest checkpoint; otherwise from where the last run got to (when that is still valid).
    // progress gets the rows done so far.
    public static async Task<ChainRun> RunAsync(AccessDbContext db, string chain, byte[] key, bool full,
        KnownHead? known, long unchainedAfterId, Action<long>? progress, CancellationToken ct)
    {
        var table = chain == ChainHasher.Access ? "AccessRecords" : "AuditLogs";
        var breaks = new List<IntegrityBreak>();
        var now = DateTime.UtcNow;
        IntegrityBreak Add(string kind, long from, long to, long? fromId = null, long? toId = null,
            DateTime? before = null, DateTime? after = null, long count = 0)
        {
            var b = new IntegrityBreak
            {
                Id = $"{chain}|{kind}|{(from != 0 ? from : fromId ?? 0)}", Chain = chain, Kind = kind, FromSeq = from, ToSeq = to,
                FromId = fromId, ToId = toId, TimeBefore = before, TimeAfter = after, DetectedAt = now,
                Count = count > 0 ? count : Math.Max(0, to - from + 1),
            };
            breaks.Add(b);
            return b;
        }

        var head = await db.ChainHeads.AsNoTracking().FirstOrDefaultAsync(h => h.Chain == chain, ct);
        var checkpoints = await db.ChainCheckpoints.AsNoTracking().Where(c => c.Chain == chain).OrderBy(c => c.Id).ToListAsync(ct);
        if (head == null && checkpoints.Count == 0)
            return new ChainRun(chain, false, breaks, 0, 0, null, 0, null);

        using var hasher = new ChainHasher(key);
        var keyId = ChainHasher.KeyId(key);

        // The checkpoints form a chain of their own (each MAC covers the one before)
        byte[] prevMac = [];
        foreach (var c in checkpoints)
        {
            if (c.KeyId == keyId && !ChainHasher.Same(hasher.CheckpointMac(c, prevMac), c.Mac))
                Add("checkpoint", c.UpToSeq, c.UpToSeq);
            prevMac = c.Mac;
        }

        var latest = checkpoints.Count > 0 ? checkpoints[^1] : null;
        if (latest != null && latest.KeyId != keyId)
        {
            Add("keyChanged", latest.UpToSeq, latest.UpToSeq);
            return new ChainRun(chain, true, breaks, 0, latest.UpToSeq, latest.Hash, 0, null);
        }
        if (head == null)
        {
            Add("headMismatch", 0, 0);
            return new ChainRun(chain, true, breaks, 0, latest?.UpToSeq ?? 0, latest?.Hash, 0, null);
        }
        if (latest == null) Add("checkpoint", 0, 0);   // the genesis was removed

        // Start: the latest checkpoint, or the verified position of the last run
        var startSeq = latest?.UpToSeq ?? 0;
        byte[]? startHash = latest?.Hash;
        if (!full && head.VerifiedHash != null && head.VerifiedSeq > startSeq && head.VerifiedSeq <= head.Seq)
        {
            startSeq = head.VerifiedSeq;
            startHash = head.VerifiedHash;
        }

        await db.Database.OpenConnectionAsync(ct);
        try
        {
            var conn = (SqliteConnection)db.Database.GetDbConnection();
            var scan = await ScanAsync(conn, chain, table, hasher, startSeq, startHash, head, progress, breaks, Add, ct);

            // Rows missing at the end, or a head that is not the last row
            if (scan.LastSeq < head.Seq)
                Add("truncatedTail", scan.LastSeq + 1, head.Seq, scan.LastId, null, scan.LastTime);
            else if (head.Seq == startSeq)
            {
                if (startHash != null && !ChainHasher.Same(startHash, head.Hash)) Add("headMismatch", head.Seq, head.Seq);
            }
            else if (scan.HeadRowHash != null && !ChainHasher.Same(scan.HeadRowHash, head.Hash))
                Add("headMismatch", head.Seq, head.Seq, scan.HeadRowId);

            // Rows saved around the chain (not by this program)
            var legacy = Math.Max(head.LegacyMaxId, full ? 0 : unchainedAfterId);
            await using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $@"SELECT COUNT(*), MIN(""Id""), MAX(""Id"") FROM ""{table}"" WHERE ""ChainSeq"" IS NULL AND ""Id"" > $id";
                cmd.Parameters.AddWithValue("$id", legacy);
                await using var r = await cmd.ExecuteReaderAsync(ct);
                if (await r.ReadAsync(ct) && r.GetInt64(0) > 0)
                    Add("unchained", 0, 0, r.GetInt64(1), r.GetInt64(2), count: r.GetInt64(0));
            }

            // The database is older than the last known state (restored backup)
            if (known != null)
                await CheckKnownAsync(conn, chain, table, known, head, latest, Add, ct);

            return new ChainRun(chain, true, breaks, scan.Rows, scan.LastSeq, scan.LastHash, scan.LastId, scan.LastTime);
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }

    private sealed record Scan(long Rows, long LastSeq, byte[]? LastHash, long LastId, DateTime? LastTime,
        byte[]? HeadRowHash, long HeadRowId);

    private delegate IntegrityBreak AddBreak(string kind, long from, long to, long? fromId = null, long? toId = null,
        DateTime? before = null, DateTime? after = null, long count = 0);

    private static async Task<Scan> ScanAsync(SqliteConnection conn, string chain, string table, ChainHasher hasher,
        long startSeq, byte[]? startHash, ChainHead head, Action<long>? progress, List<IntegrityBreak> breaks,
        AddBreak add, CancellationToken ct)
    {
        var access = chain == ChainHasher.Access;
        var columns = access
            ? @"""Id"", ""ChainSeq"", ""ChainHash"", ""AccessTime"", ""ServerName"", ""AccessType"", ""Denied"", ""IsFolder"", ""UserName"", ""FilePath"", ""FileName"", ""FolderPath"", ""ClientIp"", ""ClientMachine"", ""NewPath"", ""Detail"""
            : @"""Id"", ""ChainSeq"", ""ChainHash"", ""Time"", ""UserName"", ""Action"", ""Detail"", ""ClientIp""";

        long expect = startSeq + 1, lastSeq = startSeq, lastId = 0, rows = 0, headRowId = 0;
        byte[]? prev = startHash, headRowHash = null;
        DateTime? lastTime = null;
        IntegrityBreak? altered = null;   // the open run of altered rows

        while (true)
        {
            ct.ThrowIfCancellationRequested();
            long pageRows = 0;
            await using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = $@"SELECT {columns} FROM ""{table}"" WHERE ""ChainSeq"" > $seq ORDER BY ""ChainSeq"" LIMIT {PageSize}";
                cmd.Parameters.AddWithValue("$seq", lastSeq);
                await using var r = await cmd.ExecuteReaderAsync(ct);
                while (await r.ReadAsync(ct))
                {
                    pageRows++;
                    var id = r.GetInt64(0);
                    var seq = r.GetInt64(1);
                    var stored = r.IsDBNull(2) ? null : r.GetFieldValue<byte[]>(2);
                    var good = TryCompute(r, access, hasher, prev ?? stored ?? [], seq, out var computed, out var time);

                    if (seq > expect)
                    {
                        // Rows between expect and seq are gone; this row cannot be checked against them
                        add("missing", expect, seq - 1, lastId, id, lastTime, time);
                        altered = null;
                    }
                    else if (prev != null && (!good || stored == null || !ChainHasher.Same(computed, stored)))
                    {
                        if (altered != null && altered.ToSeq == seq - 1)
                        {
                            altered.ToSeq = seq;
                            altered.ToId = id;
                            altered.Count++;
                        }
                        else altered = add("altered", seq, seq, id, id, lastTime, null, 1);
                    }
                    else
                    {
                        if (altered != null) altered.TimeAfter = time;   // the first intact row after the run
                        altered = null;
                    }

                    prev = stored ?? computed;
                    expect = seq + 1;
                    lastSeq = seq;
                    lastId = id;
                    lastTime = time;
                    if (seq == head.Seq) { headRowHash = stored; headRowId = id; }
                }
            }
            rows += pageRows;
            progress?.Invoke(rows);
            if (pageRows < PageSize) break;
            await Task.Delay(5, ct);   // let writers in between pages
        }
        return new Scan(rows, lastSeq, prev, lastId, lastTime, headRowHash, headRowId);
    }

    // Recomputes the hash of the row under the reader; false when a field cannot be read
    private static bool TryCompute(SqliteDataReader r, bool access, ChainHasher hasher, byte[] prev, long seq,
        out byte[] hash, out DateTime? time)
    {
        hash = [];
        time = null;
        try
        {
            if (!DateTime.TryParse(r.GetString(3), CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)) return false;
            time = DateTime.SpecifyKind(t, DateTimeKind.Utc);
            hash = access
                ? hasher.AccessRow(prev, seq, r.GetString(4), t.Ticks, r.GetString(5), r.GetBoolean(6), r.GetBoolean(7),
                    r.GetString(8), r.GetString(9), r.GetString(10), r.GetString(11), Opt(r, 12), Opt(r, 13), Opt(r, 14), Opt(r, 15))
                : hasher.AuditRow(prev, seq, t.Ticks, r.GetString(4), r.GetString(5), Opt(r, 6), Opt(r, 7));
            return true;
        }
        catch (Exception ex) when (ex is InvalidCastException or FormatException or InvalidOperationException)
        {
            return false;
        }
    }

    private static string? Opt(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);

    // The state seen last outside the database must still be in the database
    private static async Task CheckKnownAsync(SqliteConnection conn, string chain, string table, KnownHead known,
        ChainHead head, ChainCheckpoint? latest, AddBreak add, CancellationToken ct)
    {
        if (head.Seq < known.Seq)
        {
            add("headRollback", head.Seq + 1, known.Seq);
            return;
        }
        byte[]? stored = null;
        if (latest != null && latest.UpToSeq == known.Seq) stored = latest.Hash;
        else if (latest == null || known.Seq > latest.UpToSeq)
        {
            await using var cmd = conn.CreateCommand();
            cmd.CommandText = $@"SELECT ""ChainHash"" FROM ""{table}"" WHERE ""ChainSeq"" = $seq";
            cmd.Parameters.AddWithValue("$seq", known.Seq);
            stored = await cmd.ExecuteScalarAsync(ct) as byte[];
            if (stored == null) return;   // the row is gone; reported as missing
        }
        if (stored != null && !ChainHasher.Same(stored, known.Hash)) add("headRollback", known.Seq, known.Seq);
    }
}
