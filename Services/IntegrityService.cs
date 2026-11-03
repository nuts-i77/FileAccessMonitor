using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// What the scheduled report and the settings card show about tamper detection
public interface IIntegrityStatus
{
    Task<IntegritySummary> GetSummaryAsync(CancellationToken ct = default);
}

// State: ok | broken | notVerified | disabled. AnchorLine: "FAM-ANCHOR v1 ..." (null when not available)
public record IntegritySummary(string State, DateTime? VerifiedUpTo, DateTime? LastCheck,
    int Breaks, string? FirstBreak, long HeadSeq, string HeadHashHex, long LegacyRows, string? AnchorLine);

public record CheckpointInfo(long Id, long UpToSeq, string Reason, long DeletedRows, DateTime CreatedAt, string? Note, string HashHex);

public record ChainStatus(string Chain, long HeadSeq, string HeadHashHex, long LegacyRows, long LegacyMaxId, DateTime? StartedAt,
    DateTime? VerifiedUpTo, long VerifiedSeq, DateTime? LastCheckAt, string? LastCheckKind, long LastCheckMs,
    List<IntegrityBreak> Breaks, List<CheckpointInfo> Checkpoints);

public record IntegrityStatus(IntegritySummary Summary, List<ChainStatus> Chains, VerifyRun? Running, bool KeyAvailable, bool AnchorNotify);

// The progress and result of one verification
public class VerifyRun
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");
    public string Kind { get; init; } = "full";   // full | incremental
    public string StartedBy { get; init; } = AuditLog.SystemUser;
    public DateTime StartedAt { get; init; } = DateTime.UtcNow;

    private volatile string _state = "running";
    public string State { get => _state; set => _state = value; }   // running | done | failed | canceled

    public long RowsDone { get; set; }
    public long RowsTotal { get; set; }
    public long ElapsedMs { get; set; }
    public string? Error { get; set; }
    public List<IntegrityBreak> Breaks { get; set; } = [];
    public int NewBreaks { get; set; }
}

public record AnchorInfo(string Line, string Server, DateTime Time, string KeyId, long AccessSeq, string AccessHash,
    long AuditSeq, string AuditHash, string Mac);

public record AnchorChainCheck(string Chain, long Seq, string Result);   // match | mismatch | ahead | deleted

public record AnchorCheck(bool Ok, string? Server, DateTime? Time, bool? MacValid, List<AnchorChainCheck> Chains);

// Verifies the chains (incrementally and in full), keeps the findings, alerts on new ones, accepts them
// after an investigation, and makes the anchors (the head of each chain published outside the database).
public class IntegrityService : IIntegrityStatus
{
    private const string StateKey = "Integrity.State";
    private const string AlertedSignatureKey = "Integrity.AlertedSignature";
    private const string AlertedAtKey = "Integrity.AlertedAt";
    private const string AnchorDayKey = "Integrity.AnchorDay";
    private const string LastFullDayKey = "Integrity.LastFullDay";
    private const int MaxBreaksKept = 200;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly IServiceScopeFactory _scopes;
    private readonly ChainInterceptor _chain;
    private readonly AuditLog _audit;
    private readonly Func<string, string, string, bool, object[], Task> _notify;
    private readonly ILogger _logger;
    private readonly IntegrityOptions _options;

    private readonly SemaphoreSlim _stateGate = new(1, 1);
    private readonly SemaphoreSlim _runGate = new(1, 1);
    private readonly object _runs = new();
    private readonly Dictionary<string, VerifyRun> _history = new();
    private IntegrityState? _state;
    private VerifyRun? _current;

    public IntegrityService(IServiceScopeFactory scopes, ChainInterceptor chain, AuditLog audit, AlertService alerts,
        ILogger<IntegrityService> logger)
        : this(scopes, chain, audit, (type, title, body, high, args) => alerts.NotifyAsync(type, title, body, high, args), logger, new())
    {
    }

    internal IntegrityService(IServiceScopeFactory scopes, ChainInterceptor chain, AuditLog audit,
        Func<string, string, string, bool, object[], Task> notify, ILogger logger, IntegrityOptions options)
    {
        _scopes = scopes;
        _chain = chain;
        _audit = audit;
        _notify = notify;
        _logger = logger;
        _options = options;
    }

    private string HeadFile => Path.Combine(_options.DataDir, "chain-head.json");

    // ---------------------------------------------------------------- status

    public async Task<IntegritySummary> GetSummaryAsync(CancellationToken ct = default)
    {
        var state = await GetStateAsync(ct);
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var heads = await ReadHeadsAsync(db, ct);
        return Summarize(state, heads, await TryAnchorLineAsync(heads, ct));
    }

    public async Task<IntegrityStatus> GetStatusAsync(CancellationToken ct = default)
    {
        var state = await GetStateAsync(ct);
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var heads = await ReadHeadsAsync(db, ct);
        var checkpoints = (await db.ChainCheckpoints.AsNoTracking().OrderByDescending(c => c.Id).Take(100).ToListAsync(ct))
            .GroupBy(c => c.Chain).ToDictionary(g => g.Key, g => g.ToList());

        var chains = new List<ChainStatus>();
        foreach (var chain in ChainHasher.Chains)
        {
            if (!heads.TryGetValue(chain, out var h)) continue;
            var cs = state.For(chain);
            chains.Add(new ChainStatus(chain, h.Seq, Convert.ToHexString(h.Hash).ToLowerInvariant(), h.LegacyCount, h.LegacyMaxId,
                Utc(h.StartedAt), cs.VerifiedTime, h.VerifiedSeq, cs.LastCheckAt, cs.LastCheckKind, cs.LastCheckMs,
                cs.Breaks.OrderByDescending(b => b.DetectedAt).ToList(),
                (checkpoints.GetValueOrDefault(chain) ?? []).Take(20)
                    .Select(c => new CheckpointInfo(c.Id, c.UpToSeq, c.Reason, c.DeletedRows, Utc(c.CreatedAt), c.Note,
                        Convert.ToHexString(c.Hash)[..16].ToLowerInvariant())).ToList()));
        }
        return new IntegrityStatus(Summarize(state, heads, await TryAnchorLineAsync(heads, ct)), chains, _current,
            _chain.Key != null, _options.AnchorNotify());
    }

    private IntegritySummary Summarize(IntegrityState state, Dictionary<string, ChainHead> heads, string? anchorLine)
    {
        if (_chain.Key == null || !heads.TryGetValue(ChainHasher.Access, out var access))
            return new IntegritySummary("disabled", null, null, 0, null, 0, "", 0, null);

        var open = state.Chains.Values.SelectMany(c => c.Breaks).Where(b => !b.Accepted).OrderBy(b => b.DetectedAt).ToList();
        var lastCheck = state.Chains.Values.Max(c => c.LastCheckAt);
        var status = open.Count > 0 ? "broken" : lastCheck == null ? "notVerified" : "ok";
        return new IntegritySummary(status, state.For(ChainHasher.Access).VerifiedTime, lastCheck, open.Count,
            open.Count > 0 ? Describe(open[0]) : null, access.Seq, Convert.ToHexString(access.Hash).ToLowerInvariant(),
            access.LegacyCount, anchorLine);
    }

    // One line: where a finding is
    public static string Describe(IntegrityBreak b)
    {
        var where = b.Kind == "unchained" ? $"Id {b.FromId}-{b.ToId}" : b.FromSeq == b.ToSeq ? $"#{b.FromSeq}" : $"#{b.FromSeq}-#{b.ToSeq}";
        return $"{b.Chain}: {b.Kind} {where} ({TimeRange(b)})";
    }

    public static string TimeRange(IntegrityBreak b) => $"{Fmt(b.TimeBefore)} - {Fmt(b.TimeAfter)} UTC";

    private static string Fmt(DateTime? t) => t?.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) ?? "?";

    private static DateTime Utc(DateTime t) => DateTime.SpecifyKind(t, DateTimeKind.Utc);

    // ---------------------------------------------------------------- verification

    public VerifyRun? GetRun(string id)
    {
        lock (_runs) return _history.GetValueOrDefault(id) ?? (_current?.Id == id ? _current : null);
    }

    // Starts a full verification in the background; a run already going is returned instead
    public VerifyRun StartVerify(string user)
    {
        VerifyRun run;
        lock (_runs)
        {
            if (_current is { State: "running" }) return _current;
            run = _current = new VerifyRun { Kind = "full", StartedBy = user };
        }
        _ = Task.Run(() => ExecuteAsync(run, CancellationToken.None));
        return run;
    }

    // Runs one verification now; null when another one is going. For the background service.
    public async Task<VerifyRun?> VerifyAsync(bool full, CancellationToken ct)
    {
        VerifyRun run;
        lock (_runs)
        {
            if (_current is { State: "running" }) return null;
            run = _current = new VerifyRun { Kind = full ? "full" : "incremental" };
        }
        await ExecuteAsync(run, ct);
        return run;
    }

    private async Task ExecuteAsync(VerifyRun run, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await _runGate.WaitAsync(ct);
        try
        {
            await VerifyCoreAsync(run, ct);
            run.State = "done";
        }
        catch (OperationCanceledException) { run.State = "canceled"; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Verification of the record chain failed.");
            run.Error = ex.Message;
            run.State = "failed";
        }
        finally
        {
            run.ElapsedMs = sw.ElapsedMilliseconds;
            lock (_runs)
            {
                _history[run.Id] = run;
                while (_history.Count > 10) _history.Remove(_history.OrderBy(h => h.Value.StartedAt).First().Key);
            }
            _runGate.Release();
        }

        // After the gate: the log writes go through the chain too
        if (run.State == "done")
        {
            if (run.Kind == "full" || run.Breaks.Count > 0)
                await _audit.WriteAsync(run.StartedBy, "integrity.verify",
                    $"kind={run.Kind}, rows={run.RowsDone}, ms={run.ElapsedMs}, breaks={run.Breaks.Count(b => !b.Accepted)}");
            try { await NotifyBreaksAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _logger.LogWarning(ex, "Integrity alert failed."); }
        }
    }

    private async Task VerifyCoreAsync(VerifyRun run, CancellationToken ct)
    {
        var full = run.Kind == "full";
        var key = _chain.Key ?? throw new InvalidOperationException(Messages.Get("integrity.noKey"));
        var state = await GetStateAsync(ct);
        var known = ReadHeadFile(key);

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var heads = await ReadHeadsAsync(db, ct);
        var starts = (await db.ChainCheckpoints.AsNoTracking().ToListAsync(ct))
            .GroupBy(c => c.Chain).ToDictionary(g => g.Key, g => g.Max(c => c.UpToSeq));
        run.RowsTotal = heads.Values.Sum(h =>
        {
            var from = starts.GetValueOrDefault(h.Chain);
            if (!full && h.VerifiedSeq > from && h.VerifiedSeq <= h.Seq) from = h.VerifiedSeq;
            return Math.Max(0, h.Seq - from);
        });

        long done = 0;
        var now = _options.UtcNow();
        foreach (var chain in ChainHasher.Chains)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var cs = state.For(chain);
            var baseRows = done;
            var result = await ChainVerifier.RunAsync(db, chain, key, full, known?.GetValueOrDefault(chain),
                cs.VerifiedId, rows => run.RowsDone = baseRows + rows, ct);
            done += result.Rows;
            run.RowsDone = done;
            if (!result.Initialized) continue;

            if (result.LastHash != null && !result.Breaks.Any(b => b.Kind == "keyChanged"))
            {
                var seq = result.LastSeq;
                var hash = result.LastHash;
                await db.ChainHeads.Where(h => h.Chain == chain).ExecuteUpdateAsync(s => s
                    .SetProperty(h => h.VerifiedSeq, seq).SetProperty(h => h.VerifiedHash, hash).SetProperty(h => h.VerifiedAt, now), ct);
            }

            await _stateGate.WaitAsync(ct);
            try
            {
                var found = result.Breaks;
                var open = cs.Breaks.Where(b => !b.Accepted).ToList();
                foreach (var b in found)
                    if (open.FirstOrDefault(o => o.Id == b.Id) is { } same) b.DetectedAt = same.DetectedAt;
                if (full)
                    cs.Breaks.RemoveAll(b => !b.Accepted);
                run.NewBreaks += found.Count(b => open.All(o => o.Id != b.Id));
                foreach (var b in found)
                    if (cs.Breaks.All(o => o.Id != b.Id || o.Accepted)) cs.Breaks.Add(b);
                if (cs.Breaks.Count > MaxBreaksKept)
                    cs.Breaks = cs.Breaks.OrderBy(b => b.Accepted ? 0 : 1).ThenByDescending(b => b.DetectedAt).Take(MaxBreaksKept).ToList();

                cs.LastCheckAt = now;
                cs.LastCheckKind = run.Kind;
                cs.LastCheckMs = sw.ElapsedMilliseconds;
                if (result.Rows > 0 || full)
                {
                    cs.VerifiedId = result.LastId;
                    if (result.LastTime != null) cs.VerifiedTime = result.LastTime;
                }
                run.Breaks.AddRange(found);
            }
            finally { _stateGate.Release(); }
        }
        await SaveStateAsync(db, state, ct);
        await UpdateHeadFileAsync(false, ct);
    }

    // ---------------------------------------------------------------- findings: alert, accept

    // A new finding is logged and alerted at once; findings that stay open are alerted again every 24 h
    public async Task NotifyBreaksAsync(CancellationToken ct)
    {
        var state = await GetStateAsync(ct);
        var open = state.Chains.Values.SelectMany(c => c.Breaks).Where(b => !b.Accepted).OrderBy(b => b.DetectedAt).ToList();

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var alerted = (await GetValueAsync(db, AlertedSignatureKey, ct) ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        DateTime.TryParse(await GetValueAsync(db, AlertedAtKey, ct), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var alertedAt);

        if (open.Count == 0)
        {
            if (alerted.Count > 0) await SetValueAsync(db, AlertedSignatureKey, "", ct);
            return;
        }
        var fresh = open.Where(b => !alerted.Contains(b.Id)).ToList();
        var now = _options.UtcNow();
        if (fresh.Count == 0 && now - alertedAt < TimeSpan.FromHours(24)) return;

        foreach (var b in fresh)
            await _audit.WriteAsync(AuditLog.SystemUser, "integrity.break", Describe(b));

        var first = (fresh.Count > 0 ? fresh : open)[0];
        await _notify("Integrity", "integrity.alertTitle", "integrity.alertBody", true,
            [first.Chain, first.Kind, first.FromSeq != 0 ? first.FromSeq : first.FromId ?? 0, TimeRange(first), Environment.MachineName, open.Count]);

        await SetValueAsync(db, AlertedSignatureKey, string.Join(';', open.Select(b => b.Id)), ct);
        await SetValueAsync(db, AlertedAtKey, now.ToString("o", CultureInfo.InvariantCulture), ct);
    }

    // Starts the chain again from its current head: the findings of that chain are accepted, and the chain verifies
    // from here. Returns null when there is nothing to accept.
    public async Task<string?> AcceptAsync(string chain, string? breakId, string? note, string user, CancellationToken ct)
    {
        var key = _chain.Key;
        if (key == null || !ChainHasher.Chains.Contains(chain)) return null;
        var state = await GetStateAsync(ct);
        var cs = state.For(chain);
        if (!cs.Breaks.Any(b => !b.Accepted)) return null;

        using (await _chain.AcquireAsync(ct))   // no save in between the head and the checkpoint
        {
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var head = await db.ChainHeads.AsNoTracking().FirstOrDefaultAsync(h => h.Chain == chain, ct);
            if (head == null) return null;
            var prevMac = await db.ChainCheckpoints.Where(c => c.Chain == chain).OrderByDescending(c => c.Id)
                .Select(c => c.Mac).FirstOrDefaultAsync(ct) ?? [];

            using var hasher = new ChainHasher(key);
            var checkpoint = new ChainCheckpoint
            {
                Chain = chain, UpToSeq = head.Seq, Hash = head.Hash, DeletedRows = 0, CreatedAt = _options.UtcNow(),
                Reason = "accepted", Note = Truncate($"{user}: {note}", 1000), KeyId = ChainHasher.KeyId(key),
            };
            checkpoint.Mac = hasher.CheckpointMac(checkpoint, prevMac);
            db.ChainCheckpoints.Add(checkpoint);
            await db.SaveChangesAsync(ct);
            await db.ChainHeads.Where(h => h.Chain == chain).ExecuteUpdateAsync(s => s
                .SetProperty(h => h.VerifiedSeq, head.Seq).SetProperty(h => h.VerifiedHash, head.Hash), ct);
            _chain.ResetHeads();
        }

        await _stateGate.WaitAsync(ct);
        try
        {
            foreach (var b in cs.Breaks.Where(b => !b.Accepted))
            {
                b.Accepted = true;
                b.AcceptedBy = user;
                b.AcceptedAt = _options.UtcNow();
                b.Note = note;
            }
        }
        finally { _stateGate.Release(); }
        using (var scope = _scopes.CreateScope())
            await SaveStateAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), state, ct);
        await UpdateHeadFileAsync(true, ct);

        await _audit.WriteAsync(user, "integrity.accept", $"chain={chain}, break={breakId}, note={note}");
        return chain;
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    // ---------------------------------------------------------------- anchors

    public async Task<AnchorInfo?> CreateAnchorAsync(CancellationToken ct = default)
    {
        var key = _chain.Key;
        if (key == null) return null;
        using var scope = _scopes.CreateScope();
        var heads = await ReadHeadsAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), ct);
        if (!heads.TryGetValue(ChainHasher.Access, out var access) || !heads.TryGetValue(ChainHasher.Audit, out var audit)) return null;

        var now = _options.UtcNow();
        var server = Environment.MachineName.Replace(' ', '_');
        var accessHash = Convert.ToHexString(access.Hash).ToLowerInvariant();
        var auditHash = Convert.ToHexString(audit.Hash).ToLowerInvariant();
        var line = $"FAM-ANCHOR v1 server={server} chain=access seq={access.Seq} hash={accessHash} " +
                   $"time={now.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)} audit-seq={audit.Seq} audit-hash={auditHash}";
        using var hasher = new ChainHasher(key);
        return new AnchorInfo(line, server, now, ChainHasher.KeyId(key), access.Seq, accessHash, audit.Seq, auditHash,
            Convert.ToHexString(hasher.Sign(line)).ToLowerInvariant());
    }

    private async Task<string?> TryAnchorLineAsync(Dictionary<string, ChainHead> heads, CancellationToken ct)
    {
        try { return heads.Count == 2 ? (await CreateAnchorAsync(ct))?.Line : null; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    // The daily anchor: always to the system log and the operation log; to the notification channels only when
    // "Integrity": { "AnchorNotify": true } is set in settings.json
    public async Task<bool> WriteAnchorAsync(CancellationToken ct)
    {
        var anchor = await CreateAnchorAsync(ct);
        if (anchor == null) return false;
        _options.OsLog(anchor.Line);
        await _audit.WriteAsync(AuditLog.SystemUser, "integrity.anchor", anchor.Line);
        if (_options.AnchorNotify())
            await _notify("IntegrityAnchor", "integrity.anchorTitle", "integrity.anchorBody", false, [anchor.Line]);
        return true;
    }

    private static readonly Regex AnchorToken = new(@"(?<k>[a-z-]+)=(?<v>\S+)", RegexOptions.Compiled);

    // Compares an anchor (the line, or the downloaded file) with the stored chain
    public async Task<AnchorCheck?> CheckAnchorAsync(string text, CancellationToken ct = default)
    {
        var key = _chain.Key;
        if (key == null) return null;
        string? mac = null;
        var line = text;
        var trimmed = text.TrimStart();
        if (trimmed.StartsWith('{'))
        {
            try
            {
                var node = JsonNode.Parse(trimmed);
                line = node?["line"]?.GetValue<string>() ?? "";
                mac = node?["mac"]?.GetValue<string>();
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return null; }
        }
        var start = line.IndexOf("FAM-ANCHOR v1", StringComparison.Ordinal);
        if (start < 0) return null;
        line = line[start..].Split('\n')[0].Trim();
        var values = AnchorToken.Matches(line).ToDictionary(m => m.Groups["k"].Value, m => m.Groups["v"].Value, StringComparer.Ordinal);

        bool? macValid = null;
        if (mac != null)
        {
            using var hasher = new ChainHasher(key);
            macValid = string.Equals(Convert.ToHexString(hasher.Sign(line)), mac, StringComparison.OrdinalIgnoreCase);
        }
        DateTime? time = values.TryGetValue("time", out var t) && DateTime.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed)
            ? parsed : null;

        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var heads = await ReadHeadsAsync(db, ct);
        var checks = new List<AnchorChainCheck>();
        foreach (var (chain, seqKey, hashKey) in new[] { (ChainHasher.Access, "seq", "hash"), (ChainHasher.Audit, "audit-seq", "audit-hash") })
        {
            if (!values.TryGetValue(seqKey, out var seqText) || !long.TryParse(seqText, out var seq) || !values.TryGetValue(hashKey, out var hashText))
                continue;
            checks.Add(new AnchorChainCheck(chain, seq, await CompareAnchorAsync(db, chain, seq, hashText, heads.GetValueOrDefault(chain), ct)));
        }
        var ok = checks.Count > 0 && checks.All(c => c.Result is "match" or "deleted") && macValid != false;
        return new AnchorCheck(ok, values.GetValueOrDefault("server"), time, macValid, checks);
    }

    private static async Task<string> CompareAnchorAsync(AccessDbContext db, string chain, long seq, string hashHex, ChainHead? head,
        CancellationToken ct)
    {
        if (head == null || seq > head.Seq) return "ahead";   // the database is older than the anchor
        byte[]? stored = chain == ChainHasher.Access
            ? await db.AccessRecords.Where(r => r.ChainSeq == seq).Select(r => r.ChainHash).FirstOrDefaultAsync(ct)
            : await db.AuditLogs.Where(r => r.ChainSeq == seq).Select(r => r.ChainHash).FirstOrDefaultAsync(ct);
        if (stored == null)
        {
            // Not there: deleted by retention (a checkpoint knows the hash at its own seq), or seq 0 = the start
            var cp = await db.ChainCheckpoints.AsNoTracking().Where(c => c.Chain == chain && c.UpToSeq == seq).FirstOrDefaultAsync(ct);
            if (cp != null) stored = cp.Hash;
            else
            {
                var newest = await db.ChainCheckpoints.Where(c => c.Chain == chain).MaxAsync(c => (long?)c.UpToSeq, ct) ?? 0;
                return seq <= newest ? "deleted" : "mismatch";
            }
        }
        return string.Equals(Convert.ToHexString(stored), hashHex, StringComparison.OrdinalIgnoreCase) ? "match" : "mismatch";
    }

    // ---------------------------------------------------------------- the head file (outside the database)

    // The newest heads are also kept in a file next to the key. A restored older database is behind it.
    private Dictionary<string, ChainVerifier.KnownHead>? ReadHeadFile(byte[] key)
    {
        try
        {
            if (!File.Exists(HeadFile)) return null;
            var node = JsonNode.Parse(File.ReadAllText(HeadFile));
            if (node == null || node["keyId"]?.GetValue<string>() != ChainHasher.KeyId(key)) return null;
            var map = new Dictionary<string, ChainVerifier.KnownHead>();
            var text = new StringBuilder(ChainHasher.KeyId(key));
            foreach (var chain in ChainHasher.Chains)
            {
                var seq = node[chain]?["seq"]?.GetValue<long>() ?? -1;
                var hash = node[chain]?["hash"]?.GetValue<string>() ?? "";
                if (seq >= 0 && hash.Length == 64) map[chain] = new ChainVerifier.KnownHead(seq, Convert.FromHexString(hash));
                text.Append('|').Append(seq).Append('|').Append(hash);
            }
            using var hasher = new ChainHasher(key);
            var mac = node["mac"]?.GetValue<string>() ?? "";
            if (!string.Equals(Convert.ToHexString(hasher.Sign(text.ToString())), mac, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("The chain head file {File} has been changed and is ignored.", HeadFile);
                return null;
            }
            return map;
        }
        catch (Exception ex) when (ex is IOException or JsonException or FormatException or InvalidOperationException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "The chain head file {File} cannot be read.", HeadFile);
            return null;
        }
    }

    // Records the current heads; never moves a chain back (that is what a restored database looks like) unless forced
    public async Task UpdateHeadFileAsync(bool force, CancellationToken ct)
    {
        var key = _chain.Key;
        if (key == null) return;
        using var scope = _scopes.CreateScope();
        var heads = await ReadHeadsAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), ct);
        if (heads.Count < ChainHasher.Chains.Length) return;
        var state = await GetStateAsync(ct);
        var known = ReadHeadFile(key) ?? new();

        var changed = false;
        var current = new Dictionary<string, (long Seq, string Hash)>();
        foreach (var chain in ChainHasher.Chains)
        {
            var h = heads[chain];
            var hash = Convert.ToHexString(h.Hash).ToLowerInvariant();
            var suspicious = state.For(chain).Breaks.Any(b => !b.Accepted && b.Kind is "headRollback" or "headMismatch" or "truncatedTail");
            if (known.TryGetValue(chain, out var k) && !force && (h.Seq < k.Seq || suspicious))
            {
                current[chain] = (k.Seq, Convert.ToHexString(k.Hash).ToLowerInvariant());
                continue;
            }
            if (!known.TryGetValue(chain, out k) || k.Seq != h.Seq || Convert.ToHexString(k.Hash).ToLowerInvariant() != hash) changed = true;
            current[chain] = (h.Seq, hash);
        }
        if (!changed && !force) return;

        var keyId = ChainHasher.KeyId(key);
        var text = new StringBuilder(keyId);
        foreach (var chain in ChainHasher.Chains) text.Append('|').Append(current[chain].Seq).Append('|').Append(current[chain].Hash);
        using var hasher = new ChainHasher(key);
        var json = new JsonObject
        {
            ["keyId"] = keyId,
            ["time"] = _options.UtcNow().ToString("o", CultureInfo.InvariantCulture),
            ["mac"] = Convert.ToHexString(hasher.Sign(text.ToString())).ToLowerInvariant(),
        };
        foreach (var chain in ChainHasher.Chains)
            json[chain] = new JsonObject { ["seq"] = current[chain].Seq, ["hash"] = current[chain].Hash };
        try
        {
            var bytes = Encoding.UTF8.GetBytes(json.ToJsonString());
            if (Path.GetFullPath(_options.DataDir) == AppPaths.DataDir) SecretStore.WriteProtected(HeadFile, bytes);
            else File.WriteAllBytes(HeadFile, bytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "The chain head file {File} cannot be written.", HeadFile);
        }
    }

    // ---------------------------------------------------------------- schedule bookkeeping (CollectorStates)

    public async Task<bool> FullDoneTodayAsync(DateTime localNow, CancellationToken ct) =>
        await StampAsync(LastFullDayKey, localNow, ct, mark: false);

    public async Task MarkFullDoneAsync(DateTime localNow, CancellationToken ct) => await StampAsync(LastFullDayKey, localNow, ct, mark: true);

    public async Task<bool> AnchorDoneTodayAsync(DateTime localNow, CancellationToken ct) =>
        await StampAsync(AnchorDayKey, localNow, ct, mark: false);

    public async Task MarkAnchorDoneAsync(DateTime localNow, CancellationToken ct) => await StampAsync(AnchorDayKey, localNow, ct, mark: true);

    private async Task<bool> StampAsync(string key, DateTime localNow, CancellationToken ct, bool mark)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var day = localNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        if (mark) { await SetValueAsync(db, key, day, ct); return true; }
        return await GetValueAsync(db, key, ct) == day;
    }

    // ---------------------------------------------------------------- state

    private static async Task<Dictionary<string, ChainHead>> ReadHeadsAsync(AccessDbContext db, CancellationToken ct)
    {
        try { return (await db.ChainHeads.AsNoTracking().ToListAsync(ct)).ToDictionary(h => h.Chain); }
        catch (Microsoft.Data.Sqlite.SqliteException) { return new(); }   // tables not created yet
    }

    private async Task<IntegrityState> GetStateAsync(CancellationToken ct)
    {
        if (_state != null) return _state;
        await _stateGate.WaitAsync(ct);
        try
        {
            if (_state != null) return _state;
            using var scope = _scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            var text = await GetValueAsync(db, StateKey, ct);
            try { _state = text == null ? new() : JsonSerializer.Deserialize<IntegrityState>(text, Json) ?? new(); }
            catch (JsonException) { _state = new(); }
            return _state;
        }
        finally { _stateGate.Release(); }
    }

    private async Task SaveStateAsync(AccessDbContext db, IntegrityState state, CancellationToken ct)
    {
        string text;
        await _stateGate.WaitAsync(ct);
        try { text = JsonSerializer.Serialize(state, Json); }
        finally { _stateGate.Release(); }
        await SetValueAsync(db, StateKey, text, ct);
    }

    private static async Task<string?> GetValueAsync(AccessDbContext db, string key, CancellationToken ct) =>
        (await db.CollectorStates.AsNoTracking().FirstOrDefaultAsync(s => s.Key == key, ct))?.Value;

    private static async Task SetValueAsync(AccessDbContext db, string key, string value, CancellationToken ct)
    {
        var row = await db.CollectorStates.FindAsync([key], ct);
        if (row == null) db.CollectorStates.Add(new CollectorState { Key = key, Value = value });
        else row.Value = value;
        await db.SaveChangesAsync(ct);
    }
}

// What a verification remembers between runs (CollectorStates "Integrity.State")
public class IntegrityState
{
    public Dictionary<string, ChainState> Chains { get; set; } = new();

    public ChainState For(string chain)
    {
        if (!Chains.TryGetValue(chain, out var s)) Chains[chain] = s = new ChainState();
        return s;
    }
}

public class ChainState
{
    public DateTime? LastCheckAt { get; set; }
    public string? LastCheckKind { get; set; }
    public long LastCheckMs { get; set; }
    public long VerifiedId { get; set; }
    public DateTime? VerifiedTime { get; set; }
    public List<IntegrityBreak> Breaks { get; set; } = [];
}

// Seams for tests: where the head file lives, the clock, the system log, the AnchorNotify setting
internal sealed class IntegrityOptions
{
    public string DataDir { get; init; } = AppPaths.DataDir;
    public Func<DateTime> UtcNow { get; init; } = () => DateTime.UtcNow;
    public Action<string> OsLog { get; init; } = line => AnchorLog.Write(line);

    public Func<bool> AnchorNotify { get; init; } = () =>
        SettingsStore.Load()["Integrity"] is JsonObject o && o["AnchorNotify"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;
}
