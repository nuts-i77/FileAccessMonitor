using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

// First start on 1.10 with an existing database: genesis, legacy counts, nothing changes on the second start
public class ChainMigrationTests
{
    private static async Task<ChainEnv> LegacyDatabaseAsync()
    {
        var env = new ChainEnv(genesis: false);
        var plain = new DbContextOptionsBuilder<AccessDbContext>().UseSqlite($"Data Source={env.DbPath}").Options;
        using var db = new AccessDbContext(plain);
        db.AccessRecords.AddRange(Enumerable.Range(1, 25).Select(i => ChainEnv.Rec(i)));
        db.AuditLogs.AddRange(Enumerable.Range(1, 7).Select(i => new AuditLogEntry { Time = DateTime.UtcNow, UserName = "admin", Action = "old.action" }));
        await db.SaveChangesAsync();
        return env;
    }

    private static async Task ApplyAsync(ChainEnv env)
    {
        using var scope = env.Scopes.CreateScope();
        await SchemaV110Integrity.ApplyAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), env.Key);
    }

    [Fact]
    public async Task The_start_records_the_old_rows_without_hashing_them()
    {
        using var env = await LegacyDatabaseAsync();
        await ApplyAsync(env);

        var access = env.Head("access");
        Assert.Equal((0L, 25L), (access.Seq, access.LegacyCount));
        Assert.Equal(env.Scalar<long>("SELECT MAX(Id) FROM AccessRecords"), access.LegacyMaxId);
        var audit = env.Head("audit");
        Assert.Equal((0L, 7L), (audit.Seq, audit.LegacyCount));
        Assert.All(env.Records(), r => Assert.Null(r.ChainSeq));

        Assert.Equal(2, env.Scalar<long>("SELECT COUNT(*) FROM ChainCheckpoints WHERE Reason = 'genesis'"));
        Assert.Equal(1, env.Scalar<long>("SELECT COUNT(*) FROM sqlite_master WHERE name = 'IX_AccessRecords_ChainSeq'"));
        Assert.Equal(1, env.Scalar<long>("SELECT COUNT(*) FROM sqlite_master WHERE name = 'IX_AuditLogs_ChainSeq'"));
    }

    [Fact]
    public async Task A_second_start_changes_nothing()
    {
        using var env = await LegacyDatabaseAsync();
        await ApplyAsync(env);
        var before = env.Head("access");
        await env.AddRecordsAsync(3, first: 100);

        await ApplyAsync(env);
        await ApplyAsync(env);
        Assert.Equal(2, env.Scalar<long>("SELECT COUNT(*) FROM ChainCheckpoints"));
        var after = env.Head("access");
        Assert.Equal(3, after.Seq);
        Assert.Equal(before.StartedAt, after.StartedAt);
        Assert.Equal(before.LegacyMaxId, after.LegacyMaxId);
    }

    [Fact]
    public async Task Old_rows_are_not_reported_but_the_summary_counts_them()
    {
        using var env = await LegacyDatabaseAsync();
        await ApplyAsync(env);
        await env.AddRecordsAsync(5, first: 100);
        var svc = env.NewService();
        var run = await svc.VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
        Assert.Equal(5, run.RowsDone);
        var summary = await svc.GetSummaryAsync();
        Assert.Equal(("ok", 5L, 25L), (summary.State, summary.HeadSeq, summary.LegacyRows));
    }

    [Fact]
    public async Task A_fresh_database_starts_with_no_legacy_rows()
    {
        using var env = new ChainEnv();
        Assert.Equal((0L, 0L, 0L), (env.Head("access").Seq, env.Head("access").LegacyCount, env.Head("audit").LegacyCount));
        await env.AddRecordsAsync(1);
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);
    }

    [Fact]
    public async Task Duplicate_seq_values_do_not_stop_the_start()
    {
        using var env = new ChainEnv(genesis: false);
        env.Exec(@"INSERT INTO AccessRecords (FilePath, FileName, FolderPath, UserName, AccessType, IsFolder, ServerName, AccessTime, Denied, ChainSeq)
                   VALUES ('a','a','a','a','Read',0,'S','2026-01-01 00:00:00',0,1), ('b','b','b','b','Read',0,'S','2026-01-01 00:00:00',0,1)");
        await ApplyAsync(env);   // the unique index cannot be made; the start still goes through
        Assert.Equal(0, env.Head("access").Seq);
    }
}
