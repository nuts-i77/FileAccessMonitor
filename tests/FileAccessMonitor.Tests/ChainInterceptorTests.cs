using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

// The insert path against real SQLite files (two contexts, busy timeout, many rows, many tasks)
public class ChainInterceptorTests
{
    [Fact]
    public async Task A_single_record_gets_seq_1_and_the_head_follows()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(1);
        var r = Assert.Single(env.Records());
        Assert.Equal(1, r.ChainSeq);
        Assert.Equal(32, r.ChainHash!.Length);
        var head = env.Head("access");
        Assert.Equal(1, head.Seq);
        Assert.Equal(r.ChainHash, head.Hash);
        Assert.Equal(0, env.Head("audit").Seq);
    }

    [Fact]
    public void Synchronous_saves_are_chained_too()
    {
        using var env = new ChainEnv();
        using var scope = env.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.AccessRecords.AddRange(ChainEnv.Rec(1), ChainEnv.Rec(2));
        db.SaveChanges();
        Assert.Equal([1L, 2L], env.Records().Select(r => r.ChainSeq!.Value).ToArray());
        Assert.Equal(2, env.Head("access").Seq);
    }

    [Fact]
    public async Task A_database_without_a_start_gets_one_on_the_first_save()
    {
        using var env = new ChainEnv(genesis: false);
        await env.AddRecordsAsync(3);
        Assert.Equal(3, env.Head("access").Seq);
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
    }

    [Fact]
    public async Task Ten_thousand_rows_get_seq_in_the_order_they_were_added()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(10_000);
        var rows = env.Records();
        Assert.Equal(10_000, rows.Count);
        // ChangeTracker order = AddRange order: seq follows the order the database assigned Ids in
        for (var i = 0; i < rows.Count; i++)
        {
            Assert.Equal(i + 1, rows[i].ChainSeq);
            Assert.Equal($"f{i + 1}.txt", rows[i].FileName);
        }
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
        Assert.Equal(10_000, run.RowsDone);
    }

    [Fact]
    public async Task Concurrent_saves_from_many_tasks_give_gap_free_unique_seq_and_a_valid_chain()
    {
        using var env = new ChainEnv();
        var audit = env.Services.GetRequiredService<AuditLog>();
        var tasks = Enumerable.Range(0, 8).Select(t => Task.Run(async () =>
        {
            for (var b = 0; b < 5; b++)
            {
                await env.AddRecordsAsync(10, first: t * 100 + b * 10);
                await audit.WriteAsync("user" + t, "test.action", $"batch {b}");
            }
        }));
        await Task.WhenAll(tasks);

        var seqs = env.Records().Select(r => r.ChainSeq!.Value).Order().ToArray();
        Assert.Equal(Enumerable.Range(1, 400).Select(i => (long)i), seqs);
        Assert.Equal(400, env.Head("access").Seq);
        Assert.Equal(40, env.Head("audit").Seq);
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
        Assert.Equal(440, run.RowsDone);
    }

    [Fact]
    public async Task Audit_entries_have_their_own_chain_and_saving_them_does_not_touch_the_access_chain()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(2);
        var audit = env.Services.GetRequiredService<AuditLog>();
        await audit.WriteAsync("admin", "a.b", "x");
        await audit.WriteAsync("admin", "a.c", null);

        using var scope = env.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var logs = db.AuditLogs.AsNoTracking().OrderBy(l => l.Id).ToList();
        Assert.Equal([1L, 2L], logs.Select(l => l.ChainSeq!.Value).ToArray());
        Assert.Equal(2, env.Head("audit").Seq);
        Assert.Equal(2, env.Head("access").Seq);
        Assert.Equal(logs[1].ChainHash, env.Head("audit").Hash);
    }

    [Fact]
    public async Task A_save_that_fails_releases_the_lock_and_leaves_the_head_unchanged()
    {
        using var env = new ChainEnv(busySeconds: 1);
        await env.AddRecordsAsync(1);

        // Another connection holds the write lock (reads still work)
        using (var other = new SqliteConnection($"Data Source={env.DbPath};Pooling=False"))
        {
            other.Open();
            using (var begin = other.CreateCommand()) { begin.CommandText = "BEGIN IMMEDIATE"; begin.ExecuteNonQuery(); }

            await Assert.ThrowsAnyAsync<Exception>(() => env.AddRecordsAsync(5));

            // The lock is free again at once (not after the 30 s watchdog)
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            (await env.Interceptor.AcquireAsync(cts.Token)).Dispose();

            using (var rollback = other.CreateCommand()) { rollback.CommandText = "ROLLBACK"; rollback.ExecuteNonQuery(); }
        }

        Assert.Equal(1, env.Head("access").Seq);
        await env.AddRecordsAsync(1);
        // The failed block left no gap: the next record is 2, and the chain is valid
        Assert.Equal([1L, 2L], env.Records().Select(r => r.ChainSeq!.Value).ToArray());
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
    }

    [Fact]
    public async Task A_second_context_waits_for_the_first_save_and_both_chain()
    {
        using var env = new ChainEnv();
        using var s1 = env.Scopes.CreateScope();
        using var s2 = env.Scopes.CreateScope();
        var db1 = s1.ServiceProvider.GetRequiredService<AccessDbContext>();
        var db2 = s2.ServiceProvider.GetRequiredService<AccessDbContext>();
        db1.AccessRecords.Add(ChainEnv.Rec(1));
        db2.AccessRecords.Add(ChainEnv.Rec(2));
        await Task.WhenAll(db1.SaveChangesAsync(), db2.SaveChangesAsync());
        Assert.Equal([1L, 2L], env.Records().Select(r => r.ChainSeq!.Value).Order().ToArray());
    }

    [Fact]
    public async Task A_canceled_save_releases_the_lock()
    {
        using var env = new ChainEnv();
        using var scope = env.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.AccessRecords.Add(ChainEnv.Rec(1));
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => db.SaveChangesAsync(canceled.Token));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        (await env.Interceptor.AcquireAsync(cts.Token)).Dispose();
        await env.AddRecordsAsync(1);
        Assert.Equal(1, env.Head("access").Seq);
    }

    [Fact]
    public async Task The_watchdog_frees_a_lock_nobody_releases()
    {
        using var env = new ChainEnv(watchdog: TimeSpan.FromMilliseconds(300));
        var lost = await env.Interceptor.AcquireAsync();   // never disposed
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        (await env.Interceptor.AcquireAsync(cts.Token)).Dispose();
        lost.Dispose();   // a late release does nothing
        await env.AddRecordsAsync(1);
        Assert.Equal(1, env.Head("access").Seq);
    }

    [Fact]
    public async Task Contexts_without_the_interceptor_still_save_unchained_rows()
    {
        using var env = new ChainEnv();
        var options = new DbContextOptionsBuilder<AccessDbContext>().UseSqlite($"Data Source={env.DbPath}").Options;
        using (var plain = new AccessDbContext(options))
        {
            plain.AccessRecords.Add(ChainEnv.Rec(1));
            await plain.SaveChangesAsync();
        }
        Assert.Null(Assert.Single(env.Records()).ChainSeq);
    }
}
