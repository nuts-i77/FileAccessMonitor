using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

// Retention deletes a prefix of the chain and leaves a checkpoint, so the chain still verifies
public class ChainRetentionTests
{
    private static readonly DateTime Now = DateTime.UtcNow;
    private static DateTime Old => Now.AddDays(-10);
    private static DateTime Recent => Now.AddHours(-1);

    private static List<long> Seqs(ChainEnv env) => env.Records().Select(r => r.ChainSeq!.Value).ToList();

    [Fact]
    public async Task The_prefix_goes_and_a_late_old_record_after_a_kept_one_stays()
    {
        using var env = new ChainEnv();
        // seq 1-4 old, 5 recent, 6 OLD but uploaded late by an agent, 7-8 recent
        await env.AddRecordsAsync(Old, Old, Old, Old, Recent, Old, Recent, Recent);
        var deleted = await env.NewRetention().CleanupAsync(Now.AddDays(-5), default);

        Assert.Equal(4, deleted);
        Assert.Equal([5L, 6L, 7L, 8L], Seqs(env));
        using var scope = env.Scopes.CreateScope();
        var cp = scope.ServiceProvider.GetRequiredService<AccessDbContext>().ChainCheckpoints
            .Where(c => c.Chain == "access" && c.Reason == "retention").Single();
        Assert.Equal(4, cp.UpToSeq);
        Assert.Equal(4, cp.DeletedRows);

        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Empty(run!.Breaks);
        Assert.Equal(4, run.RowsDone);

        // New records continue the chain after the checkpoint
        await env.AddRecordsAsync(2, first: 100);
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);
    }

    [Fact]
    public async Task A_record_dated_far_in_the_future_does_not_block_the_cleanup()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Old, Old, Now.AddDays(30), Old, Recent, Recent);
        Assert.Equal(4, await env.NewRetention().CleanupAsync(Now.AddDays(-5), default));
        Assert.Equal([5L, 6L], Seqs(env));
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);
    }

    [Fact]
    public async Task Deleting_everything_leaves_a_valid_chain_that_continues()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Old, Old, Old);
        Assert.Equal(3, await env.NewRetention().CleanupAsync(Now, default));
        Assert.Empty(env.Records());
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);

        await env.AddRecordsAsync(2, first: 10);
        Assert.Equal([4L, 5L], Seqs(env));
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);
    }

    [Fact]
    public async Task Nothing_old_means_no_checkpoint()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Recent, Recent);
        Assert.Equal(0, await env.NewRetention().CleanupAsync(Now.AddDays(-5), default));
        using var scope = env.Scopes.CreateScope();
        Assert.DoesNotContain(scope.ServiceProvider.GetRequiredService<AccessDbContext>().ChainCheckpoints.ToList(), c => c.Reason == "retention");
    }

    [Fact]
    public async Task Checkpoints_chain_their_macs_across_several_cleanups()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Old, Old, Recent, Recent);
        await env.NewRetention().CleanupAsync(Now.AddDays(-5), default);
        await env.AddRecordsAsync(Old, Old, Recent);
        await env.NewRetention().CleanupAsync(Now.AddDays(-5), default);
        await env.NewRetention().CleanupAsync(Now.AddMinutes(-30), default);

        using (var scope = env.Scopes.CreateScope())
            Assert.True(scope.ServiceProvider.GetRequiredService<AccessDbContext>().ChainCheckpoints
                .Count(c => c.Chain == "access" && c.Reason == "retention") >= 2);
        Assert.Empty((await env.NewService().VerifyAsync(full: true, default))!.Breaks);
    }

    [Fact]
    public async Task Legacy_records_are_deleted_by_time_and_unchained_new_ones_are_kept()
    {
        using var env = new ChainEnv(genesis: false);
        // Rows from before tamper detection: saved without the interceptor
        var plain = new DbContextOptionsBuilder<AccessDbContext>().UseSqlite($"Data Source={env.DbPath}").Options;
        using (var db = new AccessDbContext(plain))
        {
            db.AccessRecords.AddRange(ChainEnv.Rec(1, Old), ChainEnv.Rec(2, Old), ChainEnv.Rec(3, Recent));
            await db.SaveChangesAsync();
        }
        using (var scope = env.Scopes.CreateScope())
            await SchemaV110Integrity.ApplyAsync(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), env.Key);

        await env.AddRecordsAsync(Old, Recent);   // chained: seq 1 old, 2 recent
        // Somebody adds an old row behind the program's back
        env.Exec(@"INSERT INTO AccessRecords (FilePath, FileName, FolderPath, UserName, AccessType, IsFolder, ServerName, AccessTime, Denied)
                   VALUES ('D:\x', 'x', 'D:\', 'm', 'Read', 0, 'S1', '2020-01-01 00:00:00', 0)");

        var deleted = await env.NewRetention().CleanupAsync(Now.AddDays(-5), default);
        Assert.Equal(3, deleted);   // two legacy rows and chained seq 1
        var left = env.Records();
        Assert.Equal(3, left.Count);
        Assert.Contains(left, r => r.ChainSeq == null && r.FilePath == @"D:\x");   // evidence stays and is reported
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Equal("unchained", Assert.Single(run!.Breaks).Kind);
    }

    [Fact]
    public async Task A_removed_or_edited_checkpoint_is_found()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Old, Old, Recent, Recent);
        await env.NewRetention().CleanupAsync(Now.AddDays(-5), default);

        env.Exec("UPDATE ChainCheckpoints SET DeletedRows = 99 WHERE Reason = 'retention'");
        var run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Contains(run!.Breaks, b => b.Kind == "checkpoint");

        env.Exec("DELETE FROM ChainCheckpoints WHERE Reason = 'retention'");
        run = await env.NewService().VerifyAsync(full: true, default);
        Assert.Contains(run!.Breaks, b => b.Kind == "missing");   // the rows of the removed prefix are missing
    }

    [Fact]
    public async Task Retention_with_a_tampered_chain_still_runs()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(Old, Old, Old, Recent);
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 3");
        Assert.Equal(2, await env.NewRetention().CleanupAsync(Now.AddDays(-5), default));
        Assert.Equal([4L], Seqs(env));
    }
}
