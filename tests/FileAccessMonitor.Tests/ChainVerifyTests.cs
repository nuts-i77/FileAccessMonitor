using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

// Every way of editing the file behind the program's back is found, once, with its location
public class ChainVerifyTests
{
    private static async Task<ChainEnv> EnvWithAsync(int rows = 100)
    {
        var env = new ChainEnv();
        for (var i = 0; i < rows; i += 20)
            await env.AddRecordsAsync(Math.Min(20, rows - i), first: i + 1);
        return env;
    }

    private static async Task<VerifyRun> FullAsync(ChainEnv env, IntegrityService? svc = null)
    {
        var run = await (svc ?? env.NewService()).VerifyAsync(full: true, default);
        Assert.NotNull(run);
        Assert.Equal("done", run.State);
        return run;
    }

    [Fact]
    public async Task An_untouched_chain_is_ok()
    {
        using var env = await EnvWithAsync();
        var svc = env.NewService();
        Assert.Equal("notVerified", (await svc.GetSummaryAsync()).State);
        var run = await FullAsync(env, svc);
        Assert.Empty(run.Breaks);
        var summary = await svc.GetSummaryAsync();
        Assert.Equal("ok", summary.State);
        Assert.Equal(100, summary.HeadSeq);
        Assert.NotNull(summary.VerifiedUpTo);
    }

    [Fact]
    public async Task An_altered_row_is_one_break_with_its_place()
    {
        using var env = await EnvWithAsync();
        env.Exec("UPDATE AccessRecords SET FilePath = 'D:\\share\\evil.txt' WHERE ChainSeq = 50");
        var run = await FullAsync(env);
        var b = Assert.Single(run.Breaks);
        Assert.Equal("altered", b.Kind);
        Assert.Equal("access", b.Chain);
        Assert.Equal((50L, 50L), (b.FromSeq, b.ToSeq));
        Assert.Equal(env.Scalar<long>("SELECT Id FROM AccessRecords WHERE ChainSeq = 50"), b.FromId);
        Assert.NotNull(b.TimeBefore);
        Assert.NotNull(b.TimeAfter);
    }

    [Fact]
    public async Task A_deleted_row_in_the_middle_is_one_missing_break()
    {
        using var env = await EnvWithAsync();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 50");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("missing", b.Kind);
        Assert.Equal((50L, 50L), (b.FromSeq, b.ToSeq));
        Assert.Equal(1, b.Count);
    }

    [Fact]
    public async Task Several_deleted_rows_in_a_row_are_one_break()
    {
        using var env = await EnvWithAsync();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq BETWEEN 50 AND 60");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("missing", b.Kind);
        Assert.Equal((50L, 60L), (b.FromSeq, b.ToSeq));
        Assert.Equal(11, b.Count);
    }

    [Fact]
    public async Task A_deleted_first_row_is_found()
    {
        using var env = await EnvWithAsync();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 1");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("missing", b.Kind);
        Assert.Equal((1L, 1L), (b.FromSeq, b.ToSeq));
    }

    [Fact]
    public async Task A_deleted_last_row_is_a_truncated_tail()
    {
        using var env = await EnvWithAsync();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 100");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("truncatedTail", b.Kind);
        Assert.Equal((100L, 100L), (b.FromSeq, b.ToSeq));
    }

    [Fact]
    public async Task Several_deleted_last_rows_are_one_truncated_tail()
    {
        using var env = await EnvWithAsync();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq > 90");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("truncatedTail", b.Kind);
        Assert.Equal((91L, 100L), (b.FromSeq, b.ToSeq));
    }

    [Fact]
    public async Task An_inserted_row_without_a_chain_is_found()
    {
        using var env = await EnvWithAsync();
        env.Exec(@"INSERT INTO AccessRecords (FilePath, FileName, FolderPath, UserName, AccessType, IsFolder, ServerName, AccessTime, Denied)
                   VALUES ('D:\x.txt', 'x.txt', 'D:\', 'mallory', 'Read', 0, 'S1', '2026-01-01 00:00:00', 0)");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("unchained", b.Kind);
        Assert.Equal(1, b.Count);
        Assert.Equal(env.Scalar<long>("SELECT MAX(Id) FROM AccessRecords"), b.FromId);
    }

    [Fact]
    public async Task Swapped_seq_values_are_one_altered_break()
    {
        using var env = await EnvWithAsync();
        env.Exec("UPDATE AccessRecords SET ChainSeq = -1 WHERE ChainSeq = 10");
        env.Exec("UPDATE AccessRecords SET ChainSeq = 10 WHERE ChainSeq = 11");
        env.Exec("UPDATE AccessRecords SET ChainSeq = 11 WHERE ChainSeq = -1");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("altered", b.Kind);
        Assert.Equal(10, b.FromSeq);
        Assert.True(b.ToSeq >= 11);   // the row after the swap was hashed over the other row's hash, so it is part of the same run
    }

    [Fact]
    public async Task An_edited_head_is_found()
    {
        using var env = await EnvWithAsync();
        env.Exec("UPDATE ChainHeads SET Hash = zeroblob(32) WHERE Chain = 'access'");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal("headMismatch", b.Kind);
    }

    [Fact]
    public async Task The_wrong_key_is_one_key_changed_break_not_thousands_of_mismatches()
    {
        using var env = await EnvWithAsync();
        var other = new ChainInterceptor(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var run = await FullAsync(env, env.NewService(other));
        Assert.Equal("keyChanged", Assert.Single(run.Breaks, b => b.Chain == "access").Kind);
        Assert.Equal(0, run.RowsDone);
    }

    [Fact]
    public async Task The_audit_chain_is_verified_too()
    {
        using var env = await EnvWithAsync(10);
        var audit = env.Services.GetRequiredService<AuditLog>();
        for (var i = 0; i < 5; i++) await audit.WriteAsync("admin", "x.y", $"d{i}");
        Assert.Empty((await FullAsync(env)).Breaks);

        env.Exec("UPDATE AuditLogs SET Detail = 'changed' WHERE ChainSeq = 3");
        var b = Assert.Single((await FullAsync(env)).Breaks);
        Assert.Equal(("audit", "altered", 3L), (b.Chain, b.Kind, b.FromSeq));
    }

    [Fact]
    public async Task A_break_is_reported_once_and_again_after_24_hours()
    {
        using var env = await EnvWithAsync();
        var svc = env.NewService();
        env.Exec("UPDATE AccessRecords SET UserName = 'x' WHERE ChainSeq = 20");

        await FullAsync(env, svc);
        var first = Assert.Single(env.Notifications);
        Assert.Equal("Integrity", first.Type);
        Assert.True(first.High);
        Assert.Equal("integrity.alertTitle", first.Title);
        Assert.Equal(["access", "altered", 20L], first.Args.Take(3).ToArray());

        await FullAsync(env, svc);   // the same finding: no second alert
        Assert.Single(env.Notifications);
        Assert.Equal(1, (await svc.GetSummaryAsync()).Breaks);

        env.Now = env.Now.AddHours(25);   // still open: reminder
        await FullAsync(env, svc);
        Assert.Equal(2, env.Notifications.Count);
    }

    [Fact]
    public async Task Break_alerts_and_the_operation_log_use_integrity_break()
    {
        using var env = await EnvWithAsync();
        env.Exec("UPDATE AccessRecords SET UserName = 'x' WHERE ChainSeq = 20");
        await FullAsync(env);
        using var scope = env.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Contains(db.AuditLogs.Select(l => l.Action).ToList(), a => a == "integrity.break");
        Assert.Contains(db.AuditLogs.Select(l => l.Action).ToList(), a => a == "integrity.verify");
    }

    [Fact]
    public async Task Incremental_checks_only_the_new_rows_and_finds_a_change_among_them()
    {
        using var env = await EnvWithAsync();
        var svc = env.NewService();
        await FullAsync(env, svc);

        await env.AddRecordsAsync(30, first: 1000);
        var inc = await svc.VerifyAsync(full: false, default);
        Assert.Equal(31, inc!.RowsDone);   // 30 records and the operation-log entry the full check wrote
        Assert.Empty(inc.Breaks);

        await env.AddRecordsAsync(10, first: 2000);
        env.Exec("UPDATE AccessRecords SET FileName = 'z' WHERE ChainSeq = 135");
        inc = await svc.VerifyAsync(full: false, default);
        var b = Assert.Single(inc!.Breaks);
        Assert.Equal((135L, "altered"), (b.FromSeq, b.Kind));
        Assert.Equal("broken", (await svc.GetSummaryAsync()).State);
    }

    [Fact]
    public async Task Accepting_a_break_starts_the_chain_again_and_keeps_the_history()
    {
        using var env = await EnvWithAsync();
        var svc = env.NewService();
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 40");
        var b = Assert.Single((await FullAsync(env, svc)).Breaks);

        Assert.Equal("access", await svc.AcceptAsync("access", b.Id, "restored from backup", "admin", default));
        Assert.Equal("ok", (await svc.GetSummaryAsync()).State);

        await env.AddRecordsAsync(5, first: 500);
        Assert.Empty((await FullAsync(env, svc)).Breaks);
        var status = await svc.GetStatusAsync();
        var kept = Assert.Single(status.Chains.First(c => c.Chain == "access").Breaks);
        Assert.True(kept.Accepted);
        Assert.Equal("admin", kept.AcceptedBy);
        Assert.Contains(status.Chains.First(c => c.Chain == "access").Checkpoints, c => c.Reason == "accepted");
        Assert.Null(await svc.AcceptAsync("access", null, null, "admin", default));   // nothing left to accept

        using var scope = env.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        Assert.Contains(db.AuditLogs.Select(l => l.Action).ToList(), a => a == "integrity.accept");
    }

    [Fact]
    public async Task Accepting_after_a_new_key_starts_a_new_epoch()
    {
        using var env = await EnvWithAsync(30);
        var otherKey = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        var other = new ChainInterceptor(otherKey);
        var svc = env.NewService(other);
        await FullAsync(env, svc);
        Assert.Equal("access", await svc.AcceptAsync("access", null, "key replaced", "admin", default));

        // New rows are chained with the new key from the head
        var options = new DbContextOptionsBuilder<AccessDbContext>()
            .UseSqlite($"Data Source={env.DbPath}").AddInterceptors(other).Options;
        using (var db = new AccessDbContext(options))
        {
            db.AccessRecords.Add(ChainEnv.Rec(1));
            await db.SaveChangesAsync();
        }
        var run = await FullAsync(env, svc);
        Assert.DoesNotContain(run.Breaks, b => b.Chain == "access");
        Assert.Equal(1, run.RowsDone);
    }

    [Fact]
    public async Task A_database_older_than_the_last_known_head_is_found()
    {
        using var env = await EnvWithAsync();
        var svc = env.NewService();
        await FullAsync(env, svc);
        await svc.UpdateHeadFileAsync(false, default);   // the head file now says seq 100

        // Cut the tail off and make the head match (a consistent, older database)
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq > 80");
        env.Exec("UPDATE ChainHeads SET Seq = 80, Hash = (SELECT ChainHash FROM AccessRecords WHERE ChainSeq = 80) WHERE Chain = 'access'");
        var run = await FullAsync(env, svc);
        var b = Assert.Single(run.Breaks);
        Assert.Equal("headRollback", b.Kind);
        Assert.Equal((81L, 100L), (b.FromSeq, b.ToSeq));
    }

    [Fact]
    public async Task The_head_file_follows_new_rows_but_never_goes_back()
    {
        using var env = await EnvWithAsync(10);
        var svc = env.NewService();
        await svc.UpdateHeadFileAsync(false, default);
        Assert.Contains("\"seq\":10", File.ReadAllText(Path.Combine(env.Dir, "chain-head.json")));
        await env.AddRecordsAsync(5, first: 100);
        await svc.UpdateHeadFileAsync(false, default);
        Assert.Contains("\"seq\":15", File.ReadAllText(Path.Combine(env.Dir, "chain-head.json")));

        // A hand-edited head file is ignored (its MAC does not match)
        var path = Path.Combine(env.Dir, "chain-head.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace("\"seq\":15", "\"seq\":99"));
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq > 12");
        env.Exec("UPDATE ChainHeads SET Seq = 12, Hash = (SELECT ChainHash FROM AccessRecords WHERE ChainSeq = 12) WHERE Chain = 'access'");
        Assert.Empty((await FullAsync(env, svc)).Breaks);
    }
}
