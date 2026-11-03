using System.Text.Json;
using System.Text.RegularExpressions;
using FileAccessMonitor.Data;
using FileAccessMonitor.Services;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

public class AnchorTests
{
    private const string LinePattern =
        @"^FAM-ANCHOR v1 server=\S+ chain=access seq=\d+ hash=[0-9a-f]{64} time=\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ audit-seq=\d+ audit-hash=[0-9a-f]{64}$";

    [Fact]
    public async Task The_anchor_line_has_the_agreed_format_and_is_in_the_summary()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(3);
        var svc = env.NewService();
        var anchor = await svc.CreateAnchorAsync();
        Assert.Matches(LinePattern, anchor!.Line);
        Assert.Contains("seq=3 ", anchor.Line);
        Assert.Contains(Convert.ToHexString(env.Head("access").Hash).ToLowerInvariant(), anchor.Line);
        Assert.Equal(anchor.Line.Split(" time=")[0], (await svc.GetSummaryAsync()).AnchorLine!.Split(" time=")[0]);
    }

    [Fact]
    public async Task The_daily_anchor_goes_to_the_system_log_and_the_operation_log_but_not_to_the_channels_by_default()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(2);
        var svc = env.NewService();
        Assert.True(await svc.WriteAnchorAsync(default));

        var line = Assert.Single(env.OsLog);
        Assert.Matches(LinePattern, line);
        Assert.Empty(env.Notifications);
        using var scope = env.Scopes.CreateScope();
        var logged = scope.ServiceProvider.GetRequiredService<AccessDbContext>().AuditLogs.Single(l => l.Action == "integrity.anchor");
        Assert.Equal(line, logged.Detail);

        env.AnchorNotify = true;
        await svc.WriteAnchorAsync(default);
        var sent = Assert.Single(env.Notifications);
        Assert.Equal(("IntegrityAnchor", false), (sent.Type, sent.High));
    }

    [Fact]
    public async Task A_matching_anchor_checks_out_and_a_changed_record_does_not()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(10);
        var svc = env.NewService();
        var anchor = (await svc.CreateAnchorAsync())!;
        await env.AddRecordsAsync(5, first: 100);   // the chain grew since the anchor: still fine

        var ok = await svc.CheckAnchorAsync(anchor.Line);
        Assert.True(ok!.Ok);
        Assert.All(ok.Chains, c => Assert.Equal("match", c.Result));

        // The stored hash of the anchored record is changed (needs the key to do it right: here it is just different)
        env.Exec("UPDATE AccessRecords SET ChainHash = zeroblob(32) WHERE ChainSeq = 10");
        var bad = await svc.CheckAnchorAsync(anchor.Line);
        Assert.False(bad!.Ok);
        Assert.Equal("mismatch", bad.Chains.Single(c => c.Chain == "access").Result);
    }

    [Fact]
    public async Task An_anchor_ahead_of_the_database_means_an_older_database()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(10);
        var svc = env.NewService();
        var anchor = (await svc.CreateAnchorAsync())!;
        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq > 7");
        env.Exec("UPDATE ChainHeads SET Seq = 7, Hash = (SELECT ChainHash FROM AccessRecords WHERE ChainSeq = 7) WHERE Chain = 'access'");
        var result = await svc.CheckAnchorAsync(anchor.Line);
        Assert.False(result!.Ok);
        Assert.Equal("ahead", result.Chains.Single(c => c.Chain == "access").Result);
    }

    [Fact]
    public async Task An_anchored_record_deleted_by_retention_is_reported_as_deleted_not_as_a_mismatch()
    {
        using var env = new ChainEnv();
        var old = DateTime.UtcNow.AddDays(-10);
        await env.AddRecordsAsync(old, old, old, DateTime.UtcNow);
        var svc = env.NewService();
        var anchor = (await svc.CreateAnchorAsync())!;   // seq 4

        await env.AddRecordsAsync(old, old, old, old);   // late old rows: seq 5-8 after the kept seq 4
        await env.NewRetention().CleanupAsync(DateTime.UtcNow.AddDays(-5), default);   // deletes 1-3 only
        Assert.True((await svc.CheckAnchorAsync(anchor.Line))!.Ok);

        // Everything goes: the anchored seq 4 is covered by the checkpoint at the head
        await env.NewRetention().CleanupAsync(DateTime.UtcNow.AddDays(1), default);
        var result = await svc.CheckAnchorAsync(anchor.Line);
        Assert.True(result!.Ok);
        Assert.Equal("deleted", result.Chains.Single(c => c.Chain == "access").Result);
    }

    [Fact]
    public async Task The_downloaded_file_is_checked_with_its_mac()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(4);
        var svc = env.NewService();
        var a = (await svc.CreateAnchorAsync())!;
        var file = JsonSerializer.Serialize(new { format = "fam-anchor-v1", line = a.Line, mac = a.Mac });

        var ok = await svc.CheckAnchorAsync(file);
        Assert.True(ok!.Ok);
        Assert.True(ok.MacValid);

        var forged = await svc.CheckAnchorAsync(JsonSerializer.Serialize(new { line = a.Line.Replace("seq=4", "seq=3"), mac = a.Mac }));
        Assert.False(forged!.Ok);
        Assert.False(forged.MacValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("hello")]
    [InlineData("{not json")]
    [InlineData("{\"line\":\"nothing\"}")]
    public async Task Text_that_is_not_an_anchor_is_refused(string text)
    {
        using var env = new ChainEnv();
        Assert.Null(await env.NewService().CheckAnchorAsync(text));
    }

    [Fact]
    public async Task A_line_inside_other_text_is_found()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(2);
        var svc = env.NewService();
        var a = (await svc.CreateAnchorAsync())!;
        var result = await svc.CheckAnchorAsync($"Event 1100, source FileAccessMonitor\r\n{a.Line}\r\nmore text");
        Assert.True(result!.Ok);
        Assert.Matches(new Regex(@"^\S+$"), result.Server!);
    }
}
