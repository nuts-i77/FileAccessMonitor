using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Configuration;

namespace FileAccessMonitor.Tests;

public class AgentTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-agent-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static AccessRecord Rec(string name) => new()
    {
        FilePath = $@"D:\Share\{name}", FileName = name, FolderPath = @"D:\Share", UserName = @"CORP\sato",
        AccessType = "Read", AccessTime = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), ServerName = "ignored",
    };

    [Fact]
    public void Connection_string_round_trips_and_rejects_garbage()
    {
        var c = new AgentConnection("https://monitor:8443", "AB12", "code-_x");
        Assert.Equal(c, AgentConnection.Parse(" " + c + " "));
        Assert.StartsWith("FAM1.", c.ToString());
        Assert.Null(AgentConnection.Parse("FAM1.not-base64!"));
        Assert.Null(AgentConnection.Parse("hello"));
        Assert.Null(AgentConnection.Parse(new AgentConnection("http://monitor:8443", "AB12", "c").ToString())); // HTTPS only
    }

    [Fact]
    public void Secrets_are_checked_against_their_hash()
    {
        var secret = AgentSecrets.NewSecret();
        Assert.True(AgentSecrets.Matches(secret, AgentSecrets.Hash(secret)));
        Assert.False(AgentSecrets.Matches(secret + "x", AgentSecrets.Hash(secret)));
    }

    [Fact]
    public void Server_name_comes_from_the_registration()
    {
        var r = AgentRecord.From(Rec("a.txt")).ToRecord("FS01");
        Assert.Equal(("FS01", @"D:\Share\a.txt", DateTimeKind.Utc), (r.ServerName, r.FilePath, r.AccessTime.Kind));
    }

    [Fact]
    public void Agent_port_is_on_unless_turned_off()
    {
        static Microsoft.Extensions.Configuration.IConfiguration Config(params (string, string)[] values) =>
            new Microsoft.Extensions.Configuration.ConfigurationBuilder()
                .AddInMemoryCollection(values.ToDictionary(v => v.Item1, v => (string?)v.Item2)).Build();

        Assert.True(AgentEndpoint.Enabled(Config()));
        Assert.True(AgentEndpoint.Enabled(Config(("Agents:Enabled", "true")))); // written by v1.5
        Assert.False(AgentEndpoint.Enabled(Config(("Agents:Enabled", "false"))));
        Assert.Equal(8443, AgentEndpoint.Port(Config()));
        Assert.Equal(9443, AgentEndpoint.Port(Config(("Agents:Port", "9443"))));
    }

    [Fact]
    public void Offline_agents_are_reported_once_and_again_when_back()
    {
        var t0 = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        var tracker = new AgentStatusTracker();
        AgentStatus Seen(int minutesAgo, DateTime now, bool disabled = false) => new("FS01", now.AddMinutes(-minutesAgo), disabled);

        // Right after the monitoring server starts, silent agents are not judged yet
        Assert.Empty(tracker.Check([Seen(60, t0.AddMinutes(5))], 15, t0, t0.AddMinutes(5)));
        var now = t0.AddMinutes(20);
        Assert.Equal([true], tracker.Check([Seen(16, now)], 15, t0, now).Select(c => c.Offline));
        Assert.Empty(tracker.Check([Seen(17, now.AddMinutes(1))], 15, t0, now.AddMinutes(1))); // only once
        Assert.Equal([false], tracker.Check([Seen(0, now.AddMinutes(2))], 15, t0, now.AddMinutes(2)).Select(c => c.Offline));
        // Disabled agents and a setting of 0 report nothing
        Assert.Empty(tracker.Check([Seen(30, now.AddMinutes(30), disabled: true)], 15, t0, now.AddMinutes(30)));
        Assert.Empty(tracker.Check([Seen(30, now.AddMinutes(30))], 0, t0, now.AddMinutes(30)));
    }

    [Fact]
    public void Alerts_name_the_file_servers_the_accesses_happened_on()
    {
        var d = new AlertDetector(new AlertRules(DeleteThreshold: 2, WriteThreshold: 0, WindowMinutes: 5, CooldownMinutes: 30));
        var a = Rec("a.txt"); a.AccessType = "Delete"; a.ServerName = "FS02";
        var b = Rec("b.txt"); b.AccessType = "Delete"; b.ServerName = "FS01";
        Assert.Equal("FS01, FS02", Assert.Single(d.Process([a, b])).ServerName);
    }

    [Fact]
    public async Task Jobs_reach_their_agent_and_only_it_can_answer()
    {
        var jobs = new AgentJobs();
        var run = jobs.RunAsync("agent1", "scan", new() { ["folder"] = @"D:\Share" }, TimeSpan.FromSeconds(5), default);

        Assert.Null(await jobs.NextAsync("agent2", TimeSpan.FromMilliseconds(50), default));
        var job = await jobs.NextAsync("agent1", TimeSpan.FromSeconds(1), default);
        Assert.Equal(("scan", @"D:\Share"), (job!.Type, job.Args["folder"]!.GetValue<string>()));

        Assert.False(jobs.Complete("agent2", job.Id, new() { ["exists"] = false }));
        Assert.True(jobs.Complete("agent1", job.Id, new() { ["exists"] = true }));
        Assert.True((await run)["exists"]!.GetValue<bool>());
    }

    [Fact]
    public async Task A_job_nobody_answers_times_out_and_is_not_handed_out_later()
    {
        var jobs = new AgentJobs();
        await Assert.ThrowsAsync<TimeoutException>(() =>
            jobs.RunAsync("agent1", "scan", [], TimeSpan.FromMilliseconds(50), default));
        Assert.Null(await jobs.NextAsync("agent1", TimeSpan.FromMilliseconds(50), default));
    }

    [Fact]
    public void Agent_listing_is_marked_against_the_records()
    {
        var ticks = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;
        var result = new System.Text.Json.Nodes.JsonObject
        {
            ["scanned"] = 2, ["truncated"] = false,
            ["files"] = new System.Text.Json.Nodes.JsonArray(
                new System.Text.Json.Nodes.JsonArray(@"D:\Share\a.mp4", 10L, ticks),
                new System.Text.Json.Nodes.JsonArray(@"D:\Share\b.mp4", 20L, ticks)),
        };
        var used = new HashSet<string>([@"d:\share\A.MP4"], StringComparer.OrdinalIgnoreCase);
        var (files, scanned, truncated) = Controllers.UnusedFilesController.FromAgentListing(result, used);
        Assert.Equal((2, false), (scanned, truncated));
        Assert.Equal([true, false], files.Select(f => f.Used));
        Assert.Equal((20L, DateTimeKind.Utc), (files[1].Size, files[1].ModifiedUtc.Kind));
    }

    [Fact]
    public async Task Outbox_keeps_batches_in_order_across_restarts()
    {
        var sink = new RemoteRecordSink(new AgentOutbox(_dir), NullLogger<RemoteRecordSink>.Instance);
        Assert.True(await sink.SaveAsync([Rec("a.txt"), Rec("b.txt")], "100"));
        Assert.True(await sink.SaveAsync([], "120")); // position only
        await sink.ReportGapAsync("missedRecords=1-2", "gap.overwritten", 2L, 1L, 2L);
        Assert.True(await sink.SaveAsync([Rec("c.txt")], "130"));

        var reopened = new AgentOutbox(_dir); // service restart
        Assert.Equal("130", reopened.Position);
        Assert.Equal("130", await new RemoteRecordSink(reopened, NullLogger<RemoteRecordSink>.Instance).LoadPositionAsync());
        Assert.Equal(3, reopened.Count);

        var first = reopened.Oldest()!.Value;
        Assert.Equal((1L, 2), (first.Batch.Seq, first.Batch.Records!.Count));
        reopened.Remove(first.Path);
        var gap = reopened.Oldest()!.Value;
        Assert.Equal((2L, "gap.overwritten"), (gap.Batch.Seq, gap.Batch.Gap!.MessageKey));
        Assert.Equal(["2", "1", "2"], gap.Batch.Gap.Args);
        reopened.Remove(gap.Path);

        // Numbering continues after sent batches were removed
        Assert.True(reopened.Add(new AgentBatch { Records = [] }));
        var seqs = new List<long>();
        while (reopened.Oldest() is { } next) { seqs.Add(next.Batch.Seq); reopened.Remove(next.Path); }
        Assert.Equal([3L, 4L], seqs);
    }
}
