using System.Text.Json;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// 1.11: a full agent outbox pauses the collection instead of dropping records
public class AgentOutboxFullTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-outboxfull-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static AccessRecord Rec(string name) => new()
    {
        FilePath = $@"D:\Share\{name}", FileName = name, FolderPath = @"D:\Share", UserName = @"CORP\sato",
        AccessType = "Read", AccessTime = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc),
    };

    private RemoteRecordSink Sink(AgentOutbox outbox) =>
        new(outbox, NullLogger<RemoteRecordSink>.Instance) { FullRetryInterval = TimeSpan.FromMilliseconds(20) };

    [Fact]
    public async Task A_full_outbox_makes_the_sink_wait_and_keeps_the_position_until_there_is_room()
    {
        var outbox = new AgentOutbox(_dir, maxBytes: 1);   // full after the first batch
        var sink = Sink(outbox);
        Assert.True(await sink.SaveAsync([Rec("a.txt")], "100"));
        Assert.True(outbox.IsFull);

        var second = sink.SaveAsync([Rec("b.txt")], "200");
        await Task.Delay(200);
        Assert.False(second.IsCompleted);          // waiting, not dropped and not answered false
        Assert.Equal("100", outbox.Position);      // the collector has not moved on
        Assert.Equal(1, outbox.Count);

        outbox.Remove(outbox.Oldest()!.Value.Path); // the sender delivered a batch
        Assert.True(await second.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Equal("200", outbox.Position);
        Assert.Equal(1, outbox.Count);
        Assert.Equal("b.txt", outbox.Oldest()!.Value.Batch.Records![0].FileName);
    }

    [Fact]
    public async Task The_wait_can_be_cancelled_and_leaves_the_position_alone()
    {
        var outbox = new AgentOutbox(_dir, maxBytes: 1);
        var sink = Sink(outbox);
        await sink.SaveAsync([Rec("a.txt")], "100");

        using var stop = new CancellationTokenSource();
        var waiting = sink.SaveAsync([Rec("b.txt")], "200", stop.Token);
        await Task.Delay(100);
        stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
        Assert.Equal("100", outbox.Position);
        Assert.Equal(1, outbox.Count);
    }

    [Fact]
    public async Task A_position_only_save_and_a_gap_notice_go_through_a_full_outbox()
    {
        var outbox = new AgentOutbox(_dir, maxBytes: 1);
        var sink = Sink(outbox);
        await sink.SaveAsync([Rec("a.txt")], "100");

        Assert.True(await sink.SaveAsync([], "150").WaitAsync(TimeSpan.FromSeconds(5)));
        await sink.ReportGapAsync("missedRecords=1-2", "gap.overwritten", 2L, 1L, 2L);
        Assert.Equal("150", outbox.Position);
        Assert.Equal(2, outbox.Count);              // the gap notice is not lost
    }

    [Fact]
    public void The_outbox_reports_its_size_and_whether_it_is_full()
    {
        var outbox = new AgentOutbox(_dir, maxBytes: 100_000);
        Assert.False(outbox.IsFull);
        Assert.Equal(0, outbox.Bytes);
        outbox.Add(new AgentBatch { Records = [AgentRecord.From(Rec("a.txt"))] });
        Assert.True(outbox.Bytes > 0);
        Assert.Equal(outbox.Bytes, new AgentOutbox(_dir).Bytes);   // counted again after a restart
    }

    // ---- heartbeat

    [Fact]
    public void An_older_agent_heartbeat_without_the_field_means_not_full()
    {
        var old = JsonSerializer.Deserialize<HeartbeatRequest>("""{"version":"1.10.4","outboxCount":3}""", new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Null(old.OutboxFull);
        var current = JsonSerializer.Deserialize<HeartbeatRequest>("""{"version":"1.11.0","outboxCount":3,"outboxFull":true,"outboxBytes":2147483700}""", new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        Assert.Equal((true, 2147483700L), (current.OutboxFull, current.OutboxBytes));
    }

    [Fact]
    public async Task The_server_stores_what_the_agent_reports_and_clears_it_when_the_field_is_missing()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();
        using var db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(conn).Options);
        db.Database.EnsureCreated();
        var secret = AgentSecrets.NewSecret();
        db.Agents.Add(new Agent { Id = "a1", Name = "FS01", KeyHash = AgentSecrets.Hash(secret), CreatedAt = DateTime.UtcNow });
        db.SaveChanges();

        var config = new ConfigurationBuilder().Build();
        async Task Beat(HeartbeatRequest req)
        {
            var http = new DefaultHttpContext();
            http.Connection.LocalPort = AgentEndpoint.Port(config);
            http.Request.Scheme = "https";
            http.Request.Headers.Authorization = "Bearer a1." + secret;
            var controller = new AgentApiController(db, null!, null!, config, NullLogger<AgentApiController>.Instance, new LocalCollectorState())
            {
                ControllerContext = new ControllerContext { HttpContext = http },
            };
            Assert.IsType<OkObjectResult>(await controller.Heartbeat(req));
        }

        await Beat(new HeartbeatRequest("1.11.0", 40, true, "Windows", OutboxFull: true, OutboxBytes: 2_200_000_000));
        var agent = db.Agents.AsNoTracking().Single();
        Assert.Equal((true, 2_200_000_000L), (agent.OutboxFull, agent.OutboxBytes));

        await Beat(new HeartbeatRequest("1.10.4", 0, true, "Windows"));   // an older agent, or one that has room again
        agent = db.Agents.AsNoTracking().Single();
        Assert.Equal((false, 0L), (agent.OutboxFull, agent.OutboxBytes));
    }

    [Fact]
    public async Task The_agent_column_is_added_to_an_older_agents_table()
    {
        await using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();
        using var db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(conn).Options);
        db.Database.EnsureCreated();
        await db.Database.ExecuteSqlRawAsync(@"ALTER TABLE ""Agents"" DROP COLUMN ""OutboxFull""");
        await db.Database.ExecuteSqlRawAsync(@"ALTER TABLE ""Agents"" DROP COLUMN ""OutboxBytes""");

        await SchemaV111.ApplyAsync(db);
        await SchemaV111.ApplyAsync(db);

        Assert.Empty(db.Agents.ToList());   // the model's columns exist again
    }

    [Fact]
    public void A_full_outbox_is_reported_once_and_again_when_it_has_room()
    {
        var tracker = new AgentOutboxTracker();
        AgentOutboxState State(bool full) => new("FS01", full, full ? 2_200_000_000 : 0);

        Assert.Empty(tracker.Check([State(false)]));
        Assert.Equal([true], tracker.Check([State(true)]).Select(c => c.Full));
        Assert.Empty(tracker.Check([State(true)]));                                   // only once
        Assert.Equal([false], tracker.Check([State(false)]).Select(c => c.Full));
        Assert.Equal([true], tracker.Check([State(true)]).Select(c => c.Full));       // full again
        Assert.Empty(tracker.Check([]));                                              // removed: forgotten
        Assert.Equal([true], tracker.Check([State(true)]).Select(c => c.Full));
    }
}
