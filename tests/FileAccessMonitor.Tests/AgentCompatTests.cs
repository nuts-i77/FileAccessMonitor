using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// 1.9 agents talk to 1.8 servers (protocol 1) and 1.9 servers (protocol 2)
public class AgentCompatTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-compat-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private static readonly DateTime T = new(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);

    private static AccessRecord Rec(string name, string type = "Read", bool denied = false, string? newPath = null, string? detail = null) => new()
    {
        FilePath = $@"D:\Share\{name}", FileName = name, FolderPath = @"D:\Share", UserName = @"CORP\sato",
        AccessType = type, AccessTime = T, Denied = denied, NewPath = newPath, Detail = detail,
    };

    [Fact]
    public void Record_round_trips_with_the_new_fields()
    {
        var r = AgentRecord.From(Rec("a.txt", "Rename", newPath: @"D:\Share\b.txt"));
        var back = JsonSerializer.Deserialize<AgentRecord>(JsonSerializer.Serialize(r))!.ToRecord("FS01");
        Assert.Equal((false, @"D:\Share\b.txt", null), (back.Denied, back.NewPath, back.Detail));

        var denied = JsonSerializer.Deserialize<AgentRecord>(JsonSerializer.Serialize(AgentRecord.From(Rec("a.txt", denied: true))))!;
        Assert.True(denied.ToRecord("FS01").Denied);
        var perm = JsonSerializer.Deserialize<AgentRecord>(JsonSerializer.Serialize(AgentRecord.From(Rec("a.txt", "Permission", detail: "+ allow X: Read"))))!;
        Assert.Equal("+ allow X: Read", perm.ToRecord("FS01").Detail);
    }

    [Fact]
    public void An_old_agents_record_without_the_new_fields_still_reads()
    {
        var old = JsonSerializer.Deserialize<AgentRecord>("""
            {"FilePath":"D:\\Share\\a.txt","FileName":"a.txt","FolderPath":"D:\\Share","UserName":"u","AccessType":"Read",
             "AccessTime":"2026-11-03T00:00:00Z","IsFolder":false}
            """)!.ToRecord("FS01");
        Assert.Equal((false, null, null), (old.Denied, old.NewPath, old.Detail));
    }

    [Fact]
    public void Limits_apply_to_the_new_text_fields()
    {
        var r = AgentRecord.From(Rec("a.txt", detail: new string('x', 5000), newPath: new string('y', 5000))).ToRecord("FS01");
        Assert.Equal((2000, 2000), (r.Detail!.Length, r.NewPath!.Length));
    }

    private static AgentBatch Batch() => new()
    {
        Seq = 7,
        Records =
        [
            AgentRecord.From(Rec("read.txt")),
            AgentRecord.From(Rec("denied.txt", denied: true)),
            AgentRecord.From(Rec("new.txt", "Create")),
            AgentRecord.From(Rec("perm.txt", "Permission", detail: "owner: A -> B")),
            AgentRecord.From(Rec("old.txt", "Rename", newPath: @"D:\Share\moved.txt")),
        ],
        Gap = new AgentGap { MessageKey = "gap.overwritten" },
    };

    [Fact]
    public void Protocol_2_sends_everything_unchanged()
    {
        var batch = Batch();
        Assert.Same(batch, AgentProtocol.ForServer(batch, 2));
    }

    [Fact]
    public void Protocol_1_gets_what_a_1_8_server_understands()
    {
        var batch = Batch();
        var sent = AgentProtocol.ForServer(batch, 1);

        Assert.Equal(["read.txt", "new.txt", "old.txt"], sent.Records!.Select(r => r.FileName));
        Assert.Equal(["Read", "Write", "Rename"], sent.Records!.Select(r => r.AccessType));
        Assert.All(sent.Records!, r => Assert.False(r.Denied));
        Assert.All(sent.Records!, r => Assert.Null(r.NewPath));
        Assert.All(sent.Records!, r => Assert.Null(r.Detail));
        Assert.Equal((7L, "gap.overwritten"), (sent.Seq, sent.Gap!.MessageKey));
    }

    [Fact]
    public void Conversion_leaves_the_batch_itself_alone()
    {
        var batch = Batch();
        var json = JsonSerializer.Serialize(batch);
        AgentProtocol.ForServer(batch, 1);
        Assert.Equal(json, JsonSerializer.Serialize(batch));
        Assert.Equal(5, batch.Records!.Count);
    }

    [Fact]
    public void A_gap_only_batch_passes_and_all_denied_batch_becomes_empty()
    {
        var gap = new AgentBatch { Seq = 1, Gap = new AgentGap { MessageKey = "x" } };
        Assert.Same(gap, AgentProtocol.ForServer(gap, 1));
        var denied = new AgentBatch { Seq = 2, Records = [AgentRecord.From(Rec("d.txt", denied: true))] };
        var sent = AgentProtocol.ForServer(denied, 1);
        Assert.Empty(sent.Records!);
        Assert.Equal(2, sent.Seq);
    }

    [Fact]
    public async Task The_outbox_file_keeps_the_full_data_after_conversion()
    {
        var outbox = new AgentOutbox(_dir);
        var sink = new RemoteRecordSink(outbox, NullLogger<RemoteRecordSink>.Instance);
        Assert.True(await sink.SaveAsync([Rec("d.txt", denied: true), Rec("n.txt", "Create")], "1"));

        var queued = outbox.Oldest()!.Value.Batch;
        Assert.DoesNotContain(AgentProtocol.ForServer(queued, 1).Records!, r => r.Denied);
        // a later (upgraded) server gets the same queued batch complete
        var again = outbox.Oldest()!.Value.Batch;
        Assert.Equal(["Read", "Create"], again.Records!.Select(r => r.AccessType));
        Assert.True(again.Records![0].Denied);
    }

    [Fact]
    public void The_server_announces_protocol_2()
    {
        Assert.Equal(2, AgentProtocol.Version);
    }

    // ---- database ----

    [Fact]
    public async Task Schema_v19_adds_the_columns_and_index_to_an_old_database_once()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        conn.Open();
        using (var create = conn.CreateCommand())
        {
            create.CommandText = """
                CREATE TABLE "AccessRecords" ("Id" INTEGER PRIMARY KEY AUTOINCREMENT, "FilePath" TEXT NOT NULL, "FileName" TEXT NOT NULL,
                  "FolderPath" TEXT NOT NULL, "UserName" TEXT NOT NULL, "AccessType" TEXT NOT NULL, "IsFolder" INTEGER NOT NULL DEFAULT 0,
                  "ServerName" TEXT NOT NULL DEFAULT '', "AccessTime" TEXT NOT NULL, "ClientIp" TEXT NULL, "ClientMachine" TEXT NULL);
                INSERT INTO "AccessRecords" ("FilePath","FileName","FolderPath","UserName","AccessType","AccessTime")
                  VALUES ('D:\a.txt','a.txt','D:\','u','Read','2026-11-01 00:00:00');
                """;
            create.ExecuteNonQuery();
        }
        await using var db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(conn).Options);

        await SchemaV19.ApplyAsync(db);
        await SchemaV19.ApplyAsync(db); // idempotent
        await SchemaV110.ApplyAsync(db);   // the model also has the 1.10 columns
        await SchemaV110.ApplyAsync(db);

        var columns = await db.Database.SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_table_info('AccessRecords')").ToListAsync();
        Assert.Contains("Denied", columns);
        Assert.Contains("NewPath", columns);
        Assert.Contains("Detail", columns);
        var indexes = await db.Database.SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_index_list('AccessRecords')").ToListAsync();
        Assert.Single(indexes, i => i == "IX_AccessRecords_Denied");
        // the old row reads with the defaults
        var row = await db.AccessRecords.SingleAsync();
        Assert.Equal((false, null, null), (row.Denied, row.NewPath, row.Detail));
    }

    // ---- GUI / API support ----

    [Fact]
    public void Csv_headers_have_a_name_in_both_languages()
    {
        foreach (var key in new[] { "csv.result", "csv.resultOk", "csv.resultDenied", "csv.newPath", "csv.detail" })
        {
            Assert.True(Messages.En.ContainsKey(key), key);
            Assert.True(Messages.Ja.ContainsKey(key), key);
        }
    }

    [Fact]
    public void Alert_messages_exist_in_both_languages()
    {
        foreach (var key in new[] { "alert.deniedTitle", "alert.ransomwareTitle", "alert.rule.extension", "alert.rule.burst",
                     "alert.rule.note", "alert.highPriority", "alert.detail" })
        {
            Assert.True(Messages.En.ContainsKey(key), key);
            Assert.True(Messages.Ja.ContainsKey(key), key);
        }
        Assert.Equal("[HIGH PRIORITY]", Messages.GetIn("en", "alert.highPriority"));
        Assert.Equal("【緊急】", Messages.GetIn("ja", "alert.highPriority"));
    }

    [Fact]
    public void Recording_settings_keep_the_denied_switch_and_settings_this_class_does_not_know()
    {
        var node = JsonNode.Parse("""{ "RecordDenied": false, "UsnCorrelation": false, "MergeReadMinutes": 3 }""");
        var s = RecordingSettings.FromNode(node);
        Assert.False(s.RecordDenied);
        var saved = JsonSerializer.SerializeToNode(s)!.AsObject();
        Assert.False(saved["UsnCorrelation"]!.GetValue<bool>());
        Assert.False(saved["RecordDenied"]!.GetValue<bool>());
        Assert.True(RecordingSettings.FromNode(null).RecordDenied);
    }

    [Fact]
    public void Audit_applied_notice_follows_add_remove_and_server()
    {
        var root = new JsonObject();
        Assert.Empty(AuditApplied.For(root, "FS01"));

        AuditApplied.Set(root, "FS01", @"D:\Share");
        AuditApplied.Set(root, "FS02", @"D:\Share");
        AuditApplied.Set(root, "FS01", @"D:\share"); // same folder, other spelling: one entry
        var fs01 = AuditApplied.For(root, "FS01");
        Assert.Equal(AuditApplied.CurrentVersion, fs01[@"D:\Share"]);
        Assert.Equal(19, fs01[@"d:\SHARE"]);
        Assert.Single(fs01);
        Assert.Single(AuditApplied.For(root, "FS02"));

        AuditApplied.Remove(root, "FS01", @"d:\share");
        Assert.Empty(AuditApplied.For(root, "FS01"));
        Assert.Single(AuditApplied.For(root, "FS02"));
    }

    [Fact]
    public void Permission_is_a_valid_event_type_and_new_folders_get_it_by_default()
    {
        var root = JsonNode.Parse("""
            { "MonitoredPaths": [ "E:\\Old", { "path": "D:\\New", "eventTypes": ["Read", "Permission"] } ] }
            """)!.AsObject();
        var (configs, _) = SettingsController.ParseSettings(root);
        Assert.Equal(["Read", "Write", "Delete"], configs[0].EventTypes);   // existing folders keep what they had
        Assert.Equal(["Read", "Permission"], configs[1].EventTypes);

        var defaults = (string[])typeof(SettingsController)
            .GetField("DefaultEventTypes", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.GetValue(null)!;
        Assert.Equal(["Read", "Write", "Delete", "Permission"], defaults);
    }

    // The GUI language files are JS single-quoted literals: an unescaped apostrophe breaks the whole file
    [Theory]
    [InlineData("en.js")]
    [InlineData("ja.js")]
    public void Language_file_lines_are_well_formed(string file)
    {
        var path = FindRepoFile(Path.Combine("wwwroot", "lang", file));
        foreach (var line in File.ReadLines(path))
        {
            if (!Regex.IsMatch(line, @"^\s+'[\w.]+':")) continue;
            Assert.Matches(@"^\s+'[\w.]+': '(?:[^'\\]|\\.)*',$", line);
        }
    }

    [Fact]
    public void Gui_language_files_have_the_same_keys()
    {
        static string[] Keys(string file) => File.ReadLines(FindRepoFile(Path.Combine("wwwroot", "lang", file)))
            .Select(l => Regex.Match(l, @"^\s+'([\w.]+)':")).Where(m => m.Success).Select(m => m.Groups[1].Value).Order().ToArray();
        Assert.Equal(Keys("en.js"), Keys("ja.js"));
    }

    [Fact]
    public void Every_key_the_gui_uses_for_the_new_features_exists()
    {
        var en = File.ReadAllText(FindRepoFile(Path.Combine("wwwroot", "lang", "en.js")));
        var gui = File.ReadAllText(FindRepoFile(Path.Combine("wwwroot", "js", "app.js")))
                  + File.ReadAllText(FindRepoFile(Path.Combine("wwwroot", "index.html")));
        foreach (Match m in Regex.Matches(gui, @"(?:t\(|data-i18n(?:-ph|-title)?="")'?([a-zA-Z]+\.[A-Za-z.]+)'?"))
        {
            var key = m.Groups[1].Value;
            if (key.StartsWith("web.") || key.StartsWith("filter.") || key.StartsWith("badge.") || key.StartsWith("dash.denied")
                || key.StartsWith("type.") || key.StartsWith("msg.reapply") || key.EndsWith("ecordDenied") || key.StartsWith("alerts.denied")
                || key.StartsWith("alerts.ransomware"))
                Assert.Contains($"'{key}':", en);
        }
    }

    private static string FindRepoFile(string relative)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "FileAccessMonitor.csproj")))
                return Path.Combine(dir.FullName, relative);
        throw new FileNotFoundException(relative);
    }
}
