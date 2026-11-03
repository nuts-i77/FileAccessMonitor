using FileAccessMonitor.Services;
using Microsoft.Extensions.Logging.Abstractions;

#pragma warning disable CA1416 // the agent targets Linux; these tests only use its platform-neutral parts

public class SambaTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-linux-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private const string Prefix = @"CORP\taro|::ffff:192.168.0.20|PC01|share|/srv/share|";

    [Theory]
    [InlineData("create_file|ok|0x120089|file|open|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Read", false)]
    [InlineData("create_file|ok|0x12019f|file|overwrite_if|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Write", false)]
    [InlineData("create_file|ok|0x80000000|file|open|docs/a.txt", "/srv/share/docs/a.txt", "Read", false)] // relative path
    [InlineData("create_file|ok|0x100081|dir|open|/srv/share/docs", "/srv/share/docs", "Read", true)]
    [InlineData("create_file|ok|0x80|dir|create|/srv/share/docs/sub", "/srv/share/docs/sub", "", true)] // only shows it is a folder
    // Samba 4.23 (Rocky Linux 9) makes a folder under a temporary name, then renames it into place
    [InlineData("renameat|ok|/srv/share/docs/.::TMPNAME:D:756%6541505324126704924:sub|/srv/share/docs/sub", "/srv/share/docs/sub", "", true)]
    [InlineData("renameat|ok|/srv/share/docs/a.txt|/srv/share/docs/b.txt", "/srv/share/docs/a.txt", "Rename", false)]
    [InlineData("unlinkat|ok|/srv/share/docs/a.txt", "/srv/share/docs/a.txt", "Delete", false)]
    [InlineData("rmdir|ok|/srv/share/old", "/srv/share/old", "Delete", true)]
    public void Audit_lines_become_accesses(string rest, string path, string type, bool folder)
    {
        var access = AuditInterpreter.Interpret(AuditLine.Parse(Prefix + rest)!)!;
        Assert.Equal((path, type, folder), (access.Path, access.Type, access.IsFolder));
    }

    [Theory]
    [InlineData("create_file|ok|0x100080|file|open|/srv/share/a.txt")]   // attributes only
    [InlineData("create_file|ok|0x110080|file|open|/srv/share/a.txt")]   // delete access: recorded at unlinkat
    [InlineData("create_file|fail|0x120089|file|open|/srv/share/a.txt")] // failed
    [InlineData("connect|ok|share")]
    public void Other_lines_are_ignored(string rest) =>
        Assert.Null(AuditLine.Parse(Prefix + rest) is { } line ? AuditInterpreter.Interpret(line) : null);

    [Fact]
    public void Records_follow_monitored_folders_and_rules()
    {
        var collector = new SambaAuditCollector(new RemoteRecordSink(new AgentOutbox(_dir), NullLogger<RemoteRecordSink>.Instance), NullLogger<SambaAuditCollector>.Instance);
        collector.UseSettings([("/srv/share/docs", ["Read", "Delete"])], new RecordingSettings { MergeReadMinutes = 0 });
        var time = new DateTime(2026, 11, 3, 1, 2, 3, DateTimeKind.Utc);

        var read = collector.ToRecord(Prefix + "create_file|ok|0x120089|file|open|/srv/share/docs/a.txt", time)!;
        Assert.Equal(("/srv/share/docs/a.txt", "a.txt", "/srv/share/docs", @"CORP\taro", "Read", "192.168.0.20", "PC01"),
            (read.FilePath, read.FileName, read.FolderPath, read.UserName, read.AccessType, read.ClientIp, read.ClientMachine));

        Assert.Null(collector.ToRecord(Prefix + "create_file|ok|0x120089|file|open|/srv/share/docs2/a.txt", time)); // not monitored
        Assert.Null(collector.ToRecord(Prefix + "create_file|ok|0x120089|file|open|/srv/share/Docs/a.txt", time)); // case matters
        Assert.Null(collector.ToRecord(Prefix + "create_file|ok|0x12019f|file|open|/srv/share/docs/a.txt", time)); // Write not monitored
        Assert.Null(collector.ToRecord(Prefix + "create_file|ok|0x120089|file|open|/srv/share/docs/~$a.docx", time)); // excluded file
        Assert.Equal("Rename", collector.ToRecord(Prefix + "renameat|ok|/srv/share/docs/a.txt|/srv/share/docs/b.txt", time)!.AccessType);

        // A folder: not recorded when opened, recorded when deleted even though it is gone by then
        Assert.Null(collector.ToRecord(Prefix + "create_file|ok|0x100081|dir|open|/srv/share/docs/old", time));
        var deleted = collector.ToRecord(Prefix + "unlinkat|ok|/srv/share/docs/old", time)!;
        Assert.Equal(("Delete", true), (deleted.AccessType, deleted.IsFolder));
    }

    // Lines as Samba 4.19 (Ubuntu 24.04) wrote them for: get, put, rename, del, mkdir, rmdir, with the
    // extra rename Samba 4.23 (Rocky Linux 9) writes for mkdir
    [Fact]
    public void Real_samba_lines_give_the_expected_records()
    {
        var collector = new SambaAuditCollector(new RemoteRecordSink(new AgentOutbox(_dir), NullLogger<RemoteRecordSink>.Instance), NullLogger<SambaAuditCollector>.Instance);
        collector.UseSettings([("/srv/share/docs", ["Read", "Write", "Delete"])], new RecordingSettings { MergeReadMinutes = 0 });
        var lines = """
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x120089|file|open|/srv/share/docs/report.txt
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x12019f|file|overwrite_if|/srv/share/docs/upload.txt
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x10000|file|open|/srv/share/docs/upload.txt
            nobody|127.0.0.1|ct114|share|/srv/share|renameat|ok|/srv/share/docs/upload.txt|/srv/share/docs/renamed.txt
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x81|dir|open|/srv/share/docs
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x10000|file|open|/srv/share/docs/renamed.txt
            nobody|127.0.0.1|ct114|share|/srv/share|unlinkat|ok|/srv/share/docs/renamed.txt
            nobody|127.0.0.1|ct115|share|/srv/share|renameat|ok|/srv/share/docs/.::TMPNAME:D:756%6541505324126704924:sub|/srv/share/docs/sub
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x80|dir|create|/srv/share/docs/sub
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x10000|dir|open|/srv/share/docs/sub
            nobody|127.0.0.1|ct114|share|/srv/share|unlinkat|ok|/srv/share/docs/sub
            nobody|127.0.0.1|ct114|share|/srv/share|create_file|ok|0x120089|file|open|/srv/share/video/v.mp4
            pam_unix(samba:session): session closed for user nobody
            """.Split('\n');
        var records = lines.Select(l => collector.ToRecord(l.Trim(), DateTime.UtcNow)).OfType<FileAccessMonitor.Models.AccessRecord>()
            .Select(r => $"{r.AccessType} {r.FilePath}{(r.IsFolder ? " (folder)" : "")}").ToList();
        Assert.Equal([
            "Read /srv/share/docs/report.txt", "Write /srv/share/docs/upload.txt", "Rename /srv/share/docs/upload.txt",
            "Delete /srv/share/docs/renamed.txt", "Delete /srv/share/docs/sub (folder)",
        ], records);
    }

    [Theory]
    [InlineData("/srv/share", "/srv/share", true)]
    [InlineData("/srv/share/a.txt", "/srv/share", true)]
    [InlineData("/srv/share/a.txt", "/srv/share/", true)]
    [InlineData("/srv/share2/a.txt", "/srv/share", false)]
    [InlineData("/srv/Share/a.txt", "/srv/share", false)]
    [InlineData("/srv/share/a.txt", "/", true)]
    public void Paths_match_case_sensitively(string path, string root, bool expected) =>
        Assert.Equal(expected, SambaAuditCollector.IsUnderPath(path, root));

    private const string Conf = """
        [global]
           workgroup = CORP
           vfs objects = acl_xattr

        [share]
           path = /srv/share
           read only = no

        [projects]
           comment = Projects
           path = /srv/projects/
           vfs objects = recycle
           full_audit:success = all

        [homes]
           browseable = no
        """;

    [Fact]
    public void Shares_are_read_from_smb_conf()
    {
        var shares = new SambaConfigText(Conf).Shares();
        Assert.Equal(["share", "projects"], shares.Keys);
        Assert.Equal(["share"], SambaPlatform.SharesFor(shares, "/srv/share/docs"));     // folder inside a share
        Assert.Equal(["share", "projects"], SambaPlatform.SharesFor(shares, "/srv"));    // shares inside the folder
        Assert.Empty(SambaPlatform.SharesFor(shares, "/srv/other"));
    }

    [Fact]
    public void Auditing_is_added_and_removed_without_changing_the_rest()
    {
        var config = new SambaConfigText(Conf);
        config.EnableAudit("share", samba414: true);
        config.EnableAudit("projects", samba414: false);
        var text = config.ToString();

        Assert.True(config.IsAudited("share") && config.IsAudited("projects"));
        Assert.Contains("\tvfs objects = acl_xattr full_audit", text);   // keeps the global modules
        Assert.Contains("\tvfs objects = recycle full_audit", text);     // keeps the share's own
        Assert.Contains("full_audit:success = create_file renameat unlinkat", text);
        Assert.Contains("full_audit:success = create_file rename unlink rmdir", text);
        Assert.Contains(SambaConfigText.DisabledPrefix + "   vfs objects = recycle", text);
        Assert.Contains(SambaConfigText.DisabledPrefix + "   full_audit:success = all", text);
        Assert.Contains("full_audit:prefix = " + SambaConfigText.Prefix, text);

        config.EnableAudit("share", samba414: true); // again: no second block
        Assert.Equal(2, config.ToString().Split('\n').Count(l => l.Contains("full_audit:prefix = %u")));

        config.DisableAudit("share");
        config.DisableAudit("projects");
        Assert.Equal(Conf.Replace("\r\n", "\n"), config.ToString());
        Assert.False(config.IsAudited("share"));
    }

    [Fact]
    public void Unknown_shares_are_reported() =>
        Assert.Throws<InvalidOperationException>(() => new SambaConfigText(Conf).EnableAudit("nope", true));
}
