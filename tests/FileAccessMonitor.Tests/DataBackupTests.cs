using System.Security.AccessControl;
using System.Security.Principal;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;

namespace FileAccessMonitor.Tests;

public sealed class DataBackupTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-backup-" + Guid.NewGuid().ToString("N"));
    private string Data => Path.Combine(_dir, "data");
    private string Root => DataBackup.DefaultRoot(Data);

    public DataBackupTests()
    {
        Directory.CreateDirectory(Path.Combine(Data, "logs"));
        Directory.CreateDirectory(Path.Combine(Data, "keys"));
        File.WriteAllText(Path.Combine(Data, "settings.json"), "{\"RetentionDays\": 90}");
        File.WriteAllText(Path.Combine(Data, "jwt.key"), "secret-jwt");
        File.WriteAllText(Path.Combine(Data, "chain-head.json"), "{}");
        File.WriteAllText(Path.Combine(Data, "keys", "key-1.xml"), "<key/>");
        File.WriteAllText(Path.Combine(Data, "logs", "app-20261123.log"), "log");
        File.WriteAllText(Path.Combine(Data, "settings.json.tmp"), "half");
        DataBackup.WriteDataVersion(Data, "1.12.1");
        Exec("CREATE TABLE T (Id INTEGER PRIMARY KEY, V TEXT); INSERT INTO T (V) VALUES ('a'), ('b');");
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private void Exec(string sql, string? db = null)
    {
        using var c = new SqliteConnection($"Data Source={db ?? Path.Combine(Data, "fileaccess.db")};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static long Count(string db)
    {
        using var c = new SqliteConnection($"Data Source={db};Pooling=False;Mode=ReadOnly");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM T";
        return (long)cmd.ExecuteScalar()!;
    }

    [Fact]
    public void A_backup_has_the_files_and_a_copy_of_the_database_but_not_logs_or_temp_files()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");

        Assert.True(File.Exists(Path.Combine(info.Path!, DataBackup.ManifestFile)));
        Assert.Equal("secret-jwt", File.ReadAllText(Path.Combine(info.Path!, "jwt.key")));
        Assert.True(File.Exists(Path.Combine(info.Path!, "keys", "key-1.xml")));
        Assert.False(Directory.Exists(Path.Combine(info.Path!, "logs")));
        Assert.False(Directory.Exists(Path.Combine(info.Path!, DataBackup.FolderName)));
        Assert.False(File.Exists(Path.Combine(info.Path!, "settings.json.tmp")));
        Assert.False(File.Exists(Path.Combine(info.Path!, "fileaccess.db-wal")));
        Assert.Equal(2, Count(Path.Combine(info.Path!, "fileaccess.db")));
        Assert.Equal("1.12.1", info.DataVersion);
        Assert.Equal("1.13.0", info.AppVersion);
        Assert.Empty(DataBackup.Verify(DataBackup.TryRead(info.Path!)!));
    }

    [Fact]
    public void The_chain_head_file_is_copied_before_the_database()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        var files = info.Entries.Where(e => !e.Directory).Select(e => e.Path).ToList();
        Assert.True(files.IndexOf("chain-head.json") < files.IndexOf("fileaccess.db"));
        Assert.Equal("fileaccess.db", files[^1]);
    }

    [Fact]
    public void A_changed_file_is_found_by_verify()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        File.WriteAllText(Path.Combine(info.Path!, "jwt.key"), "other");
        Assert.Equal(["jwt.key"], DataBackup.Verify(DataBackup.TryRead(info.Path!)!));
        Assert.Throws<BackupException>(() => DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!));
    }

    [Fact]
    public void Restore_puts_the_backup_back_and_keeps_what_was_there()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        Exec("INSERT INTO T (V) VALUES ('c');");
        File.WriteAllText(Path.Combine(Data, "jwt.key"), "changed");
        File.WriteAllText(Path.Combine(Data, "new-after-backup.txt"), "x");

        var saved = DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!);

        Assert.Equal("secret-jwt", File.ReadAllText(Path.Combine(Data, "jwt.key")));
        Assert.Equal(2, Count(Path.Combine(Data, "fileaccess.db")));
        Assert.False(File.Exists(Path.Combine(Data, "new-after-backup.txt")));
        Assert.True(File.Exists(Path.Combine(Data, "logs", "app-20261123.log")));   // logs stay
        Assert.Equal("changed", File.ReadAllText(Path.Combine(saved, "jwt.key")));
        Assert.Equal(3, Count(Path.Combine(saved, "fileaccess.db")));

        // The marker is read once by the next start
        var marker = DataBackup.TakeRestoredMarker(Data);
        Assert.NotNull(marker);
        Assert.Equal(info.Name, marker!.Backup);
        Assert.Equal(Path.GetFileName(saved), marker.PreviousDataSavedAs);
        Assert.Null(DataBackup.TakeRestoredMarker(Data));
    }

    [Fact]
    public void What_a_restore_moved_away_can_be_restored_to_undo_it()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        Exec("INSERT INTO T (V) VALUES ('c');");
        var saved = DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!);
        DataBackup.TakeRestoredMarker(Data);

        var undo = DataBackup.TryRead(saved);
        Assert.NotNull(undo);
        Assert.Equal(DataBackup.ReasonBeforeRestore, undo!.Reason);
        DataBackup.Restore(Data, undo);
        Assert.Equal(3, Count(Path.Combine(Data, "fileaccess.db")));
    }

    [Fact]
    public void A_backup_without_the_collector_folder_leaves_the_current_one_in_place()
    {
        var collector = Path.Combine(Data, AppPaths.CollectorFolderName);
        Directory.CreateDirectory(collector);
        File.WriteAllText(Path.Combine(collector, "secret"), "collector-secret");
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0", includeCollector: false);
        Assert.False(info.CollectorIncluded);
        Assert.False(Directory.Exists(Path.Combine(info.Path!, AppPaths.CollectorFolderName)));

        File.WriteAllText(Path.Combine(collector, "secret"), "newer-secret");
        DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!);
        Assert.Equal("newer-secret", File.ReadAllText(Path.Combine(collector, "secret")));
    }

    // What backup-schedule set up describes this machine's task or timer, not the data
    [Fact]
    public void The_daily_backup_setting_is_not_backed_up_nor_replaced_by_a_restore()
    {
        var schedule = Path.Combine(Data, BackupSchedule.InfoFile);
        File.WriteAllText(schedule, "before");
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        Assert.False(File.Exists(Path.Combine(info.Path!, BackupSchedule.InfoFile)));

        File.WriteAllText(schedule, "current");
        DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!);
        Assert.Equal("current", File.ReadAllText(schedule));
    }

    [Fact]
    public void A_backup_of_newer_data_is_refused_unless_forced()
    {
        DataBackup.WriteDataVersion(Data, "1.13.0");
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        Assert.Equal("backup.newer", DataBackup.RestoreRefusal(info, "1.12.1"));
        Assert.Null(DataBackup.RestoreRefusal(info, "1.13.0-rc1"));
        Assert.Null(DataBackup.RestoreRefusal(info, "1.14.0"));
        Assert.Null(DataBackup.RestoreRefusal(info, "0.0.0"));   // a local build
    }

    [Fact]
    public void Prune_keeps_the_newest_of_one_reason()
    {
        var t = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        for (var i = 0; i < 4; i++) DataBackup.Create(Data, Root, DataBackup.ReasonScheduled, "1.13.0", now: t.AddDays(i));
        var manual = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0", now: t);

        var deleted = DataBackup.Prune(Root, DataBackup.ReasonScheduled, 2);

        Assert.Equal(2, deleted.Count);
        var left = DataBackup.List(Root);
        Assert.Equal(2, left.Count(b => b.Reason == DataBackup.ReasonScheduled));
        Assert.Contains(left, b => b.Name == manual.Name);
        Assert.Equal(t.AddDays(3), left.First(b => b.Reason == DataBackup.ReasonScheduled).Created);
    }

    [Fact]
    public void Names_from_outside_resolve_inside_the_backups_folder_only()
    {
        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        Assert.Equal(info.Path, DataBackup.Resolve(Root, info.Name));
        Assert.Null(DataBackup.Resolve(Root, "../" + info.Name));
        Assert.Null(DataBackup.Resolve(Root, ".."));
        Assert.Null(DataBackup.Resolve(Root, "missing"));
    }

    [Fact]
    public void A_target_elsewhere_inside_the_data_folder_is_refused()
    {
        var e = Assert.Throws<BackupException>(() =>
            DataBackup.Create(Data, Path.Combine(Data, "keys", "bk"), DataBackup.ReasonManual, "1.13.0"));
        Assert.Equal("backup.badTarget", e.Key);
    }

    [Fact]
    public void A_folder_without_a_manifest_is_not_a_backup()
    {
        Directory.CreateDirectory(Path.Combine(Root, "20261101-000000-manual"));
        Assert.Empty(DataBackup.List(Root));
    }

    [Theory]
    [InlineData("1.13.0", 1, 13, 0)]
    [InlineData("1.13.0-rc1", 1, 13, 0)]
    [InlineData("1.12", 1, 12, 0)]
    public void Versions_are_read_without_their_suffix(string text, int major, int minor, int build) =>
        Assert.Equal(new Version(major, minor, build), DataBackup.ParseVersion(text));

    // Windows: a protected key file keeps its own access rules in the backup and after a restore
    [Fact]
    public void Permissions_of_a_protected_file_are_kept()
    {
        if (!OperatingSystem.IsWindows()) return;
        var key = Path.Combine(Data, "chain.key");
        File.WriteAllText(key, "k");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(true, false);
        var self = WindowsIdentity.GetCurrent().User!;
        security.AddAccessRule(new FileSystemAccessRule(self, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(key).SetAccessControl(security);
        var before = new FileInfo(key).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);

        var info = DataBackup.Create(Data, Root, DataBackup.ReasonManual, "1.13.0");
        var copy = new FileInfo(Path.Combine(info.Path!, "chain.key")).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        Assert.Equal(before, copy);

        File.Delete(key);
        DataBackup.Restore(Data, DataBackup.TryRead(info.Path!)!);
        Assert.Equal(before, new FileInfo(key).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
    }
}
