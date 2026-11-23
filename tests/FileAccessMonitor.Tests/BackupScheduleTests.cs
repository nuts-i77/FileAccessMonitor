using System.Text.Json;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public sealed class BackupScheduleTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "fam-schedule-" + Guid.NewGuid().ToString("N"));

    public BackupScheduleTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    [Theory]
    [InlineData("02:00", true)]
    [InlineData("2:30", true)]
    [InlineData("23:59", true)]
    [InlineData("24:00", false)]
    [InlineData("12:60", false)]
    [InlineData("noon", false)]
    public void Times_are_hours_and_minutes(string time, bool ok) => Assert.Equal(ok, BackupSchedule.TimeOk(time));

    [Fact]
    public void The_task_runs_a_scheduled_backup_with_its_folder_quoted()
    {
        Assert.Equal("\"C:\\Program Files\\FileAccessMonitor\\FileAccessMonitor.exe\" backup --reason scheduled --keep 7",
            BackupSchedule.WindowsTaskCommand(@"C:\Program Files\FileAccessMonitor\FileAccessMonitor.exe", 7, null));
        Assert.EndsWith("--keep 14 --to \"D:\\Backups FAM\"",
            BackupSchedule.WindowsTaskCommand(@"C:\x.exe", 14, @"D:\Backups FAM"));
    }

    // Before a closing quote one backslash would escape the quote; two read as one
    [Fact]
    public void A_drive_root_keeps_its_backslash()
    {
        Assert.EndsWith("--to \"D:\\\\\"", BackupSchedule.BackupArguments(7, @"D:\"));
        var args = CommandLineArgs(BackupSchedule.WindowsTaskCommand(@"C:\x.exe", 7, @"D:\"));
        Assert.Equal(@"D:\", args[^1]);
    }

    [Fact]
    public void The_systemd_units_run_the_backup_daily_and_catch_up()
    {
        var service = BackupSchedule.LinuxService("/opt/fileaccessmonitor/FileAccessMonitor", 7, "/backup/fam");
        Assert.Contains("ExecStart=\"/opt/fileaccessmonitor/FileAccessMonitor\" backup --reason scheduled --keep 7 --to \"/backup/fam\"", service);
        Assert.Contains("Type=oneshot", service);
        var timer = BackupSchedule.LinuxTimer("03:30");
        Assert.Contains("OnCalendar=*-*-* 03:30:00", timer);
        Assert.Contains("Persistent=true", timer);
        Assert.Contains("WantedBy=timers.target", timer);
    }

    [Theory]
    [InlineData("/backup/fam", true)]
    [InlineData("/backup/my fam", false)]
    [InlineData("/backup/100%", false)]
    [InlineData("/backup/\"x\"", false)]
    public void Linux_folders_must_fit_in_a_unit_file(string path, bool ok) => Assert.Equal(ok, BackupSchedule.LinuxPathOk(path));

    [Fact]
    public void The_card_warns_without_a_recent_backup()
    {
        var now = new DateTime(2026, 11, 23, 12, 0, 0, DateTimeKind.Utc);
        Assert.True(Stale(BackupController.Describe(_dir, now)));   // none at all

        Directory.CreateDirectory(Path.Combine(_dir, "keys"));
        File.WriteAllText(Path.Combine(_dir, "settings.json"), "{}");
        DataBackup.Create(_dir, DataBackup.DefaultRoot(_dir), DataBackup.ReasonScheduled, "1.13.0", now: now.AddDays(-3));
        Assert.True(Stale(BackupController.Describe(_dir, now)));

        DataBackup.Create(_dir, DataBackup.DefaultRoot(_dir), DataBackup.ReasonScheduled, "1.13.0", now: now.AddHours(-20));
        Assert.False(Stale(BackupController.Describe(_dir, now)));
    }

    [Fact]
    public void The_schedule_shown_is_the_one_written_by_the_command()
    {
        File.WriteAllText(Path.Combine(_dir, BackupSchedule.InfoFile),
            JsonSerializer.Serialize(new BackupScheduleInfo(true, "03:00", 14, @"D:\Backups", DateTime.UtcNow),
                new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
        var info = BackupSchedule.Read(_dir);
        Assert.NotNull(info);
        Assert.Equal("03:00", info!.Time);
        Assert.Equal(14, info.Keep);
        Assert.Equal([Path.GetFullPath(@"D:\Backups"), Path.GetFullPath(DataBackup.DefaultRoot(_dir))],
            DataBackup.Roots(_dir, info.To));
    }

    private static bool Stale(object described) =>
        JsonDocument.Parse(JsonSerializer.Serialize(described)).RootElement.GetProperty("stale").GetBoolean();

    // How a Windows program splits its command line (the rules the task's command goes through)
    private static string[] CommandLineArgs(string commandLine)
    {
        var args = new List<string>();
        var current = new System.Text.StringBuilder();
        var quoted = false;
        var any = false;
        for (var i = 0; i < commandLine.Length; i++)
        {
            var c = commandLine[i];
            if (c == '\\')
            {
                var n = 0;
                while (i < commandLine.Length && commandLine[i] == '\\') { n++; i++; }
                if (i < commandLine.Length && commandLine[i] == '"')
                {
                    current.Append('\\', n / 2);
                    if (n % 2 == 1) { current.Append('"'); }
                    else { quoted = !quoted; }
                }
                else { current.Append('\\', n); i--; }
                any = true;
                continue;
            }
            if (c == '"') { quoted = !quoted; any = true; continue; }
            if (char.IsWhiteSpace(c) && !quoted)
            {
                if (any) { args.Add(current.ToString()); current.Clear(); any = false; }
                continue;
            }
            current.Append(c);
            any = true;
        }
        if (any) args.Add(current.ToString());
        return [.. args];
    }
}
