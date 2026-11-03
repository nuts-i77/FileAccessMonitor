using FileAccessMonitor.Models;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class RansomwareDetectorTests
{
    private static readonly DateTime T0 = new(2026, 11, 3, 1, 0, 0, DateTimeKind.Utc);

    private static AlertDetector Detector(RansomwareRules? rules = null) =>
        new(new AlertRules(0, 0, 5, 30, Ransomware: rules ?? new RansomwareRules()));

    private static AccessRecord Write(string user, int i, double seconds, string type = "Write", string folder = @"D:\Share\r", string server = "FS01") => new()
    {
        UserName = user, AccessType = type, AccessTime = T0.AddSeconds(seconds), ServerName = server,
        FolderPath = folder, FilePath = $@"{folder}\f{i}.docx", FileName = $"f{i}.docx",
    };

    private static AccessRecord Rename(string user, int i, double seconds, string newExt, string oldExt = "docx", string server = "FS01") => new()
    {
        UserName = user, AccessType = "Rename", AccessTime = T0.AddSeconds(seconds), ServerName = server,
        FolderPath = @"D:\Share\r", FilePath = $@"D:\Share\r\f{i}.{oldExt}", FileName = $"f{i}.{oldExt}",
        NewPath = $@"D:\Share\r\f{i}.{newExt}",
    };

    private static AccessRecord Note(string user, string name, string folder, double seconds, string type = "Create") => new()
    {
        UserName = user, AccessType = type, AccessTime = T0.AddSeconds(seconds), ServerName = "FS01",
        FolderPath = folder, FilePath = $@"{folder}\{name}", FileName = name,
    };

    [Fact]
    public void Many_renames_to_the_same_new_extension_alert()
    {
        var alerts = Detector().Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, i, "locked")));
        var a = Assert.Single(alerts);
        Assert.Equal(("Ransomware", "extension", "High", 20), (a.AccessType, a.Rule, a.Priority, a.Count));
        Assert.Equal(".locked (20 files)", a.Detail);
        Assert.Equal("FS01", a.ServerName);
    }

    [Fact]
    public void Fewer_renames_or_renames_to_different_extensions_do_not_alert()
    {
        Assert.Empty(Detector().Process(Enumerable.Range(0, 19).Select(i => Rename("u", i, i, "locked"))));
        Assert.Empty(Detector().Process(Enumerable.Range(0, 60).Select(i => Rename("u", i, i, "ext" + i % 5))));
    }

    [Fact]
    public void Renames_slower_than_the_window_do_not_alert()
    {
        // 20 renames, one every 10 s: never 20 inside 2 minutes
        Assert.Empty(Detector().Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, i * 10, "locked"))));
    }

    [Theory]
    [InlineData("tmp", "jpg")]       // a photo import: .tmp -> .jpg
    [InlineData("docx", "bak")]
    [InlineData("xls", "xlsx")]      // saved in the newer format
    [InlineData("docx", "~wrl0001")]
    [InlineData("download", "part")]
    public void Everyday_renames_do_not_alert(string oldExt, string newExt)
    {
        Assert.Empty(Detector().Process(Enumerable.Range(0, 50).Select(i => Rename("u", i, i, newExt, oldExt))));
    }

    [Fact]
    public void Renames_without_a_new_path_cannot_trigger_the_extension_rule()
    {
        var records = Enumerable.Range(0, 50).Select(i => { var r = Rename("u", i, i, "locked"); r.NewPath = null; return r; });
        Assert.Empty(Detector().Process(records));
    }

    [Fact]
    public void Mass_writing_together_with_mass_renaming_alerts_but_either_alone_does_not()
    {
        var both = Enumerable.Range(0, 100).Select(i => Write("u", i, i * 0.5))
            .Concat(Enumerable.Range(0, 50).Select(i => Rename("u", i, 50 + i * 0.5, "x" + i)));  // all different extensions
        var a = Assert.Single(Detector().Process(both));
        Assert.Equal("burst", a.Rule);

        Assert.Empty(Detector().Process(Enumerable.Range(0, 300).Select(i => Write("u", i, i * 0.1)))); // a bulk copy
        Assert.Empty(Detector().Process(Enumerable.Range(0, 200).Select(i => Rename("u", i, i * 0.1, "x" + i)))); // a tidy-up
    }

    [Fact]
    public void Created_files_count_as_writes_for_the_burst_rule()
    {
        var records = Enumerable.Range(0, 100).Select(i => Write("u", i, i * 0.5, "Create"))
            .Concat(Enumerable.Range(0, 50).Select(i => Rename("u", i, 50 + i * 0.5, "x" + i)));
        Assert.Equal("burst", Assert.Single(Detector().Process(records)).Rule);
    }

    [Fact]
    public void A_note_in_several_folders_alerts()
    {
        var records = new[]
        {
            Note("u", "README_DECRYPT.txt", @"D:\A", 0),
            Note("u", "README_DECRYPT.txt", @"D:\B", 5, "Write"),
            Note("u", "README_DECRYPT.txt", @"D:\C", 10),
        };
        var a = Assert.Single(Detector().Process(records));
        Assert.Equal(("note", "High", 3), (a.Rule, a.Priority, a.Count));
        Assert.Contains("3 folders", a.Detail);
    }

    [Fact]
    public void A_note_in_the_same_folder_twice_or_in_two_folders_does_not_alert()
    {
        Assert.Empty(Detector().Process([
            Note("u", "HOW_TO_DECRYPT_FILES.txt", @"D:\A", 0), Note("u", "HOW_TO_DECRYPT_FILES.txt", @"D:\A", 1),
            Note("u", "HOW_TO_DECRYPT_FILES.txt", @"D:\B", 2)]));
    }

    [Fact]
    public void Ordinary_readme_files_in_many_folders_do_not_alert()
    {
        Assert.Empty(Detector().Process(Enumerable.Range(0, 10).Select(i => Note("u", "README.txt", @"D:\F" + i, i))));
        Assert.Empty(Detector().Process(Enumerable.Range(0, 10).Select(i => Note("u", "readme_install.txt", @"D:\F" + i, i))));
    }

    [Theory]
    [InlineData("README_DECRYPT.txt", true)]
    [InlineData("readme-to-restore.html", true)]
    [InlineData("HOW_TO_DECRYPT_FILES.txt", true)]
    [InlineData("How to recover your files.hta", true)]
    [InlineData("DECRYPT_INSTRUCTIONS.txt", true)]
    [InlineData("!!!_HELP_RECOVER_!!!.txt", true)]
    [InlineData("_readme_.txt", true)]
    [InlineData("@Please_Read_Me@.txt", true)]
    [InlineData("RyukReadMe.txt", true)]
    [InlineData("#DECRYPT#.html", true)]
    [InlineData("report-DECRYPT.txt", true)]
    [InlineData("files.README.txt", true)]
    [InlineData("HOW_TO_BACK_FILES.txt", true)]
    [InlineData("README.txt", false)]
    [InlineData("readme_install.txt", false)]
    [InlineData("recovery_plan.txt", false)]
    [InlineData("restore_notes.docx", false)]       // not a note extension
    [InlineData("README_DECRYPT.docx", false)]
    [InlineData("notes.txt", false)]
    public void Ransom_note_names(string name, bool expected) =>
        Assert.Equal(expected, AlertDetector.IsRansomNote(name));

    [Fact]
    public void Cooldown_is_per_rule_user_and_server_and_a_second_alert_comes_after_it()
    {
        var d = Detector();
        Assert.Single(d.Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, i, "locked"))));
        // same user and server within the cooldown: quiet
        Assert.Empty(d.Process(Enumerable.Range(20, 30).Select(i => Rename("u", i, 30 + i, "locked"))));
        // another user, and the same user on another server, alert at once
        Assert.Single(d.Process(Enumerable.Range(0, 20).Select(i => Rename("v", i, i, "locked"))));
        Assert.Single(d.Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, i, "locked", server: "FS02"))));
        // after the cooldown (30 min)
        Assert.Single(d.Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, 3600 + i, "locked"))));
    }

    [Fact]
    public void Users_are_counted_separately()
    {
        var records = Enumerable.Range(0, 38).Select(i => Rename(i % 2 == 0 ? "a" : "b", i, i, "locked"));
        Assert.Empty(Detector().Process(records)); // 19 each
    }

    [Fact]
    public void Old_records_are_judged_by_their_own_time()
    {
        // a backlog from the past followed by a new burst far later: the old ones are no longer in the window
        var d = Detector();
        Assert.Empty(d.Process(Enumerable.Range(0, 19).Select(i => Rename("u", i, i, "locked"))));
        Assert.Empty(d.Process(Enumerable.Range(19, 1).Select(i => Rename("u", i, 3600, "locked"))));
        Assert.Single(d.Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, 7200 + i, "locked"))));
    }

    [Fact]
    public void Denied_records_and_folders_are_ignored_and_the_switch_turns_it_off()
    {
        var denied = Enumerable.Range(0, 50).Select(i => { var r = Rename("u", i, i, "locked"); r.Denied = true; return r; });
        Assert.Empty(Detector().Process(denied));
        var folders = Enumerable.Range(0, 50).Select(i => { var r = Rename("u", i, i, "locked"); r.IsFolder = true; return r; });
        Assert.Empty(Detector().Process(folders));
        Assert.Empty(Detector(new RansomwareRules(Enabled: false)).Process(Enumerable.Range(0, 50).Select(i => Rename("u", i, i, "locked"))));
        Assert.Empty(new AlertDetector(new AlertRules(0, 0, 5, 30)).Process(Enumerable.Range(0, 50).Select(i => Rename("u", i, i, "locked"))));
    }

    [Fact]
    public void Ransomware_alert_text_is_high_priority_in_both_languages()
    {
        var a = Assert.Single(Detector().Process(Enumerable.Range(0, 20).Select(i => Rename("u", i, i, "locked"))));
        var (titleEn, bodyEn) = AlertService.Format(a, "en");
        Assert.StartsWith("[HIGH PRIORITY]", titleEn);
        Assert.Contains("Ransomware-like", titleEn);
        Assert.Contains(".locked (20 files)", bodyEn);
        var (titleJa, bodyJa) = AlertService.Format(a, "ja");
        Assert.StartsWith("【緊急】", titleJa);
        Assert.Contains("ランサムウェア", titleJa);
        Assert.Contains(".locked (20 files)", bodyJa);
    }

    [Fact]
    public void Rule_changes_are_seen_by_record_equality_and_defaults_match_the_design()
    {
        var s = new AlertSettings();
        Assert.Equal(new RansomwareRules(true, 2, 20, 100, 50, 3, 30), s.Rules.Ransomware);
        Assert.Equal(20, s.Rules.DeniedThreshold);
        Assert.Equal(s.Rules, new AlertSettings().Rules);
        Assert.NotEqual(s.Rules, new AlertSettings { RansomwareEnabled = false }.Rules);
    }
}
