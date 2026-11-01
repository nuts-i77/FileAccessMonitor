using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class UnusedFilesTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "fam-unused-" + Guid.NewGuid().ToString("N"));

    public UnusedFilesTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "sub"));
        File.WriteAllText(Path.Combine(_root, "watched.mp4"), "x");
        File.WriteAllText(Path.Combine(_root, "unwatched.mp4"), "xyz");
        File.WriteAllText(Path.Combine(_root, "sub", "old.mp4"), "xy");
        File.WriteAllText(Path.Combine(_root, "Thumbs.db"), "t");
    }

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Fact]
    public void Lists_files_without_records_except_excluded_ones()
    {
        // recorded paths may differ in case from the file system
        var used = new HashSet<string>([Path.Combine(_root, "WATCHED.mp4")], StringComparer.OrdinalIgnoreCase);
        var (files, scanned, truncated) = UnusedFilesController.Scan(
            _root, used, new RecordingRules(new RecordingSettings()), CancellationToken.None);

        Assert.Equal(4, scanned);
        Assert.False(truncated);
        Assert.Equal(["old.mp4", "unwatched.mp4"], files.Where(f => !f.Used).Select(f => Path.GetFileName(f.Path)).Order());
        Assert.Equal(3, files.Single(f => f.Path.EndsWith("unwatched.mp4")).Size);
        Assert.DoesNotContain(files, f => f.Path.EndsWith("Thumbs.db"));
    }

    [Fact]
    public void Summarizes_one_level_below_the_folder()
    {
        var used = new HashSet<string>([Path.Combine(_root, "watched.mp4")], StringComparer.OrdinalIgnoreCase);
        var (files, _, _) = UnusedFilesController.Scan(
            _root, used, new RecordingRules(new RecordingSettings()), CancellationToken.None);
        var seen = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
        var summary = UnusedFilesController.Summarize(_root, files,
            new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase) { [Path.Combine(_root, "watched.mp4")] = seen });

        var self = summary.Single(s => s.IsSelf);
        Assert.Equal((_root, 2, 4L, 1, 3L, (DateTime?)seen),
            (self.Path, self.Files, self.Size, self.UnusedFiles, self.UnusedSize, self.LastAccess));
        var sub = summary.Single(s => !s.IsSelf);
        Assert.Equal((Path.Combine(_root, "sub"), 1, 2L, (DateTime?)null), (sub.Path, sub.UnusedFiles, sub.UnusedSize, sub.LastAccess));
    }
}
