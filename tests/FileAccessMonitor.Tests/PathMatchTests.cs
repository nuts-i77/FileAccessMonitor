using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class PathMatchTests
{
    [Theory]
    [InlineData(@"D:\Share\a.txt", @"D:\Share")]
    [InlineData(@"D:\Share\sub\a.txt", @"D:\Share\")]
    [InlineData(@"d:\share\A.TXT", @"D:\Share")]
    [InlineData(@"D:\Share", @"D:\Share")]
    [InlineData(@"U:\photo.jpg", @"U:\")]
    public void Matches_files_inside_root(string file, string root) =>
        Assert.True(EventLogCollectorService.IsUnderPath(file, root));

    [Theory]
    [InlineData(@"D:\Share2\a.txt", @"D:\Share")]
    [InlineData(@"D:\Shared.txt", @"D:\Share")]
    [InlineData(@"E:\Share\a.txt", @"D:\Share")]
    public void Does_not_match_sibling_paths(string file, string root) =>
        Assert.False(EventLogCollectorService.IsUnderPath(file, root));
}
