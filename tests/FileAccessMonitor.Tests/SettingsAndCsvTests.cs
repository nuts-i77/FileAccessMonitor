using System.Text.Json.Nodes;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class SettingsStoreTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"fam-settings-{Guid.NewGuid():N}.json");

    public void Dispose() => File.Delete(_path);

    [Fact]
    public void Updating_one_key_keeps_the_others()
    {
        File.WriteAllText(_path, """
            { "MonitoredPaths": [ { "path": "D:\\Share", "eventTypes": ["Read"] } ], "DnsServer": "192.0.2.1" }
            """);

        SettingsStore.Update(_path, root => root["RetentionDays"] = 90);

        var root = SettingsStore.Load(_path);
        Assert.Equal(90, root["RetentionDays"]!.GetValue<int>());
        Assert.Equal("192.0.2.1", root["DnsServer"]!.GetValue<string>());
        var (configs, dns) = SettingsController.ParseSettings(root);
        Assert.Equal(@"D:\Share", Assert.Single(configs).Path);
        Assert.Equal("192.0.2.1", dns);
    }

    [Fact]
    public void Missing_or_broken_file_loads_as_empty()
    {
        Assert.Empty(SettingsStore.Load(_path));
        File.WriteAllText(_path, "{ not json");
        Assert.Empty(SettingsStore.Load(_path));
    }

    [Fact]
    public void Parses_old_and_new_path_formats()
    {
        var root = JsonNode.Parse("""
            { "MonitoredPaths": [ "E:\\Old", { "path": "D:\\New", "eventTypes": ["Write", "Delete"] } ] }
            """)!.AsObject();
        var (configs, _) = SettingsController.ParseSettings(root);
        Assert.Equal(["Read", "Write", "Delete"], configs[0].EventTypes);
        Assert.Equal(["Write", "Delete"], configs[1].EventTypes);
    }
}

public class CsvTests
{
    [Theory]
    [InlineData("report.xlsx", "\"report.xlsx\"")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("=HYPERLINK(\"x\")", "\"'=HYPERLINK(\"\"x\"\")\"")]   // CSV injection
    [InlineData("+1.txt", "\"'+1.txt\"")]
    [InlineData("@cmd", "\"'@cmd\"")]
    [InlineData(null, "\"\"")]
    public void Escapes_fields(string? value, string expected) =>
        Assert.Equal(expected, StatsController.CsvField(value));
}
