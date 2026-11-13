using System.Text.Json.Nodes;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// The setup wizard: the Security log size job and the "finished" flag
public class SetupWizardTests
{
    [Theory]
    [InlineData(20L * 1024 * 1024, true)]
    [InlineData(20L * 1024 * 1024 - 1, false)]
    [InlineData(1L << 30, true)]
    [InlineData(64L << 30, true)]
    [InlineData((64L << 30) + 1, false)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    public void The_size_must_be_between_20_MB_and_64_GB(long bytes, bool ok) =>
        Assert.Equal(ok, SecurityLogSize.InRange(bytes));

    [Theory]
    [InlineData(1L << 30, 1L << 30)]              // already a multiple of 64 KB
    [InlineData(1_000_000_000, 1_000_013_824)]    // rounded up to the next one
    [InlineData(65_536, 65_536)]
    [InlineData(1, 65_536)]
    public void The_size_is_rounded_up_to_64_KB(long bytes, long expected) =>
        Assert.Equal(expected, SecurityLogSize.Round(bytes));

    [Fact]
    public void A_job_without_a_size_is_a_query()
    {
        Assert.Null(SecurityLogSize.Wanted(new JsonObject()));
        Assert.Equal(1L << 30, SecurityLogSize.Wanted(new JsonObject { ["maxBytes"] = 1L << 30 }));
        // As it arrives from the server: parsed JSON
        Assert.Equal(1L << 30, SecurityLogSize.Wanted(JsonNode.Parse("""{ "maxBytes": 1073741824 }""")!.AsObject()));
    }

    // The Security log job needs an agent of 1.12 or later (an older one takes it for a folder job)
    [Theory]
    [InlineData("1.12.0", true)]
    [InlineData("1.12.0-rc1", true)]
    [InlineData("1.13.2", true)]
    [InlineData("2.0.0", true)]
    [InlineData("0.0.0", true)]      // a local build
    [InlineData("1.11.2", false)]
    [InlineData("1.9.0", false)]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("garbage", false)]
    public void The_agent_version_decides_whether_the_security_log_can_be_set(string? version, bool ok) =>
        Assert.Equal(ok, SettingsController.AgentAtLeast(version, SecurityLogSize.SinceVersion));

    [Fact]
    public void The_wizard_counts_as_finished_only_when_the_flag_is_true()
    {
        Assert.False(SettingsController.SetupDone(new JsonObject()));
        Assert.False(SettingsController.SetupDone(new JsonObject { [SettingsController.SetupDoneKey] = false }));
        Assert.False(SettingsController.SetupDone(new JsonObject { [SettingsController.SetupDoneKey] = "yes" }));
        Assert.True(SettingsController.SetupDone(new JsonObject { [SettingsController.SetupDoneKey] = true }));
    }

    // The Windows agent (and the collector, which is the same code) answers the job without a folder.
    // Reading the log's configuration needs administrator rights (an elevated test run, or CI).
    [Fact]
    public void The_windows_platform_reads_the_security_log_size()
    {
        if (!OperatingSystem.IsWindows() || !Elevated()) return;
        var result = WindowsPlatform().RunJob(new AgentJob("1", SecurityLogSize.JobType, new JsonObject()), CancellationToken.None);
        Assert.True(result["maxBytes"]!.GetValue<long>() > 0);
        Assert.Equal(SecurityLogSize.RecommendedBytes, result["recommendedBytes"]!.GetValue<long>());
        Assert.Null(result["error"]);
    }

    // Refused before the log is even opened, so without administrator rights too
    [Fact]
    public void A_size_out_of_range_is_refused_before_anything_changes()
    {
        if (!OperatingSystem.IsWindows()) return;
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            WindowsPlatform().RunJob(new AgentJob("1", SecurityLogSize.JobType, new JsonObject { ["maxBytes"] = 1024 }), CancellationToken.None));
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static WindowsAgentPlatform WindowsPlatform() =>
        new(new SaclManagerService(NullLogger<SaclManagerService>.Instance), NullLogger<WindowsAgentPlatform>.Instance);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static bool Elevated() =>
        new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent())
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
}
