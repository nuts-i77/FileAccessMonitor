using FileAccessMonitor.Services;
using Xunit.Abstractions;

namespace FileAccessMonitor.Tests;

// Skipped unless FAM_PERF=1: dotnet test --filter Category=Perf
public sealed class PerfFactAttribute : FactAttribute
{
    public PerfFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("FAM_PERF") != "1") Skip = "Performance test: set FAM_PERF=1 to run it.";
    }
}

public class ChainPerfTests(ITestOutputHelper output)
{
    [PerfFact]
    [Trait("Category", "Perf")]
    public async Task Verifying_a_million_records()
    {
        using var env = new ChainEnv();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (var i = 0; i < 1_000_000; i += 5000) await env.AddRecordsAsync(5000, first: i + 1);
        output.WriteLine($"insert 1M: {sw.Elapsed.TotalSeconds:F1} s");

        sw.Restart();
        var run = await env.NewService().VerifyAsync(full: true, default);
        output.WriteLine($"verify 1M: {sw.Elapsed.TotalSeconds:F1} s = {run!.RowsDone / sw.Elapsed.TotalSeconds:N0} rows/s");
        Assert.Empty(run.Breaks);
        Assert.Equal(1_000_000, run.RowsDone);
    }
}
