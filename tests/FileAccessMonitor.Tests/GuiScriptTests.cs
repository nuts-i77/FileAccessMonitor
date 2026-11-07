namespace FileAccessMonitor.Tests;

// Mistakes in the GUI scripts that no test runs in a browser would catch
public class GuiScriptTests
{
    // In a JS template literal "\${x}" is the text ${x}, not the value of x (an update command once
    // came out as "$env:TEMP${exe}")
    [Fact]
    public void No_escaped_placeholder_in_template_literals()
    {
        var dir = Repo(Path.Combine("wwwroot", "js"));
        foreach (var file in Directory.GetFiles(dir, "*.js"))
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
                Assert.False(lines[i].Contains(@"\${"), $"{Path.GetFileName(file)}:{i + 1}: {lines[i].Trim()}");
        }
    }

    private static string Repo(string relative)
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d != null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "FileAccessMonitor.csproj")))
                return Path.Combine(d.FullName, relative);
        throw new DirectoryNotFoundException(relative);
    }
}
