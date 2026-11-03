using System.Text.RegularExpressions;

namespace FileAccessMonitor.Tests;

// wwwroot/lang/<feature>.js: one Object.assign for I18N_EN, then one for I18N_JA, keys with the feature's prefix
public class FeatureLanguageFileTests
{
    public static TheoryData<string, string> Features => new()
    {
        { "permissions", "perm." },
        { "history", "hist." },
        { "reports", "report." },
        { "integrity", "integrity." },
    };

    [Theory]
    [MemberData(nameof(Features))]
    public void English_and_japanese_have_the_same_keys_with_the_prefix(string feature, string prefix)
    {
        var text = File.ReadAllText(Lang(feature + ".js"));
        var ja = text.IndexOf("window.I18N_JA", StringComparison.Ordinal);
        Assert.True(ja > 0, "I18N_JA block missing");
        var en = Keys(text[..ja]);
        Assert.Equal(en, Keys(text[ja..]));
        Assert.All(en, key => Assert.StartsWith(prefix, key));
    }

    [Theory]
    [MemberData(nameof(Features))]
    public void Lines_are_well_formed(string feature, string _)
    {
        foreach (var line in File.ReadLines(Lang(feature + ".js")))
        {
            if (!Regex.IsMatch(line, @"^\s+'[\w.]+':")) continue;
            Assert.Matches(@"^\s+'[\w.]+': '(?:[^'\\]|\\.)*',$", line);
        }
    }

    // Keys in the feature's own lang file or the main one
    [Theory]
    [MemberData(nameof(Features))]
    public void Every_key_the_feature_script_uses_exists(string feature, string prefix)
    {
        var known = File.ReadAllText(Lang("en.js")) + File.ReadAllText(Lang(feature + ".js"));
        var script = File.ReadAllText(Repo(Path.Combine("wwwroot", "js", feature + ".js")))
                     + File.ReadAllText(Repo(Path.Combine("wwwroot", "index.html")));
        foreach (Match m in Regex.Matches(script, @"(?:\bt\(|data-i18n(?:-ph|-title)?="")'?([a-zA-Z]+\.[A-Za-z0-9.]+)'?"))
        {
            var key = m.Groups[1].Value;
            if (key.StartsWith(prefix)) Assert.Contains($"'{key}':", known);
        }
    }

    private static string[] Keys(string text) => Regex.Matches(text, @"(?m)^\s+'([\w.]+)':")
        .Select(m => m.Groups[1].Value).Order().ToArray();

    private static string Lang(string file) => Repo(Path.Combine("wwwroot", "lang", file));

    private static string Repo(string relative)
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "FileAccessMonitor.csproj")))
                return Path.Combine(dir.FullName, relative);
        throw new FileNotFoundException(relative);
    }
}
