using System.Globalization;
using System.Text.RegularExpressions;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class MessagesTests
{
    [Fact]
    public void Japanese_and_English_have_the_same_keys() =>
        Assert.Equal(Messages.AllEn.Keys.Order(), Messages.AllJa.Keys.Order());

    [Fact]
    public void Japanese_and_English_use_the_same_placeholders()
    {
        static string[] Placeholders(string s) =>
            Regex.Matches(s, @"\{(\d+)").Select(m => m.Groups[1].Value).Distinct().Order().ToArray();

        foreach (var (key, en) in Messages.AllEn)
            Assert.True(Placeholders(en).SequenceEqual(Placeholders(Messages.AllJa[key])), key);
    }

    // Each feature table uses its own key prefix
    [Theory]
    [InlineData(typeof(MessagesPermissions), "perm.")]
    [InlineData(typeof(MessagesHistory), "hist.")]
    [InlineData(typeof(MessagesReports), "report.")]
    [InlineData(typeof(MessagesIntegrity), "integrity.")]
    public void Feature_tables_use_their_prefix(Type table, string prefix)
    {
        foreach (var name in new[] { "En", "Ja" })
        {
            var dict = (IReadOnlyDictionary<string, string>)table.GetField(name)!.GetValue(null)!;
            Assert.All(dict.Keys, key => Assert.StartsWith(prefix, key));
        }
    }

    [Theory]
    [InlineData("en", @"Folder not found: D:\x")]
    [InlineData("ja", @"フォルダが見つかりません: D:\x")]
    [InlineData("ja-JP", @"フォルダが見つかりません: D:\x")]
    [InlineData("fr", @"Folder not found: D:\x")]
    public void Follows_ui_culture(string culture, string expected)
    {
        using var _ = new UICulture(culture);
        Assert.Equal(expected, Messages.Get("path.notFound", @"D:\x"));
    }

    [Fact]
    public void Identity_errors_are_localized()
    {
        var describer = new LocalizedIdentityErrorDescriber();
        using (new UICulture("ja"))
            Assert.Equal("パスワードは 8 文字以上にしてください。", describer.PasswordTooShort(8).Description);
        using (new UICulture("en"))
            Assert.Contains("at least 8 characters", describer.PasswordTooShort(8).Description);
    }

    private sealed class UICulture : IDisposable
    {
        private readonly CultureInfo _previous = CultureInfo.CurrentUICulture;
        public UICulture(string name) => CultureInfo.CurrentUICulture = new CultureInfo(name);
        public void Dispose() => CultureInfo.CurrentUICulture = _previous;
    }
}
