using System.Text.RegularExpressions;

namespace FileAccessMonitor.Tests;

// The page layout of 1.13: settings menu and pages, the totals tab, and hints with details
public class GuiLayoutTests
{
    private static readonly string Html = File.ReadAllText(Repo(Path.Combine("wwwroot", "index.html")));

    private static string AllLang() => string.Concat(Directory.GetFiles(Repo(Path.Combine("wwwroot", "lang")), "*.js")
        .Select(File.ReadAllText));

    [Fact]
    public void Every_settings_menu_item_has_a_page_and_every_page_an_item()
    {
        var items = Regex.Matches(Html, @"<a [^>]*class=""list-group-item[^""]*"" data-page=""(\w+)""")
            .Select(m => m.Groups[1].Value).Order().ToArray();
        var pages = Regex.Matches(Html, @"class=""set-page[^""]*"" data-page=""(\w+)""")
            .Select(m => m.Groups[1].Value).Order().ToArray();
        Assert.NotEmpty(pages);
        Assert.Equal(pages, items);
        Assert.Equal(pages.Length, pages.Distinct().Count());
    }

    // The cards that loaders and feature scripts look up by id are all still on a settings page
    [Theory]
    [InlineData("monitoredPathsList")]
    [InlineData("recordingSettingsSection")]
    [InlineData("securityLogSection")]
    [InlineData("agentsSection")]
    [InlineData("alertsSettingsSection")]
    [InlineData("reportsSettingsSection")]
    [InlineData("integritySettingsSection")]
    [InlineData("usermgmtSettingsSection")]
    [InlineData("retentionDaysInput")]
    [InlineData("dnsServerInput")]
    [InlineData("appInfoSection")]
    [InlineData("webTlsSection")]
    [InlineData("auditLogSection")]
    public void Settings_cards_are_inside_the_pages(string id)
    {
        var pages = Html.IndexOf("id=\"settingsPages\"", StringComparison.Ordinal);
        var end = Html.IndexOf("<!-- Create User Modal -->", StringComparison.Ordinal);
        var at = Html.IndexOf($"id=\"{id}\"", StringComparison.Ordinal);
        Assert.True(pages > 0 && at > pages && at < end, id);
    }

    [Fact]
    public void The_totals_tab_switches_between_files_folders_and_users()
    {
        Assert.Contains("data-group=\"totals\"", Html);
        foreach (var tab in new[] { "files", "folders", "users" })
        {
            Assert.Contains($"data-tab=\"{tab}\" onclick=\"switchTab('{tab}', this)\"", Html);
            Assert.Contains($"id=\"tab-{tab}\"", Html);
        }
    }

    [Fact]
    public void Every_hint_key_exists_in_both_languages()
    {
        var gui = Html + string.Concat(Directory.GetFiles(Repo(Path.Combine("wwwroot", "js")), "*.js").Select(File.ReadAllText));
        var keys = Regex.Matches(gui, @"(?:data-hint=""|\bhintHtml\(')([\w.]+)").Select(m => m.Groups[1].Value).Distinct().ToArray();
        Assert.NotEmpty(keys);
        var lang = AllLang();
        foreach (var key in keys)
            Assert.Equal(2, Regex.Matches(lang, $@"(?m)^\s+'{Regex.Escape(key)}':").Count);
    }

    // A details key without its hint would never be shown; each one comes in both languages
    [Fact]
    public void Every_details_text_belongs_to_a_hint()
    {
        var lang = AllLang();
        var more = Regex.Matches(lang, @"(?m)^\s+'([\w.]+)More':").Select(m => m.Groups[1].Value).Distinct().ToArray();
        Assert.NotEmpty(more);
        foreach (var key in more)
        {
            Assert.Equal(2, Regex.Matches(lang, $@"(?m)^\s+'{Regex.Escape(key)}More':").Count);
            Assert.Equal(2, Regex.Matches(lang, $@"(?m)^\s+'{Regex.Escape(key)}':").Count);
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
