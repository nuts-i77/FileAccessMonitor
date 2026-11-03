using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class ReportHtmlTests
{
    private const string Hostile = @"D:\<script>alert(1)</script>\""onmouseover=x><img src=x onerror=1>.txt";
    private const string HostileUser = "<b>evil</b>&co";
    private static readonly DateTime Slot = ReportTestHost.Monday;

    // Every section filled, with attacker-controlled names
    private static ReportData Full(string language)
    {
        var d = new ReportData { Request = ReportTestHost.Weekly(language: language), ServerLabel = "FS<1>" };
        d.Summary.Total = 15; d.Summary.PreviousTotal = 10; d.Summary.Denied = 2; d.Summary.UniqueFiles = 3; d.Summary.ActiveUsers = 2;
        d.Summary.PermissionChanges = 1;
        d.Summary.ByType = new() { ["Read"] = 10, ["Write"] = 5, ["Weird"] = 1 };
        d.Summary.Changes = [new ReportChange(Slot.AddDays(-1), HostileUser, "FS01", Hostile)];
        d.AlertGroups = [new ReportAlertGroup("Ransomware[extension]", 2, Slot)];
        d.AlertRows = [new ReportAlertRow(Slot, "Ransomware[extension]", "FS01", HostileUser, "40")];
        d.TopFiles = [new ReportTopFile("FS01", Hostile, 9, 5, 4)];
        d.TopFolders = [new ReportTopFolder("FS01", Hostile, 9)];
        d.TopUsers = [new ReportTopUser(HostileUser, 9, 5, 4)];
        d.Agents = [new ReportAgent("A<1>", "Win", "1.0", null, true, false, false, 2, true), new ReportAgent("A2", "", "", Slot, false, true, null, 0, false)];
        d.Permissions = new ReportPermissions
        {
            High = 1, Medium = 0, NeverScanned = ["FS01: " + Hostile],
            Roots = [new ReportPermRoot("FS01", Hostile, Slot.AddDays(-30), true, 1, 0)],
            Top = [new BroadRow("FS01", Hostile, Hostile, HostileUser, "Allow", "Modify", "high", true)],
        };
        d.Integrity = new IntegritySummary("broken", Slot, Slot, 1, "seq 5 <x>", 9, "ab", 3, "FAM-ANCHOR v1 server=<x> seq=9");
        return d;
    }

    [Theory]
    [InlineData("en")]
    [InlineData("ja")]
    public void Hostile_names_are_encoded_in_the_html_and_present_in_the_text(string lang)
    {
        var (html, text) = ReportHtml.Render(Full(lang), ["big.csv"], csvCut: true);
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain("<b>evil", html);
        Assert.DoesNotContain("onmouseover=x>", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("&lt;b&gt;evil&lt;/b&gt;&amp;co", html);
        Assert.Contains("FS&lt;1&gt;", html);
        Assert.Contains("FAM-ANCHOR v1 server=&lt;x&gt;", html);

        // plain text says the same, unencoded
        Assert.Contains(Hostile, text);
        Assert.Contains(HostileUser, text);
        Assert.Contains("FAM-ANCHOR v1 server=<x> seq=9", text);
        Assert.Contains("big.csv", text);
        Assert.Contains("+50%", text);
    }

    [Theory]
    [InlineData("en")]
    [InlineData("ja")]
    public void Every_text_of_the_report_has_a_translation(string lang)
    {
        var (html, text) = ReportHtml.Render(Full(lang), ["big.csv"], csvCut: true);
        Assert.DoesNotMatch(@"\breport\.[a-z]", text);
        Assert.DoesNotMatch(@"\breport\.[a-z]", html);
        Assert.DoesNotContain("hist.", text);
    }

    [Fact]
    public void The_html_is_conservative_for_mail_clients()
    {
        var (html, _) = ReportHtml.Render(Full("en"));
        Assert.Contains("max-width:720px", html);
        foreach (var forbidden in new[] { "<img", "<link", "<script", "url(", "http://", "https://", "@import", "<style" })
            Assert.DoesNotContain(forbidden, html);
        // colours are set explicitly (text and background), so a dark-mode client cannot make it unreadable
        Assert.Contains("background-color:#ffffff", html);
        Assert.Contains("color:#1f2937", html);
    }

    [Fact]
    public void Language_follows_the_setting()
    {
        var en = ReportHtml.Render(Full("en"));
        var ja = ReportHtml.Render(Full("ja"));
        Assert.Contains("Summary", en.Html);
        Assert.Contains("lang=\"en\"", en.Html);
        Assert.Contains("概要", ja.Html);
        Assert.Contains("lang=\"ja\"", ja.Html);
        Assert.Contains("Weekly report", ReportHtml.Subject(Full("en")));
        Assert.Contains("週次レポート", ReportHtml.Subject(Full("ja")));
        Assert.DoesNotContain("機械", ja.Text);
    }

    [Fact]
    public void Deltas_show_new_activity_and_percentages()
    {
        var d = new ReportData { Request = ReportTestHost.Weekly() };
        d.Summary.Total = 5;
        d.Summary.PreviousTotal = 0;
        d.Summary.Denied = 1;
        d.Summary.PreviousDenied = 4;
        var text = ReportHtml.Render(d).Text;
        Assert.Contains("5 (previous period: 0, new)", text);
        Assert.Contains("1 (previous period: 4, -75%)", text);
    }

    [Fact]
    public void The_webhook_summary_has_numbers_only()
    {
        var text = ReportHtml.WebhookText(Full("en"));
        Assert.Contains("15", text);
        Assert.Contains("Broken", text);
        Assert.DoesNotContain("script", text);
        Assert.DoesNotContain("evil", text);
        Assert.DoesNotContain("FAM-ANCHOR", text);
    }
}

public class ReportAttachmentTests
{
    [Fact]
    public void Values_that_excel_would_run_are_neutralized_and_the_file_has_a_bom()
    {
        var (file, cut) = ReportAttachments.Csv("x.csv", ["a", "b"], [["=cmd|' /C calc'!A0", "+1"], ["@SUM(1)", "ok \"q\""]]);
        Assert.False(cut);
        Assert.Equal("text/csv; charset=utf-8", file.ContentType);
        Assert.Equal([0xEF, 0xBB, 0xBF], file.Content.Take(3).Select(b => (int)b));
        var text = System.Text.Encoding.UTF8.GetString(file.Content);
        Assert.Contains("\"'=cmd|' /C calc'!A0\"", text);
        Assert.Contains("\"'+1\"", text);
        Assert.Contains("\"'@SUM(1)\"", text);
        Assert.Contains("\"ok \"\"q\"\"\"", text);
    }

    [Fact]
    public void A_file_is_cut_at_the_row_cap()
    {
        var rows = Enumerable.Range(0, ReportBuilder.MaxCsvRows + 5).Select(i => new string?[] { i.ToString() });
        var (file, cut) = ReportAttachments.Csv("x.csv", ["n"], rows);
        Assert.True(cut);
        var text = System.Text.Encoding.UTF8.GetString(file.Content).TrimEnd();
        Assert.Equal(ReportBuilder.MaxCsvRows + 1, text.Split('\n').Length);   // header + cap
    }

    [Fact]
    public void The_largest_files_are_dropped_first_until_the_total_fits()
    {
        static MailAttachmentData F(string name, int size) => new(name, new byte[size], "text/csv");
        var dropped = new List<string>();
        var kept = ReportAttachments.Fit([F("a.csv", 100), F("big.csv", 500), F("mid.csv", 300)], 450, dropped);
        Assert.Equal(["big.csv"], dropped);
        Assert.Equal(["a.csv", "mid.csv"], kept.Select(f => f.FileName));

        dropped.Clear();
        var one = ReportAttachments.Fit([F("a.csv", 100), F("big.csv", 500), F("mid.csv", 300)], 150, dropped);
        Assert.Equal(["a.csv"], one.Select(f => f.FileName));
        Assert.Equal(["big.csv", "mid.csv"], dropped);
    }
}
