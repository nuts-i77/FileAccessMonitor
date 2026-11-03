using System.Globalization;
using System.Net;
using System.Text;

namespace FileAccessMonitor.Services;

// Renders a ReportData as an HTML mail and a plain-text alternative from one model, so both say the same.
// The HTML is conservative for mail clients: tables, inline CSS, light colours set explicitly (so a
// dark-mode client does not make text unreadable), no images, no external resources. File and user names
// come from the monitored file servers (an attacker can name a file anything): everything is HTML-encoded.
public static class ReportHtml
{
    // Local time for the times in the report (the server's)
    internal static TimeZoneInfo Zone { get; set; } = TimeZoneInfo.Local;

    private abstract record Block;
    private sealed record Note(string Text, string Tone = "") : Block;                 // "" | warn | bad | ok
    private sealed record Facts(List<(string Label, string Value)> Items) : Block;
    private sealed record Table(string[] Headers, List<string[]> Rows) : Block;
    private sealed record Section(string Title, List<Block> Blocks);

    public static string Subject(ReportData d)
    {
        var req = d.Request;
        return Messages.GetIn(req.Language, "report.subject", Messages.GetIn(req.Language, "report.freq." + req.Frequency),
            req.FromLocal.ToString("yyyy-MM-dd"), req.ToLocal.ToString("yyyy-MM-dd"), d.ServerLabel);
    }

    public static (string Html, string Text) Render(ReportData d, IReadOnlyList<string>? droppedAttachments = null, bool csvCut = false)
    {
        var lang = d.Request.Language;
        string L(string key, params object?[] args) => Messages.GetIn(lang, key, args);
        var sections = Sections(d, L, droppedAttachments ?? [], csvCut);
        var title = L("report.title");
        var period = L("report.period", Time(d.Request.FromLocal), Time(d.Request.ToLocal));
        return (Html(d, title, period, sections, L), Text(d, title, period, sections, L));
    }

    // A few lines for the webhook: numbers only, no file or folder names
    public static string WebhookText(ReportData d)
    {
        string L(string key, params object?[] args) => Messages.GetIn(d.Request.Language, key, args);
        var s = d.Summary;
        var lines = new List<string>
        {
            L("report.period", Time(d.Request.FromLocal), Time(d.Request.ToLocal)),
            $"{L("report.sum.total")}: {Num(s.Total)}",
            $"{L("report.sum.denied")}: {Num(s.Denied)}",
            $"{L("report.sum.changes")}: {Num(s.PermissionChanges)}",
        };
        if (d.Permissions != null) lines.Add($"{L("report.perm.high")}: {Num(d.Permissions.High)}");
        if (d.Integrity != null) lines.Add($"{L("report.integrity.title")}: {L("report.integrity.state." + d.Integrity.State)}");
        return string.Join("\n", lines);
    }

    // ---- the content

    private static List<Section> Sections(ReportData d, Func<string, object?[], string> L0, IReadOnlyList<string> dropped, bool csvCut)
    {
        string L(string key, params object?[] args) => L0(key, args);
        var s = d.Summary;
        var list = new List<Section>();

        if (d.Scoped)
            list.Add(new Section(L("report.scoped.title"), [new Note(L("report.scoped"), "warn")]));

        var sum = new List<Block>
        {
            new Facts(
            [
                (L("report.sum.total"), WithDelta(s.Total, s.PreviousTotal, L)),
                (L("report.sum.files"), Num(s.UniqueFiles)),
                (L("report.sum.users"), Num(s.ActiveUsers)),
                (L("report.sum.denied"), WithDelta(s.Denied, s.PreviousDenied, L)),
                (L("report.sum.changes"), WithDelta(s.PermissionChanges, s.PreviousPermissionChanges, L)),
            ]),
        };
        if (s.ByType.Count > 0)
            sum.Add(new Facts(s.ByType.OrderByDescending(kv => kv.Value)
                .Select(kv => (TypeName(kv.Key, L), Num(kv.Value))).ToList()));
        else
            sum.Add(new Note(L("report.empty")));
        list.Add(new Section(L("report.sum.title"), sum));

        if (s.Changes.Count > 0)
            list.Add(new Section(L("report.changes.title"),
                [new Table([L("report.col.time"), L("report.col.user"), L("report.col.server"), L("report.col.path")],
                    s.Changes.Select(c => new[] { Time(c.Time), c.User, c.Server, c.Path }).ToList())]));

        if (d.AlertGroups != null)
        {
            var blocks = new List<Block>();
            if (d.AlertGroups.Count == 0) blocks.Add(new Note(L("report.alerts.none")));
            else
            {
                blocks.Add(new Table([L("report.col.type"), L("report.col.count"), L("report.col.last")],
                    d.AlertGroups.Select(g => new[] { g.Type, Num(g.Count), Time(g.Last) }).ToList()));
                if (d.AlertRows.Count > 0)
                    blocks.Add(new Table([L("report.col.time"), L("report.col.type"), L("report.col.server"), L("report.col.user"), L("report.col.count")],
                        d.AlertRows.Select(a => new[] { Time(a.Time), a.Type, a.Server, a.User, a.Count }).ToList()));
            }
            list.Add(new Section(L("report.alerts.title"), blocks));
        }

        if (d.TopFiles.Count > 0)
            list.Add(new Section(L("report.top.files"),
                [new Table([L("report.col.path"), L("report.col.server"), L("report.col.total"), L("report.col.reads"), L("report.col.writes")],
                    d.TopFiles.Select(f => new[] { f.Path, f.Server, Num(f.Total), Num(f.Reads), Num(f.Writes) }).ToList())]));
        if (d.TopFolders.Count > 0)
            list.Add(new Section(L("report.top.folders"),
                [new Table([L("report.col.folder"), L("report.col.server"), L("report.col.total")],
                    d.TopFolders.Select(f => new[] { f.Folder, f.Server, Num(f.Total) }).ToList())]));
        if (d.TopUsers.Count > 0)
            list.Add(new Section(L("report.top.users"),
                [new Table([L("report.col.user"), L("report.col.total"), L("report.col.reads"), L("report.col.writes")],
                    d.TopUsers.Select(u => new[] { u.User, Num(u.Total), Num(u.Reads), Num(u.Writes) }).ToList())]));

        if (d.Agents != null && d.Agents.Count > 0)
            list.Add(new Section(L("report.agents.title"),
                [new Table([L("report.col.name"), L("report.col.os"), L("report.col.version"), L("report.col.lastSeen"), L("report.col.state")],
                    d.Agents.Select(a => new[]
                    {
                        a.Name, a.Os, a.Version, a.LastSeen == null ? "-" : Time(a.LastSeen.Value),
                        string.Join(", ", AgentFlags(a, L)),
                    }).ToList())]));

        list.Add(PermissionSection(d, L));

        if (d.Integrity is { } i)
        {
            var facts = new List<(string, string)>
            {
                (L("report.integrity.status"), L("report.integrity.state." + i.State)),
                (L("report.integrity.verified"), i.VerifiedUpTo == null ? "-" : Time(i.VerifiedUpTo.Value)),
                (L("report.integrity.breaks"), Num(i.Breaks)),
            };
            if (i.FirstBreak != null) facts.Add((L("report.integrity.first"), i.FirstBreak));
            if (i.LegacyRows > 0) facts.Add((L("report.integrity.legacy"), Num((int)Math.Min(i.LegacyRows, int.MaxValue))));
            var blocks = new List<Block> { new Facts(facts) };
            if (i.State == "broken") blocks.Insert(0, new Note(L("report.integrity.brokenNote"), "bad"));
            if (i.AnchorLine != null) blocks.Add(new Note(L("report.integrity.anchor") + "\n" + i.AnchorLine));
            list.Add(new Section(L("report.integrity.title"), blocks));
        }

        var tail = new List<Block>();
        if (dropped.Count > 0) tail.Add(new Note(L("report.attachments.dropped", string.Join(", ", dropped)), "warn"));
        if (csvCut) tail.Add(new Note(L("report.attachments.cut", ReportBuilder.MaxCsvRows.ToString("N0", CultureInfo.InvariantCulture)), "warn"));
        if (tail.Count > 0) list.Add(new Section(L("report.attachments.title"), tail));
        return list;
    }

    private static Section PermissionSection(ReportData d, Func<string, object?[], string> L0)
    {
        string L(string key, params object?[] args) => L0(key, args);
        var title = L("report.perm.title");
        var p = d.Permissions;
        if (p == null) return new Section(title, [new Note(L("report.perm.unavailable"), "warn")]);

        var blocks = new List<Block> { new Note(L("report.perm.note")) };
        if (p.Roots.Count == 0)
            blocks.Add(new Note(L("report.perm.none")));
        else
        {
            blocks.Add(new Facts([(L("report.perm.high"), Num(p.High)), (L("report.perm.medium"), Num(p.Medium))]));
            blocks.Add(new Table([L("report.col.server"), L("report.col.folder"), L("report.col.scanned"), L("report.perm.high"), L("report.perm.medium")],
                p.Roots.Select(r => new[]
                {
                    r.Server, r.Root, Time(r.ScannedAt) + (r.Old ? " (" + L("report.perm.old") + ")" : ""), Num(r.High), Num(r.Medium),
                }).ToList()));
            if (p.Top.Count > 0)
                blocks.Add(new Table([L("report.col.path"), L("report.col.principal"), L("report.col.level"), L("report.col.server")],
                    p.Top.Select(r => new[] { r.Path, r.Principal, r.Level + (r.InheritanceBroken ? " *" : ""), r.Server }).ToList()));
            else
                blocks.Add(new Note(L("report.perm.noBroad"), "ok"));
        }
        foreach (var never in p.NeverScanned)
            blocks.Add(new Note(L("report.perm.never", never), "warn"));
        return new Section(title, blocks);
    }

    private static IEnumerable<string> AgentFlags(ReportAgent a, Func<string, object?[], string> L)
    {
        yield return a.Disabled ? L("report.agents.disabled", []) : a.Offline ? L("report.agents.offline", []) : L("report.agents.online", []);
        if (a.AuditOk == false) yield return L("report.agents.auditOff", []);
        if (a.Outbox > 0) yield return L("report.agents.outbox", [a.Outbox]);
        if (a.Outdated) yield return L("report.agents.outdated", []);
    }

    private static string TypeName(string type, Func<string, object?[], string> L)
    {
        var key = "report.type." + type;
        var text = L(key, []);
        return text == key ? type : text;
    }

    private static string WithDelta(int now, int before, Func<string, object?[], string> L)
    {
        string delta = before == 0
            ? now == 0 ? "0%" : L("report.delta.new", [])
            : ((now - before) * 100.0 / before).ToString("+0;-0;0", CultureInfo.InvariantCulture) + "%";
        return L("report.sum.vsPrevious", [Num(now), Num(before), delta]);
    }

    private static string Num(int n) => n.ToString("N0", CultureInfo.InvariantCulture);

    private static string Time(DateTime t) =>
        t.Kind == DateTimeKind.Utc ? TimeZoneInfo.ConvertTimeFromUtc(t, Zone).ToString("yyyy-MM-dd HH:mm") : t.ToString("yyyy-MM-dd HH:mm");

    // ---- plain text

    private static string Text(ReportData d, string title, string period, List<Section> sections, Func<string, object?[], string> L)
    {
        var sb = new StringBuilder();
        sb.AppendLine(title);
        sb.AppendLine(period);
        sb.AppendLine(L("report.server", [d.ServerLabel]));
        foreach (var section in sections)
        {
            sb.AppendLine().AppendLine(section.Title).AppendLine(new string('-', Math.Min(section.Title.Length * 2, 60)));
            foreach (var block in section.Blocks)
            {
                switch (block)
                {
                    case Note n:
                        sb.AppendLine(n.Text);
                        break;
                    case Facts f:
                        foreach (var (label, value) in f.Items) sb.AppendLine($"{label}: {value}");
                        break;
                    case Table t:
                        sb.AppendLine(string.Join(" | ", t.Headers));
                        foreach (var row in t.Rows) sb.AppendLine(string.Join(" | ", row));
                        break;
                }
            }
        }
        sb.AppendLine().AppendLine(L("report.footer", [AppInfo.Version]));
        return sb.ToString();
    }

    // ---- HTML

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private const string Font = "font-family:'Segoe UI',Meiryo,'Hiragino Sans',Arial,sans-serif;";

    private static string Html(ReportData d, string title, string period, List<Section> sections, Func<string, object?[], string> L)
    {
        var lang = d.Request.Language.StartsWith("ja", StringComparison.OrdinalIgnoreCase) ? "ja" : "en";
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html lang=\"").Append(lang).Append("\"><head><meta charset=\"utf-8\">")
          .Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light\">")
          .Append("<title>").Append(E(title)).Append("</title></head>")
          .Append("<body style=\"margin:0;padding:0;background-color:#f3f4f6;color:#1f2937;").Append(Font).Append("\">")
          .Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#f3f4f6\" style=\"background-color:#f3f4f6;\"><tr><td align=\"center\" style=\"padding:16px 8px;\">")
          .Append("<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#ffffff\" style=\"max-width:720px;background-color:#ffffff;border:1px solid #d1d5db;\">");

        sb.Append("<tr><td bgcolor=\"#1f3a5f\" style=\"background-color:#1f3a5f;color:#ffffff;padding:16px 20px;").Append(Font).Append("\">")
          .Append("<div style=\"font-size:20px;font-weight:bold;color:#ffffff;\">").Append(E(title)).Append("</div>")
          .Append("<div style=\"font-size:13px;color:#dbe4f0;margin-top:4px;\">").Append(E(period)).Append(" &middot; ").Append(E(d.ServerLabel)).Append("</div></td></tr>");

        foreach (var section in sections)
        {
            sb.Append("<tr><td style=\"padding:16px 20px 4px 20px;").Append(Font).Append("\">")
              .Append("<div style=\"font-size:15px;font-weight:bold;color:#1f3a5f;border-bottom:1px solid #d1d5db;padding-bottom:4px;\">").Append(E(section.Title)).Append("</div></td></tr>");
            foreach (var block in section.Blocks)
            {
                sb.Append("<tr><td style=\"padding:6px 20px;font-size:13px;line-height:1.5;color:#1f2937;").Append(Font).Append("\">");
                switch (block)
                {
                    case Note n: AppendNote(sb, n); break;
                    case Facts f: AppendFacts(sb, f); break;
                    case Table t: AppendTable(sb, t); break;
                }
                sb.Append("</td></tr>");
            }
        }
        sb.Append("<tr><td style=\"padding:16px 20px;font-size:11px;color:#6b7280;").Append(Font).Append("\">")
          .Append(E(L("report.footer", [AppInfo.Version]))).Append("</td></tr></table></td></tr></table></body></html>");
        return sb.ToString();
    }

    private static void AppendNote(StringBuilder sb, Note n)
    {
        var (bg, fg, border) = n.Tone switch
        {
            "warn" => ("#fff4e5", "#7a4b00", "#f0c36d"),
            "bad" => ("#fdecea", "#8a1c1c", "#e5a3a0"),
            "ok" => ("#eaf6ec", "#1e5b2b", "#a6d6ae"),
            _ => ("#ffffff", "#374151", "#ffffff"),
        };
        sb.Append("<div style=\"background-color:").Append(bg).Append(";color:").Append(fg).Append(";border:1px solid ").Append(border)
          .Append(";padding:6px 10px;word-break:break-all;\">").Append(E(n.Text).Replace("\n", "<br>")).Append("</div>");
    }

    private static void AppendFacts(StringBuilder sb, Facts f)
    {
        sb.Append("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\">");
        foreach (var (label, value) in f.Items)
            sb.Append("<tr><td style=\"padding:2px 12px 2px 0;color:#4b5563;width:50%;\">").Append(E(label))
              .Append("</td><td style=\"padding:2px 0;font-weight:bold;color:#111827;\">").Append(E(value)).Append("</td></tr>");
        sb.Append("</table>");
    }

    private static void AppendTable(StringBuilder sb, Table t)
    {
        sb.Append("<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"100%\" style=\"border-collapse:collapse;font-size:12px;\"><tr>");
        foreach (var h in t.Headers)
            sb.Append("<td bgcolor=\"#eef2f7\" style=\"background-color:#eef2f7;color:#1f2937;padding:4px 6px;border:1px solid #d1d5db;font-weight:bold;\">").Append(E(h)).Append("</td>");
        sb.Append("</tr>");
        foreach (var row in t.Rows)
        {
            sb.Append("<tr>");
            foreach (var cell in row)
                sb.Append("<td style=\"padding:4px 6px;border:1px solid #d1d5db;color:#1f2937;word-break:break-all;\">").Append(E(cell)).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</table>");
    }
}
