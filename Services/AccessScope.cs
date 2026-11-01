using System.Linq.Expressions;
using System.Security.Claims;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// One folder a Viewer may see: on one file server, or on every server when Server is null.
// Stored one per line as "SERVER|D:\Share" or "D:\Share" ('|' cannot appear in either part).
public sealed record ScopeEntry(string? Server, string Path)
{
    public override string ToString() => Server == null ? Path : $"{Server}|{Path}";
}

// Restricts what a Viewer sees to the folders assigned to them (UserScope).
public static class AccessScope
{
    public static List<ScopeEntry> Parse(string? text) => Parse(
        (text ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    public static List<ScopeEntry> Parse(IEnumerable<string> lines) => lines
        .Select(line =>
        {
            var bar = line.IndexOf('|');
            var server = bar < 0 ? null : line[..bar].Trim();
            return new ScopeEntry(string.IsNullOrEmpty(server) ? null : server.ToUpperInvariant(),
                Normalize(bar < 0 ? line : line[(bar + 1)..]));
        })
        .Where(e => e.Path.Length > 0)
        .DistinctBy(e => e.ToString().ToUpperInvariant())
        .ToList();

    // "D:\Share\" -> "D:\Share", but a drive root keeps its backslash ("D:\")
    public static string Normalize(string path)
    {
        var p = path.Trim().TrimEnd('\\');
        return p.EndsWith(':') ? p + "\\" : p;
    }

    public static bool Contains(IReadOnlyList<ScopeEntry> scope, string server, string path) =>
        scope.Any(e => (e.Server == null || e.Server.Equals(server, StringComparison.OrdinalIgnoreCase))
                       && EventLogCollectorService.IsUnderPath(path, e.Path));

    // Records whose path is one of the folders or inside one, matched case-insensitively
    // (SQLite LIKE ignores ASCII case, as Windows paths do), on the entry's server if it names one.
    public static IQueryable<AccessRecord> Apply(IQueryable<AccessRecord> query, IReadOnlyList<ScopeEntry> scope)
    {
        var r = Expression.Parameter(typeof(AccessRecord), "r");
        var filePath = Expression.Property(r, nameof(AccessRecord.FilePath));
        var serverName = Expression.Call(Expression.Property(r, nameof(AccessRecord.ServerName)),
            typeof(string).GetMethod(nameof(string.ToUpper), Type.EmptyTypes)!);
        var like = typeof(DbFunctionsExtensions).GetMethod(nameof(DbFunctionsExtensions.Like),
            [typeof(DbFunctions), typeof(string), typeof(string), typeof(string)])!;
        Expression Like(string pattern) => Expression.Call(like,
            Expression.Constant(EF.Functions), filePath, Expression.Constant(pattern), Expression.Constant("\\"));

        Expression body = Expression.Constant(false);
        foreach (var entry in scope)
        {
            var folder = entry.Path.TrimEnd('\\');
            Expression match = Expression.OrElse(Like(Escape(folder)), Like(Escape(folder + "\\") + "%"));
            if (entry.Server != null)
                match = Expression.AndAlso(Expression.Equal(serverName, Expression.Constant(entry.Server)), match);
            body = Expression.OrElse(body, match);
        }
        return query.Where(Expression.Lambda<Func<AccessRecord, bool>>(body, r));
    }

    public static string Escape(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

// The signed-in user's scope, or null when they may see everything.
// Synchronous: a primary-key lookup in a local SQLite file, used once per request.
public class UserScopeService(AccessDbContext db)
{
    public List<ScopeEntry>? Get(ClaimsPrincipal user)
    {
        if (user.IsInRole("Admin")) return null;
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier);
        var row = id == null ? null : db.UserScopes.Find(id);
        var scope = AccessScope.Parse(row?.Paths);
        return scope.Count == 0 ? null : scope;
    }

    public IQueryable<AccessRecord> Records(ClaimsPrincipal user) =>
        Get(user) is { } scope ? AccessScope.Apply(db.AccessRecords, scope) : db.AccessRecords;
}
