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

    // "D:\Share\" -> "D:\Share", but a drive root keeps its backslash ("D:\"); "/srv/share/" -> "/srv/share"
    public static string Normalize(string path) => PathText.Normalize(path);

    public static bool Contains(IReadOnlyList<ScopeEntry> scope, string server, string path) =>
        scope.Any(e => (e.Server == null || e.Server.Equals(server, StringComparison.OrdinalIgnoreCase))
                       && PathText.IsUnder(path, e.Path));

    // Records whose path is one of the folders or inside one, on the entry's server if it names one.
    // Windows paths match case-insensitively (SQLite LIKE ignores ASCII case, as Windows does);
    // Linux paths ("/srv/share") match exactly.
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

        var substring = typeof(string).GetMethod(nameof(string.Substring), [typeof(int), typeof(int)])!;
        Expression StartsExactly(string prefix) => Expression.AndAlso(
            Expression.GreaterThanOrEqual(Expression.Property(filePath, nameof(string.Length)), Expression.Constant(prefix.Length)),
            Expression.Equal(Expression.Call(filePath, substring, Expression.Constant(0), Expression.Constant(prefix.Length)),
                Expression.Constant(prefix)));

        Expression body = Expression.Constant(false);
        foreach (var entry in scope)
        {
            var sep = PathText.SeparatorOf(entry.Path);
            var folder = entry.Path.TrimEnd(sep);
            Expression match = PathText.IsUnix(entry.Path)
                ? Expression.OrElse(Expression.Equal(filePath, Expression.Constant(entry.Path)), StartsExactly(folder + sep))
                : Expression.OrElse(Like(Escape(folder)), Like(Escape(folder + sep) + "%"));
            if (entry.Server != null)
                match = Expression.AndAlso(Expression.Equal(serverName, Expression.Constant(entry.Server)), match);
            body = Expression.OrElse(body, match);
        }
        return query.Where(Expression.Lambda<Func<AccessRecord, bool>>(body, r));
    }

    public static string Escape(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

// The signed-in user's scope: null when they may see everything (Admins, and Viewers set to all folders),
// otherwise their folders; a Viewer without folders gets an empty list, which matches nothing.
// Synchronous: a primary-key lookup in a local SQLite file, used once per request.
public class UserScopeService(AccessDbContext db)
{
    public List<ScopeEntry>? Get(ClaimsPrincipal user)
    {
        if (user.IsInRole("Admin")) return null;
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier);
        var row = id == null ? null : db.UserScopes.Find(id);
        return Resolve(row);
    }

    public static List<ScopeEntry>? Resolve(UserScope? row) =>
        row is { AllFolders: true } ? null : AccessScope.Parse(row?.Paths);

    public IQueryable<AccessRecord> Records(ClaimsPrincipal user) =>
        Get(user) is { } scope ? AccessScope.Apply(db.AccessRecords, scope) : db.AccessRecords;
}
