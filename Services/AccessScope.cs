using System.Linq.Expressions;
using System.Security.Claims;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// Restricts what a Viewer sees to the folders assigned to them (UserScope).
public static class AccessScope
{
    public static List<string> ParsePaths(string? text) =>
        (text ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(Normalize).Where(p => p.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    // "D:\Share\" -> "D:\Share", but a drive root keeps its backslash ("D:\")
    public static string Normalize(string path)
    {
        var p = path.Trim().TrimEnd('\\');
        return p.EndsWith(':') ? p + "\\" : p;
    }

    public static bool Contains(IReadOnlyList<string> scope, string path) =>
        scope.Any(root => EventLogCollectorService.IsUnderPath(path, root));

    // Records whose path is one of the folders or inside one, matched case-insensitively
    // (SQLite LIKE ignores ASCII case, as Windows paths do).
    public static IQueryable<AccessRecord> Apply(IQueryable<AccessRecord> query, IReadOnlyList<string> scope)
    {
        var r = Expression.Parameter(typeof(AccessRecord), "r");
        var filePath = Expression.Property(r, nameof(AccessRecord.FilePath));
        var like = typeof(DbFunctionsExtensions).GetMethod(nameof(DbFunctionsExtensions.Like),
            [typeof(DbFunctions), typeof(string), typeof(string), typeof(string)])!;
        Expression Like(string pattern) => Expression.Call(like,
            Expression.Constant(EF.Functions), filePath, Expression.Constant(pattern), Expression.Constant("\\"));

        Expression body = Expression.Constant(false);
        foreach (var root in scope)
        {
            var folder = root.TrimEnd('\\');
            body = Expression.OrElse(body, Expression.OrElse(Like(Escape(folder)), Like(Escape(folder + "\\") + "%")));
        }
        return query.Where(Expression.Lambda<Func<AccessRecord, bool>>(body, r));
    }

    public static string Escape(string s) => s.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
}

// The signed-in user's scope, or null when they may see everything.
// Synchronous: a primary-key lookup in a local SQLite file, used once per request.
public class UserScopeService(AccessDbContext db)
{
    public List<string>? Get(ClaimsPrincipal user)
    {
        if (user.IsInRole("Admin")) return null;
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier);
        var row = id == null ? null : db.UserScopes.Find(id);
        var paths = AccessScope.ParsePaths(row?.Paths);
        return paths.Count == 0 ? null : paths;
    }

    public IQueryable<AccessRecord> Records(ClaimsPrincipal user) =>
        Get(user) is { } scope ? AccessScope.Apply(db.AccessRecords, scope) : db.AccessRecords;
}
