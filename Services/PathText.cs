namespace FileAccessMonitor.Services;

// Paths as recorded: Windows ("D:\Share\a.txt", case-insensitive) or, from Linux agents,
// "/srv/share/a.txt" (case-sensitive)
public static class PathText
{
    public static bool IsUnix(string path) => path.StartsWith('/');

    public static char SeparatorOf(string path) => IsUnix(path) ? '/' : '\\';

    public static StringComparison ComparisonOf(string path) =>
        IsUnix(path) ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;

    public static StringComparer ComparerOf(string path) =>
        IsUnix(path) ? StringComparer.Ordinal : StringComparer.OrdinalIgnoreCase;

    // "D:\Share\" -> "D:\Share", "/srv/share/" -> "/srv/share"; roots keep their separator ("D:\", "/")
    public static string Normalize(string path)
    {
        var p = path.Trim();
        if (IsUnix(p))
        {
            var t = p.TrimEnd('/');
            return t.Length == 0 ? "/" : t;
        }
        p = p.TrimEnd('\\');
        return p.EndsWith(':') ? p + "\\" : p;
    }

    // True if path is root itself or inside it (D:\Share matches D:\Share\a.txt but not D:\Share2\a.txt)
    public static bool IsUnder(string path, string root)
    {
        var r = Normalize(root);
        var sep = SeparatorOf(r);
        var trimmed = r.TrimEnd(sep);
        var comparison = ComparisonOf(r);
        return path.Equals(r, comparison) || path.StartsWith(trimmed + sep, comparison);
    }
}
