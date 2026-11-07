using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;

namespace FileAccessMonitor.Services;

// Browsers kept an old app.js after an update (the files are served without a caching rule, so the
// browser guesses from Last-Modified). The GUI's own pages, scripts and styles are sent with
// "Cache-Control: no-cache": the browser keeps them but asks every time (ETag / Last-Modified), so a
// changed file is loaded and an unchanged one costs a 304. Vendor libraries (wwwroot/lib) and
// fonts/images stay cacheable as before.
public static class StaticFileCache
{
    public static StaticFileOptions CreateOptions() => new() { OnPrepareResponse = Prepare };

    private static readonly string[] Revalidated = [".html", ".js", ".css"];

    // fileName: the file served (for the fallback to index.html it differs from the request path)
    public static bool MustRevalidate(string fileName, PathString requestPath) =>
        Revalidated.Contains(Path.GetExtension(fileName), StringComparer.OrdinalIgnoreCase)
        && !requestPath.StartsWithSegments("/lib", StringComparison.OrdinalIgnoreCase);

    public static void Prepare(StaticFileResponseContext context)
    {
        if (MustRevalidate(context.File.Name, context.Context.Request.Path))
            context.Context.Response.Headers.CacheControl = "no-cache";
    }
}
