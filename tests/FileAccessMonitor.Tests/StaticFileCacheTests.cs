using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;

namespace FileAccessMonitor.Tests;

// After an update browsers must load the new app.js: the GUI's own files are revalidated on every load
public class StaticFileCacheTests
{
    [Theory]
    [InlineData("index.html", "/", true)]
    [InlineData("index.html", "/some/route", true)]    // the fallback to index.html
    [InlineData("app.js", "/js/app.js", true)]
    [InlineData("en.js", "/lang/en.js", true)]
    [InlineData("APP.JS", "/js/APP.JS", true)]
    [InlineData("login.html", "/login.html", true)]
    [InlineData("site.css", "/css/site.css", true)]
    [InlineData("bootstrap.min.css", "/lib/bootstrap/bootstrap.min.css", false)]   // vendor libraries stay cacheable
    [InlineData("chart.umd.min.js", "/lib/chartjs/chart.umd.min.js", false)]
    [InlineData("bootstrap-icons.woff2", "/lib/bootstrap-icons/fonts/bootstrap-icons.woff2", false)]
    [InlineData("logo.png", "/img/logo.png", false)]
    [InlineData("font.woff2", "/css/font.woff2", false)]
    public void Only_the_gui_s_own_pages_scripts_and_styles_are_revalidated(string file, string requestPath, bool revalidate) =>
        Assert.Equal(revalidate, StaticFileCache.MustRevalidate(file, requestPath));

    [Theory]
    [InlineData("app.js", "/js/app.js", "no-cache")]
    [InlineData("chart.umd.min.js", "/lib/chartjs/chart.umd.min.js", "")]
    public void The_response_gets_the_header(string file, string requestPath, string expected)
    {
        var http = new DefaultHttpContext();
        http.Request.Path = requestPath;
        var context = new StaticFileResponseContext(http, new NotFoundFileInfo(file));
        StaticFileCache.CreateOptions().OnPrepareResponse(context);
        Assert.Equal(expected, http.Response.Headers.CacheControl.ToString());
    }
}
