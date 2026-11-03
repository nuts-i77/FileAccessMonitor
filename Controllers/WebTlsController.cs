using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace FileAccessMonitor.Controllers;

// Read-only: how the web GUI is served. Switching HTTPS needs a service restart and can lock an
// administrator out, so it is done with the installer or the command line, not from the GUI.
[ApiController]
[Route("api/web-tls")]
[Authorize(Roles = "Admin")]
public class WebTlsController : ControllerBase
{
    // GET /api/web-tls
    // { https, mode: "selfSigned" | "pfx" | null, subject, names[], fingerprint, notAfter, redirectPort, requestIsHttps }
    // https is whether this run serves TLS; configured is whether settings.json asks for it (they
    // differ until the service restarts, or when the certificate could not be loaded)
    [HttpGet]
    public IActionResult Get()
    {
        var status = WebTls.Status;
        var settings = WebTlsSettings.Load();
        return Ok(new
        {
            https = status.Https,
            mode = status.Mode,
            subject = status.Subject,
            names = status.Names,
            fingerprint = status.Fingerprint,
            notAfter = status.NotAfter,
            redirectPort = status.Https ? settings.RedirectPort : 0,
            requestIsHttps = Request.IsHttps,
            configured = settings.Enabled,
        });
    }
}
