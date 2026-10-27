using FileAccessMonitor.Data;
using FileAccessMonitor.Models;

namespace FileAccessMonitor.Services;

// Writes the operation log (who changed settings, managed users, exported data, ...).
// Failures are logged but never break the operation being audited.
public class AuditLog(IServiceScopeFactory scopeFactory, ILogger<AuditLog> logger)
{
    public const string SystemUser = "(system)";

    public async Task WriteAsync(string? userName, string action, string? detail = null, string? clientIp = null)
    {
        logger.LogInformation("Audit: {User} {Action} {Detail}", userName ?? SystemUser, action, detail);
        try
        {
            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
            db.AuditLogs.Add(new AuditLogEntry
            {
                Time = DateTime.UtcNow,
                UserName = string.IsNullOrEmpty(userName) ? SystemUser : userName,
                Action = action,
                Detail = detail is { Length: > 4000 } ? detail[..4000] : detail,
                ClientIp = clientIp,
            });
            await db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to write audit log entry {Action}.", action);
        }
    }

    // For API requests: user and client IP come from the request.
    public Task WriteAsync(HttpContext context, string action, string? detail = null, string? userName = null) =>
        WriteAsync(userName ?? context.User.Identity?.Name, action, detail, ClientIp(context));

    private static string? ClientIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        if (ip == null) return null;
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }
}
