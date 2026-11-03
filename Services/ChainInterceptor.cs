using Microsoft.EntityFrameworkCore.Diagnostics;

namespace FileAccessMonitor.Services;

// Tamper detection: gives every new AccessRecord / AuditLogEntry its place in the hash chain.
// Step-0 stub (does nothing); filled in by the tamper-detection work.
public class ChainInterceptor : SaveChangesInterceptor
{
}
