namespace FileAccessMonitor.Services;

// What the scheduled report and the settings card show about tamper detection
public interface IIntegrityStatus
{
    Task<IntegritySummary> GetSummaryAsync(CancellationToken ct = default);
}

// State: ok | broken | notVerified | disabled. AnchorLine: "FAM-ANCHOR v1 ..." (null when not available)
public record IntegritySummary(string State, DateTime? VerifiedUpTo, DateTime? LastCheck,
    int Breaks, string? FirstBreak, long HeadSeq, string HeadHashHex, long LegacyRows, string? AnchorLine);

// Step-0 stub; filled in by the tamper-detection work
public class IntegrityService : IIntegrityStatus
{
    public Task<IntegritySummary> GetSummaryAsync(CancellationToken ct = default) =>
        Task.FromResult(new IntegritySummary("disabled", null, null, 0, null, 0, "", 0, null));
}
