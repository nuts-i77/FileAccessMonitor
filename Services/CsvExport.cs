namespace FileAccessMonitor.Services;

// What the CSV exports (search, file history, permissions) share: lines end in CRLF (RFC 4180, whatever the
// server's OS), at most two run at a time (a large export holds the database for seconds), and a cut result
// is said in a header the GUI reads (a note inside the CSV would break other tools that read it).
public static class CsvExport
{
    public const string NewLine = "\r\n";
    public const string TruncatedHeader = "X-Export-Truncated";
    public const int MaxConcurrent = 2;

    private static readonly SemaphoreSlim Gate = new(MaxConcurrent, MaxConcurrent);

    // A slot for one export, or null when all are taken (answer 429 then); dispose it when done
    public static IDisposable? TryEnter() => Gate.Wait(0) ? new Slot() : null;

    private sealed class Slot : IDisposable
    {
        private int _released;
        public void Dispose() { if (Interlocked.Exchange(ref _released, 1) == 0) Gate.Release(); }
    }
}
