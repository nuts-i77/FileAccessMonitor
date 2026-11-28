using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace FileAccessMonitor.Services;

// A file reference number: 64 bits on NTFS (USN_RECORD_V2), 128 bits on ReFS (V3)
public readonly record struct UsnFileRef(ulong Low, ulong High);

public readonly record struct UsnRecord(
    int MajorVersion, UsnFileRef FileRef, UsnFileRef ParentRef, long Usn, DateTime TimeUtc,
    uint Reason, uint FileAttributes, string Name)
{
    public bool IsDirectory => (FileAttributes & UsnReasons.DirectoryAttribute) != 0;
}

public static class UsnReasons
{
    public const uint DataTruncation = 0x4;
    public const uint FileCreate = 0x100;
    public const uint Close = 0x80000000;
    public const uint RenameOldName = 0x1000;
    public const uint RenameNewName = 0x2000;
    public const uint DirectoryAttribute = 0x10;
}

// Parses the output of FSCTL_READ_USN_JOURNAL: the next USN (8 bytes), then USN_RECORD_V2 / V3 records.
public static class UsnRecordParser
{
    public static List<UsnRecord> Parse(ReadOnlySpan<byte> buffer, out long nextUsn)
    {
        var records = new List<UsnRecord>();
        nextUsn = 0;
        if (buffer.Length < 8) return records;
        nextUsn = BinaryPrimitives.ReadInt64LittleEndian(buffer);

        var pos = 8;
        while (pos + 8 <= buffer.Length)
        {
            var length = (int)BinaryPrimitives.ReadUInt32LittleEndian(buffer[pos..]);
            if (length < 8 || pos + length > buffer.Length) break;
            if (TryParseRecord(buffer.Slice(pos, length), out var record)) records.Add(record);
            pos += (length + 7) & ~7; // records are 8-byte aligned
        }
        return records;
    }

    // Unknown versions and damaged records are skipped, not fatal
    public static bool TryParseRecord(ReadOnlySpan<byte> r, out UsnRecord record)
    {
        record = default;
        if (r.Length < 8) return false;
        int major = BinaryPrimitives.ReadUInt16LittleEndian(r[4..]);

        UsnFileRef fileRef, parentRef;
        int usnOffset, nameLengthOffset;
        switch (major)
        {
            case 2:
                if (r.Length < 60) return false;
                fileRef = new UsnFileRef(BinaryPrimitives.ReadUInt64LittleEndian(r[8..]), 0);
                parentRef = new UsnFileRef(BinaryPrimitives.ReadUInt64LittleEndian(r[16..]), 0);
                usnOffset = 24;
                nameLengthOffset = 56;
                break;
            case 3:
                if (r.Length < 76) return false;
                fileRef = new UsnFileRef(BinaryPrimitives.ReadUInt64LittleEndian(r[8..]), BinaryPrimitives.ReadUInt64LittleEndian(r[16..]));
                parentRef = new UsnFileRef(BinaryPrimitives.ReadUInt64LittleEndian(r[24..]), BinaryPrimitives.ReadUInt64LittleEndian(r[32..]));
                usnOffset = 40;
                nameLengthOffset = 72;
                break;
            default:
                return false;
        }

        var usn = BinaryPrimitives.ReadInt64LittleEndian(r[usnOffset..]);
        var fileTime = BinaryPrimitives.ReadInt64LittleEndian(r[(usnOffset + 8)..]);
        var reason = BinaryPrimitives.ReadUInt32LittleEndian(r[(usnOffset + 16)..]);
        var attributes = BinaryPrimitives.ReadUInt32LittleEndian(r[(nameLengthOffset - 4)..]);
        int nameLength = BinaryPrimitives.ReadUInt16LittleEndian(r[nameLengthOffset..]);
        int nameOffset = BinaryPrimitives.ReadUInt16LittleEndian(r[(nameLengthOffset + 2)..]);
        if (nameOffset + nameLength > r.Length || (nameLength & 1) != 0) return false;
        if (fileTime < 0 || fileTime > DateTime.MaxValue.Ticks - DateTime.FromFileTimeUtc(0).Ticks) return false;

        record = new UsnRecord(major, fileRef, parentRef, usn, DateTime.FromFileTimeUtc(fileTime), reason, attributes,
            Encoding.Unicode.GetString(r.Slice(nameOffset, nameLength)));
        return true;
    }
}

// Reads the NTFS/ReFS change journal of the volumes that hold monitored folders and tells the
// UsnCorrelator which files were created and renamed. Volumes without a journal (FAT, exFAT,
// network paths, or NTFS / ReFS where nobody created one) are left alone: a journal is created only by the
// "createJournal" job, which an administrator starts with "Turn on the change journal" in Settings > Monitored folders (CreateJournal).
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
public class UsnJournalReader
{
    private const uint GenericRead = 0x80000000;
    private const uint ShareReadWrite = 3; // FILE_SHARE_READ | FILE_SHARE_WRITE
    private const uint ShareAll = 7;
    private const uint OpenExisting = 3;
    private const uint BackupSemantics = 0x02000000;
    private const uint FileReadAttributes = 0x80;
    private const uint FsctlQueryUsnJournal = 0x900F4;
    private const uint FsctlReadUsnJournal = 0x900BB;

    private const int ErrorHandleEof = 38;
    private const int ErrorJournalDeleteInProgress = 1178;
    private const int ErrorJournalNotActive = 1179;
    private const int ErrorJournalEntryDeleted = 1181;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(500);
    // A drive without a usable journal is looked at again after this long: a journal an administrator
    // creates is read from then on, without a restart (opening the drive and asking is cheap)
    internal static readonly TimeSpan RetryUnavailableAfter = TimeSpan.FromMinutes(1);
    // The saved position lags behind, so that a restart also re-reads the journal for the Security
    // events it re-reads (those saved a few seconds ago)
    private static readonly TimeSpan PositionLag = TimeSpan.FromSeconds(30);
    private const int ReadBufferSize = 64 * 1024;
    private const int MaxPathCache = 50_000;
    private const int MaxTracked = 100_000;

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)] public uint Size;
        [FieldOffset(4)] public int Type; // 0 = FileIdType (64 bit), 2 = ExtendedFileIdType (128 bit)
        [FieldOffset(8)] public ulong Low;
        [FieldOffset(16)] public ulong High;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[]? input, int inputSize,
        byte[]? output, int outputSize, out int returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle volumeHint, ref FileIdDescriptor id, uint access,
        uint share, IntPtr security, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, char[] path, uint length, uint flags);

    private sealed class Volume(string letter)
    {
        public string Letter { get; } = letter; // "C:"
        public SafeFileHandle? Handle;
        public ulong JournalId;
        public long NextUsn;
        public DateTime CaughtUpUtc = DateTime.MinValue;
        public DateTime UnavailableSinceUtc = DateTime.MinValue;
        public bool Available => Handle != null;
        // What was found the last time (JournalStates; "" before the first look) and the file system
        public string State = "";
        public string? Format;
        public readonly Dictionary<UsnFileRef, string> ParentPaths = new();
        public readonly Dictionary<UsnFileRef, (string Path, DateTime Time)> OldNames = new();
        public readonly HashSet<UsnFileRef> Created = new();
        public readonly HashSet<UsnFileRef> Truncated = new();
        public readonly Queue<(DateTime Time, long Usn)> History = new();
    }

    private readonly UsnCorrelator _correlator;
    private readonly ILogger _logger;
    private readonly Func<IReadOnlyList<string>> _roots;
    private readonly Func<bool> _enabled;
    private readonly string _positionFile;
    private readonly Dictionary<string, Volume> _volumes = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private Dictionary<string, SavedPosition> _saved = new();
    private int _recheckSeen;

    private sealed record SavedPosition(ulong JournalId, long NextUsn);

    // roots: the monitored folders (empty = every fixed drive); enabled: Recording.UsnCorrelation
    public UsnJournalReader(UsnCorrelator correlator, ILogger logger, Func<IReadOnlyList<string>> roots, Func<bool> enabled,
        string positionFile)
    {
        _correlator = correlator;
        _logger = logger;
        _roots = roots;
        _enabled = enabled;
        _positionFile = positionFile;
        _saved = LoadPositions(positionFile);
    }

    // Facts outside the monitored folders cannot match a record (and a create or truncation there must not
    // be recorded on its own), so they are not kept
    private bool Monitored(string path) => _roots().Any(r => EventLogCollectorService.IsUnderPath(path, r));

    // True if creates and renames below this path are reported by a working journal
    public bool Covers(string path)
    {
        if (!_enabled() || !TryDriveOf(path, out var letter)) return false;
        lock (_gate) return _volumes.TryGetValue(letter, out var v) && v.Available;
    }

    public async Task RunAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try { Poll(); }
                catch (Exception ex) { _logger.LogWarning(ex, "Reading the USN change journal failed."); }
                await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            lock (_gate)
                foreach (var v in _volumes.Values) v.Handle?.Dispose();
        }
    }

    private void Poll()
    {
        if (!_enabled())
        {
            _correlator.CaughtUpUtc = DateTime.MinValue;
            UsnJournalStatus.Current = _roots().Select(r => new JournalVolume(UsnJournalStatus.DriveOf(r) ?? r, JournalStates.Disabled))
                .DistinctBy(v => v.Volume, StringComparer.OrdinalIgnoreCase).ToList();
            return;
        }
        var now = DateTime.UtcNow;
        lock (_gate)
        {
            var watched = VolumesToWatch().ToList();
            PublishStatus(watched);
            // A journal was just created from the web GUI: look at the drives without one now
            var recheck = UsnJournalStatus.RecheckCount;
            var lookNow = recheck != _recheckSeen;
            _recheckSeen = recheck;
            foreach (var letter in watched)
            {
                if (!_volumes.TryGetValue(letter, out var volume)) _volumes[letter] = volume = new Volume(letter);
                if (!volume.Available && (lookNow || now - volume.UnavailableSinceUtc >= RetryUnavailableAfter)) Open(volume, now);
                if (volume.Available) ReadVolume(volume, now);
            }
            // Only the volumes read now: one no longer watched (its folders were removed) stays where it stopped
            var caughtUp = watched.Select(l => _volumes[l]).Where(v => v.Available).Select(v => v.CaughtUpUtc)
                .DefaultIfEmpty(DateTime.MinValue).Min();
            _correlator.CaughtUpUtc = caughtUp;
        }
    }

    // For the heartbeat: the drives of the monitored folders (one not looked at yet is left out until it
    // is), and network folders, which have no journal here
    private void PublishStatus(List<string> watched)
    {
        var roots = _roots();
        if (roots.Count == 0) { UsnJournalStatus.Current = []; return; }
        var list = new List<JournalVolume>();
        foreach (var letter in watched)
            if (_volumes.TryGetValue(letter, out var v) && v.State != "")
                list.Add(new JournalVolume(letter, v.State, v.Format));
        foreach (var root in roots.Where(r => !TryDriveOf(r, out _)).Distinct(StringComparer.OrdinalIgnoreCase))
            list.Add(new JournalVolume(root, JournalStates.Network));
        UsnJournalStatus.Current = list;
    }

    // Logs what was found when it differs from the last time (a drive without a journal is looked at
    // every minute, but said once)
    private bool ChangeState(Volume v, string state, string? format = null)
    {
        var changed = v.State != state;
        v.State = state;
        v.Format = format;
        return changed;
    }

    private IEnumerable<string> VolumesToWatch()
    {
        var roots = _roots();
        if (roots.Count == 0)
            return DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed).Select(d => d.Name.TrimEnd('\\'));
        return roots.Select(r => TryDriveOf(r, out var l) ? l : null).Where(l => l != null).Select(l => l!).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    internal static bool TryDriveOf(string path, out string letter)
    {
        letter = "";
        if (path.Length < 2 || path[1] != ':' || !char.IsAsciiLetter(path[0])) return false; // UNC and the like
        letter = char.ToUpperInvariant(path[0]) + ":";
        return true;
    }

    // The volume itself, as CreateFile opens it for FSCTL_QUERY_USN_JOURNAL: \\.\E:
    internal static string DevicePath(string letter) => $@"\\.\{letter}";

    // The journal "Turn it on" in the web GUI creates: the same as the documented
    // fsutil usn createjournal m=33554432 a=8388608 (32 MB, 8 MB at a time). Not a choice of the caller.
    public const ulong CreateMaximumSize = 33554432;
    public const ulong CreateAllocationDelta = 8388608;
    private const uint GenericWrite = 0x40000000;
    private const uint FsctlCreateUsnJournal = 0x000900E7;

    // Results of CreateJournal
    public const string CreateDone = "created";
    public const string CreateExists = "exists";           // the drive has one already: left as it is
    public const string CreateUnsupported = "unsupported"; // not NTFS / ReFS
    public const string CreateFailed = "failed";

    // Creates the change journal of a drive that has none (the "createJournal" job). A drive that has one
    // is left alone: creating again would change a size another program may have chosen.
    public static (string Result, string? Detail) CreateJournal(string letter)
    {
        string format;
        try { format = new DriveInfo(letter).DriveFormat; }
        catch (Exception ex) { return (CreateFailed, ex.Message); }
        if (!format.Equals("NTFS", StringComparison.OrdinalIgnoreCase) && !format.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
            return (CreateUnsupported, format);

        using var handle = CreateFileW(DevicePath(letter), GenericRead | GenericWrite, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid) return (CreateFailed, $"error {Marshal.GetLastWin32Error()}");

        var info = new byte[80];
        if (DeviceIoControl(handle, FsctlQueryUsnJournal, null, 0, info, info.Length, out _, IntPtr.Zero))
            return (CreateExists, format);
        var queryError = Marshal.GetLastWin32Error();
        if (queryError != ErrorJournalNotActive) return (CreateFailed, $"error {queryError}");

        var input = new byte[16]; // CREATE_USN_JOURNAL_DATA
        BinaryPrimitives.WriteUInt64LittleEndian(input, CreateMaximumSize);
        BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(8), CreateAllocationDelta);
        if (!DeviceIoControl(handle, FsctlCreateUsnJournal, input, input.Length, null, 0, out _, IntPtr.Zero))
            return (CreateFailed, $"error {Marshal.GetLastWin32Error()}");
        UsnJournalStatus.RequestRecheck();
        return (CreateDone, format);
    }

    private void Open(Volume v, DateTime now)
    {
        v.UnavailableSinceUtc = now;
        string format;
        try
        {
            format = new DriveInfo(v.Letter).DriveFormat;
            if (!format.Equals("NTFS", StringComparison.OrdinalIgnoreCase) && !format.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
            {
                if (ChangeState(v, JournalStates.Unsupported, format))
                    _logger.LogInformation("Volume {Volume} is {Format}, which has no change journal (only NTFS and ReFS have one), so file creation and the new name of renamed files are not recorded there.",
                        v.Letter, format);
                return;
            }
        }
        catch (Exception ex)
        {
            if (ChangeState(v, JournalStates.Error))
                _logger.LogInformation(ex, "Volume {Volume} is not available for the change journal.", v.Letter);
            return;
        }

        var handle = CreateFileW(DevicePath(v.Letter), GenericRead, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var openError = Marshal.GetLastWin32Error();
            if (ChangeState(v, JournalStates.Error, format))
                _logger.LogInformation("Cannot open volume {Volume} for the change journal (error {Error}); file creation and new names are not recorded there.",
                    v.Letter, openError);
            handle.Dispose();
            return;
        }

        var info = new byte[80];
        if (!DeviceIoControl(handle, FsctlQueryUsnJournal, null, 0, info, info.Length, out _, IntPtr.Zero))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorJournalNotActive)
            {
                if (ChangeState(v, JournalStates.Off, format))
                    _logger.LogInformation("Volume {Volume} ({Format}) has no USN change journal, so file creation and the new name of renamed files are not recorded there. "
                        + "To record them, an administrator turns the journal on with \"Turn on the change journal\" in Settings > Monitored folders of the web GUI, "
                        + "or on this server with: fsutil usn createjournal m=33554432 a=8388608 {Volume}  (it uses up to 32 MB; no restart is needed, it is read within a minute)",
                        v.Letter, format, v.Letter);
            }
            else if (ChangeState(v, JournalStates.Error, format))
            {
                _logger.LogInformation("The USN change journal of volume {Volume} cannot be read (error {Error}); file creation and new names are not recorded there.",
                    v.Letter, error);
            }
            handle.Dispose();
            return;
        }

        var journalId = BinaryPrimitives.ReadUInt64LittleEndian(info);
        var first = BinaryPrimitives.ReadInt64LittleEndian(info.AsSpan(8));
        var next = BinaryPrimitives.ReadInt64LittleEndian(info.AsSpan(16));

        // Resume where the last run stopped, if that part of the journal is still there; else live
        var start = next;
        if (_saved.TryGetValue(v.Letter, out var saved) && saved.JournalId == journalId && saved.NextUsn >= first && saved.NextUsn <= next)
            start = saved.NextUsn;

        v.Handle = handle;
        v.JournalId = journalId;
        v.NextUsn = start;
        v.CaughtUpUtc = now;
        v.History.Clear();
        v.History.Enqueue((now, start));
        ChangeState(v, JournalStates.On, format);
        _logger.LogInformation("Reading the USN change journal of volume {Volume} ({Format}).", v.Letter, format);
    }

    private void ReadVolume(Volume v, DateTime pollStart)
    {
        var buffer = new byte[ReadBufferSize];
        var input = new byte[48];
        for (var round = 0; round < 20; round++)
        {
            // READ_USN_JOURNAL_DATA_V1
            BinaryPrimitives.WriteInt64LittleEndian(input, v.NextUsn);
            BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8),
                UsnReasons.FileCreate | UsnReasons.RenameOldName | UsnReasons.RenameNewName | UsnReasons.DataTruncation);
            BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(12), 0); // also records of files still open
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(16), 0); // timeout: do not wait
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(24), 0); // bytes to wait for
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32), v.JournalId);
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(40), 2);
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(42), 3);

            if (!DeviceIoControl(v.Handle!, FsctlReadUsnJournal, input, input.Length, buffer, buffer.Length, out var returned, IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorHandleEof) { Caught(v, pollStart); return; }
                HandleReadError(v, error);
                return;
            }

            var records = UsnRecordParser.Parse(buffer.AsSpan(0, returned), out var next);
            foreach (var record in records) Process(v, record);
            if (next > v.NextUsn) v.NextUsn = next;
            if (records.Count == 0 && returned <= 8) { Caught(v, pollStart); return; }
            if (records.Count > 0) v.CaughtUpUtc = records[^1].TimeUtc;
            if (next <= 0) return;
        }
    }

    private void Caught(Volume v, DateTime pollStart)
    {
        v.CaughtUpUtc = pollStart;
        v.History.Enqueue((pollStart, v.NextUsn));
        while (v.History.Count > 4000) v.History.Dequeue();
    }

    private void HandleReadError(Volume v, int error)
    {
        if (error == ErrorJournalEntryDeleted)
        {
            // The journal wrapped around faster than it was read: facts of that time are lost
            _logger.LogWarning("The USN change journal of volume {Volume} wrapped around before it was read; creates and new names are missing for that time.", v.Letter);
            var info = new byte[80];
            if (DeviceIoControl(v.Handle!, FsctlQueryUsnJournal, null, 0, info, info.Length, out _, IntPtr.Zero))
            {
                v.JournalId = BinaryPrimitives.ReadUInt64LittleEndian(info);
                v.NextUsn = BinaryPrimitives.ReadInt64LittleEndian(info.AsSpan(8));
                return;
            }
        }
        else if (error is not (ErrorJournalNotActive or ErrorJournalDeleteInProgress))
        {
            _logger.LogInformation("Reading the USN change journal of volume {Volume} failed (error {Error}).", v.Letter, error);
            ChangeState(v, JournalStates.Error, v.Format);
        }
        else
        {
            _logger.LogInformation("The USN change journal of volume {Volume} was deleted or replaced (error {Error}); it is checked again later.", v.Letter, error);
            ChangeState(v, JournalStates.Off, v.Format);
        }
        // Give the handle up; Poll opens the volume again (and starts at the end of the journal) after a while
        v.Handle?.Dispose();
        v.Handle = null;
        v.UnavailableSinceUtc = DateTime.UtcNow;
    }

    private void Process(Volume v, UsnRecord r)
    {
        if (r.IsDirectory && (r.Reason & UsnReasons.RenameNewName) != 0)
            v.ParentPaths.Clear(); // paths below a renamed folder changed

        if ((r.Reason & UsnReasons.FileCreate) != 0 && !r.IsDirectory && v.Created.Add(r.FileRef))
        {
            if (v.Created.Count > MaxTracked) { v.Created.Clear(); v.Created.Add(r.FileRef); }
            if (ResolvePath(v, r) is { } created && Monitored(created)) _correlator.AddCreate(created, r.TimeUtc);
        }

        // Reasons add up until the file is closed: one truncation per open (a new file has none)
        if ((r.Reason & UsnReasons.DataTruncation) != 0 && (r.Reason & UsnReasons.FileCreate) == 0 && !r.IsDirectory
            && v.Truncated.Add(r.FileRef))
        {
            if (v.Truncated.Count > MaxTracked) { v.Truncated.Clear(); v.Truncated.Add(r.FileRef); }
            if (ResolvePath(v, r) is { } truncated && Monitored(truncated)) _correlator.AddTruncate(truncated, r.TimeUtc);
        }
        if ((r.Reason & UsnReasons.Close) != 0) v.Truncated.Remove(r.FileRef);

        if ((r.Reason & UsnReasons.RenameOldName) != 0)
        {
            if (v.OldNames.Count > MaxTracked) v.OldNames.Clear();
            if (ResolvePath(v, r) is { } old) v.OldNames[r.FileRef] = (old, r.TimeUtc);
        }
        else if ((r.Reason & UsnReasons.RenameNewName) != 0)
        {
            if (v.OldNames.Remove(r.FileRef, out var old) && ResolvePath(v, r) is { } renamed)
                _correlator.AddRename(old.Path, renamed, r.TimeUtc);
        }
    }

    private string? ResolvePath(Volume v, UsnRecord r)
    {
        var parent = ParentPath(v, r.ParentRef, r.MajorVersion);
        return parent == null ? null : CombinePath(parent, r.Name);
    }

    internal static string CombinePath(string parent, string name) => parent.TrimEnd('\\') + "\\" + name;

    // The folder's path from its file reference number, cached
    private string? ParentPath(Volume v, UsnFileRef parent, int major)
    {
        if (v.ParentPaths.TryGetValue(parent, out var cached)) return cached;
        var path = PathOf(v, parent, major);
        if (path == null) return null; // folder is gone (a temporary file made and deleted)
        if (v.ParentPaths.Count >= MaxPathCache) v.ParentPaths.Clear();
        v.ParentPaths[parent] = path;
        return path;
    }

    private static string? PathOf(Volume v, UsnFileRef id, int major)
    {
        var descriptor = new FileIdDescriptor { Size = 24, Type = major >= 3 ? 2 : 0, Low = id.Low, High = id.High };
        using var handle = OpenFileById(v.Handle!, ref descriptor, FileReadAttributes, ShareAll, IntPtr.Zero, BackupSemantics);
        if (handle.IsInvalid) return null;

        var chars = new char[1024];
        var length = GetFinalPathNameByHandleW(handle, chars, (uint)chars.Length, 0);
        if (length == 0) return null;
        if (length > chars.Length)
        {
            chars = new char[length + 1];
            length = GetFinalPathNameByHandleW(handle, chars, (uint)chars.Length, 0);
            if (length == 0 || length > chars.Length) return null;
        }
        return StripPrefix(new string(chars, 0, (int)length));
    }

    // \\?\C:\dir -> C:\dir ; \\?\UNC\server\share -> \\server\share
    internal static string StripPrefix(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) return @"\\" + path[8..];
        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }

    // Written together with the Security log position. Best effort.
    public void SavePositions()
    {
        try
        {
            var positions = new Dictionary<string, SavedPosition>(_saved, StringComparer.OrdinalIgnoreCase);
            lock (_gate)
            {
                var limit = DateTime.UtcNow - PositionLag;
                foreach (var v in _volumes.Values.Where(v => v.Available))
                {
                    // Newest sample at least PositionLag old; before that, the oldest one
                    var usn = v.History.Peek().Usn;
                    foreach (var (time, u) in v.History)
                        if (time <= limit) usn = u;
                    while (v.History.Count > 1 && v.History.ElementAt(1).Time <= limit) v.History.Dequeue();
                    positions[v.Letter] = new SavedPosition(v.JournalId, usn);
                }
            }
            _saved = positions;
            var tmp = _positionFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(positions));
            File.Move(tmp, _positionFile, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not save the USN journal position.");
        }
    }

    private static Dictionary<string, SavedPosition> LoadPositions(string file)
    {
        try
        {
            if (File.Exists(file) && JsonSerializer.Deserialize<Dictionary<string, SavedPosition>>(File.ReadAllText(file)) is { } d)
                return new Dictionary<string, SavedPosition>(d, StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is JsonException or IOException) { }
        return new Dictionary<string, SavedPosition>(StringComparer.OrdinalIgnoreCase);
    }
}
