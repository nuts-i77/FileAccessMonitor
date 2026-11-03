using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FileAccessMonitor.Services;

// Reads owner, group, mode and POSIX ACLs below a folder (Linux agent and Linux server).
// The BCL has no uid/gid and no extended attributes, so libc is called directly: statx (the same
// struct layout on every architecture), getxattr, getpwuid_r and getgrgid_r. No getfacl: a machine
// may have getfacl or getfattr, but not both. Samba's NT ACLs (security.NTACL) are not read.
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public static class PermissionScanLinux
{
    // Tags of POSIX ACL entries
    internal const ushort TagUserObj = 0x01, TagUser = 0x02, TagGroupObj = 0x04, TagGroup = 0x08, TagMask = 0x10, TagOther = 0x20;

    internal const string AccessXattr = "system.posix_acl_access", DefaultXattr = "system.posix_acl_default";

    internal readonly record struct AclEntry(ushort Tag, ushort Perm, uint Id);

    // The binary form of system.posix_acl_*: u32 version (2), then entries of u16 tag, u16 perm, u32 id
    // (little endian on disk). null when it is not a valid ACL.
    internal static List<AclEntry>? ParsePosixAcl(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4 || (data.Length - 4) % 8 != 0) return null;
        if (BitConverter.ToUInt32(data[..4]) != 2) return null;
        var list = new List<AclEntry>((data.Length - 4) / 8);
        for (var i = 4; i < data.Length; i += 8)
        {
            var tag = BitConverter.ToUInt16(data.Slice(i, 2));
            var perm = BitConverter.ToUInt16(data.Slice(i + 2, 2));
            var id = BitConverter.ToUInt32(data.Slice(i + 4, 4));
            if (tag is not (TagUserObj or TagUser or TagGroupObj or TagGroup or TagMask or TagOther) || perm > 7) return null;
            list.Add(new AclEntry(tag, perm, id));
        }
        // Exactly one of each base entry
        return list.Count(e => e.Tag == TagUserObj) == 1 && list.Count(e => e.Tag == TagGroupObj) == 1
            && list.Count(e => e.Tag == TagOther) == 1 && list.Count(e => e.Tag == TagMask) <= 1 ? list : null;
    }

    // rwx bits (4, 2, 1) of a mode or ACL entry as level bits. Write on a folder also lets one delete
    // and rename the entries in it.
    internal static int LevelOf(int rwx, bool folder)
    {
        var level = 0;
        if ((rwx & 4) != 0) level |= PermissionContract.Read;
        if ((rwx & 2) != 0) level |= PermissionContract.Write | (folder ? PermissionContract.Delete : 0);
        if ((rwx & 1) != 0) level |= PermissionContract.Exec;
        return level;
    }

    internal sealed record Entry(string Principal, int Level, int Before, string Kind);

    // The entries shown for one object. With an ACL the mask limits the group and named entries;
    // the level before the mask is kept (Before) when it differs.
    internal static List<Entry> EntriesOf(int mode, uint uid, uint gid, List<AclEntry>? acl, bool folder,
        Func<uint, string> user, Func<uint, string> group)
    {
        var list = new List<Entry>();
        if (acl == null)
        {
            list.Add(new Entry($"user:{user(uid)}", LevelOf((mode >> 6) & 7, folder), 0, "owner"));
            list.Add(new Entry($"group:{group(gid)}", LevelOf((mode >> 3) & 7, folder), 0, "group"));
            list.Add(new Entry("other", LevelOf(mode & 7, folder), 0, "other"));
            return list;
        }
        var mask = acl.FirstOrDefault(e => e.Tag == TagMask) is { Tag: TagMask } m ? (int?)m.Perm : null;
        foreach (var e in acl)
        {
            switch (e.Tag)
            {
                case TagUserObj:
                    list.Add(new Entry($"user:{user(uid)}", LevelOf(e.Perm, folder), 0, "owner"));
                    break;
                case TagUser:
                    list.Add(Limited($"user:{user(e.Id)}", e.Perm, mask, folder, "user"));
                    break;
                case TagGroupObj:
                    list.Add(Limited($"group:{group(gid)}", e.Perm, mask, folder, "group"));
                    break;
                case TagGroup:
                    list.Add(Limited($"group:{group(e.Id)}", e.Perm, mask, folder, "group"));
                    break;
                case TagOther:
                    list.Add(new Entry("other", LevelOf(e.Perm, folder), 0, "other"));
                    break;
            }
        }
        return list;
    }

    private static Entry Limited(string name, int perm, int? mask, bool folder, string kind)
    {
        var effective = LevelOf(mask is { } m ? perm & m : perm, folder);
        return new Entry(name, effective, LevelOf(perm, folder), kind);
    }

    // ── The scan ──────────────────────────────────────────────────

    private sealed record Stat(uint Uid, uint Gid, int Mode, bool IsDir, bool IsLink);

    private sealed class Names
    {
        private readonly Dictionary<uint, string> _users = [], _groups = [];
        public string User(uint id) => _users.TryGetValue(id, out var n) ? n : _users[id] = LookupUser(id) ?? id.ToString();
        public string Group(uint id) => _groups.TryGetValue(id, out var n) ? n : _groups[id] = LookupGroup(id) ?? id.ToString();
    }

    public static JsonObject Scan(string root, PermissionScanOptions requested, CancellationToken ct)
    {
        var o = PermissionContract.Clamp(requested);
        var result = new PermissionResultBuilder("linux", root, o);
        var clock = Stopwatch.StartNew();
        var limit = TimeSpan.FromSeconds(o.TimeLimitSeconds);
        var names = new Names();
        result.SetShares(SharesJson(root));

        var queue = new Queue<(string Path, int Depth, string Rel, string ParentSignature, int ParentOther)>();
        queue.Enqueue((root, 0, "", "", 0));
        var listing = new EnumerationOptions { IgnoreInaccessible = true, AttributesToSkip = 0 };

        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            if (result.Truncated) break;
            if (clock.Elapsed > limit) { result.Truncate("time"); break; }
            if (result.Folders >= o.MaxFolders) { result.Truncate("folders"); break; }
            var (path, depth, rel, parentSig, parentOther) = queue.Dequeue();
            result.CountFolder();

            var (sig, other) = AddObject(path, rel, folder: true, depth == 0, parentSig, parentOther, names, result);
            DirectoryInfo dir;
            try { dir = new DirectoryInfo(path); }
            catch (Exception) { continue; }

            try
            {
                if (o.IncludeFiles)
                {
                    foreach (var file in dir.EnumerateFiles("*", listing))
                    {
                        ct.ThrowIfCancellationRequested();
                        if ((file.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if (result.Files >= o.MaxFiles) { result.Truncate("files"); goto done; }
                        if (result.Truncated) goto done;
                        if (clock.Elapsed > limit) { result.Truncate("time"); goto done; }
                        result.CountFile();
                        AddObject(file.FullName, rel.Length == 0 ? file.Name : rel + "/" + file.Name, folder: false, false, sig, other, names, result);
                    }
                }
                var subs = dir.EnumerateDirectories("*", listing).Where(d => (d.Attributes & FileAttributes.ReparsePoint) == 0)
                    .OrderBy(d => d.Name, StringComparer.Ordinal).ToList();
                if (depth >= o.MaxDepth)
                {
                    if (subs.Count > 0) result.Truncate("depth");
                    continue;
                }
                foreach (var sub in subs)
                    queue.Enqueue((sub.FullName, depth + 1, rel.Length == 0 ? sub.Name : rel + "/" + sub.Name, sig, other));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                result.AddError($"{path}: {ex.Message}");
            }
        }
        done:
        return result.Build();
    }

    // Adds the row of one folder or file when it is the root or differs from its parent folder; returns
    // the object's signature (what children are compared with) and its "other" level
    private static (string Signature, int Other) AddObject(string path, string rel, bool folder, bool isRoot,
        string parentSig, int parentOther, Names names, PermissionResultBuilder result)
    {
        var stat = StatOf(path);
        if (stat == null)
        {
            result.AddError($"{path}: not readable");
            result.AddRow(rel, (folder ? PermissionContract.FlagFolder : 0) | PermissionContract.FlagNotReadable, -1, []);
            return (parentSig, parentOther);
        }
        var access = ReadAcl(path, AccessXattr);
        var defaults = folder ? ReadAcl(path, DefaultXattr) : null;
        // The execute bits of files are left out: a script among documents is not a difference
        var mode = stat.Mode & 0xFFF;
        var comparable = folder ? mode & 0x1FF : mode & 0x1B6;
        var signature = $"{comparable:x}:{stat.Uid}:{stat.Gid}:{Hex(access)}:{Hex(defaults)}";

        var entries = EntriesOf(mode, stat.Uid, stat.Gid, access, folder, names.User, names.Group);
        var other = entries.First(e => e.Kind == "other").Level;
        // Files are compared with their folder's file bits, so a plain 0644 file in a 0755 folder is not listed
        var parentComparable = parentSig;
        if (!folder && parentSig.Length > 0)
        {
            var colon = parentSig.IndexOf(':');
            var parentMode = Convert.ToInt32(parentSig[..colon], 16) & 0x1B6;
            parentComparable = $"{parentMode:x}{parentSig[colon..]}";
        }
        var differs = isRoot || signature != parentComparable
            || ((other & (PermissionContract.Read | PermissionContract.Write)) != 0 && (parentOther & (PermissionContract.Read | PermissionContract.Write)) == 0);
        if (!differs) return (signature, other);

        var flags = folder ? PermissionContract.FlagFolder : 0;
        if (access != null && access.Count > 3) flags |= PermissionContract.FlagAcl;
        if (defaults != null) flags |= PermissionContract.FlagDefaultAcl;
        var aces = entries.Select(e => new PermissionAce(
            result.Principal(e.Principal, null), 0, e.Level, PermissionContract.ScopeThis, e.Before > 0 ? e.Before : null)).ToList();
        if (defaults != null)
            foreach (var e in EntriesOf(mode, stat.Uid, stat.Gid, defaults, true, names.User, names.Group))
                aces.Add(new PermissionAce(result.Principal(e.Principal, null), 0, e.Level,
                    PermissionContract.ScopeThis | PermissionContract.ScopeSubfolders | PermissionContract.ScopeFiles,
                    e.Before > 0 ? e.Before : null));
        var ownerIdx = result.Principal($"user:{names.User(stat.Uid)}", null);
        result.AddRow(rel, flags, isRoot ? ownerIdx : -1, aces);
        return (signature, other);
    }

    private static string Hex(List<AclEntry>? acl) =>
        acl == null ? "" : string.Join(",", acl.Select(e => $"{e.Tag:x}{e.Perm:x}{e.Id:x}"));

    // ── testparm: the shares that hold the folder ─────────────────

    internal sealed record ShareInfo(string Name, string Path, bool GuestOk, bool ReadOnly, string ValidUsers, string WriteList, bool NtAcl);

    // Parses "testparm -s" output: "[name]" sections of "key = value" lines. testparm prints the
    // effective values but leaves out defaults, so a share without "read only" is read only and one
    // without "guest ok" does not allow guests.
    internal static List<ShareInfo> ParseShares(string testparm)
    {
        var shares = new List<ShareInfo>();
        string? name = null;
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Flush()
        {
            if (name == null || name.Equals("global", StringComparison.OrdinalIgnoreCase) || !values.TryGetValue("path", out var path)) return;
            bool Yes(string key, bool fallback) => values.TryGetValue(key, out var v)
                ? v.Trim().ToLowerInvariant() is "yes" or "true" or "1" or "on" : fallback;
            var vfs = values.GetValueOrDefault("vfs objects", "");
            var ntAcl = vfs.Split([' ', ',', '\t'], StringSplitOptions.RemoveEmptyEntries)
                .Any(m => m.Equals("acl_xattr", StringComparison.OrdinalIgnoreCase) || m.Equals("acl_tdb", StringComparison.OrdinalIgnoreCase));
            shares.Add(new ShareInfo(name, path.Trim(), Yes("guest ok", false) || Yes("public", false),
                Yes("read only", !Yes("writable", false) && !Yes("writeable", false)),
                values.GetValueOrDefault("valid users", "").Trim(), values.GetValueOrDefault("write list", "").Trim(), ntAcl));
        }
        foreach (var raw in testparm.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] is '#' or ';') continue;
            var section = Regex.Match(line, @"^\[(.+)\]$");
            if (section.Success)
            {
                Flush();
                name = section.Groups[1].Value;
                values.Clear();
                continue;
            }
            var eq = line.IndexOf('=');
            if (eq > 0 && name != null) values[line[..eq].Trim()] = line[(eq + 1)..].Trim();
        }
        Flush();
        return shares;
    }

    // Shares that hold the folder, or are inside it
    internal static List<ShareInfo> SharesHolding(List<ShareInfo> shares, string root)
    {
        var folder = root.TrimEnd('/');
        return shares.Where(s =>
        {
            var p = s.Path.TrimEnd('/');
            return folder == p || folder.StartsWith(p + "/", StringComparison.Ordinal) || p.StartsWith(folder + "/", StringComparison.Ordinal) || folder.Length == 0;
        }).ToList();
    }

    private static JsonArray SharesJson(string root)
    {
        var list = new JsonArray();
        try
        {
            var (code, output, _) = Samba.Run("testparm", "-s");
            if (code != 0) return list;
            foreach (var s in SharesHolding(ParseShares(output), root))
                list.Add(new JsonObject
                {
                    ["name"] = s.Name, ["path"] = s.Path, ["guestOk"] = s.GuestOk, ["readOnly"] = s.ReadOnly,
                    ["validUsers"] = s.ValidUsers, ["writeList"] = s.WriteList, ["ntAcl"] = s.NtAcl,
                });
        }
        catch (Exception) { /* no Samba: the folder is scanned anyway */ }
        return list;
    }

    // ── libc ──────────────────────────────────────────────────────

    [DllImport("libc", EntryPoint = "getxattr", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern nint GetXattr(string path, string name, byte[] value, nuint size);

    [DllImport("libc", EntryPoint = "statx", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern int StatX(int dirfd, string path, int flags, uint mask, byte[] buffer);

    [DllImport("libc", EntryPoint = "getpwuid_r")]
    private static extern int GetPwUidR(uint uid, nint pwd, nint buf, nuint buflen, out nint result);

    [DllImport("libc", EntryPoint = "getgrgid_r")]
    private static extern int GetGrGidR(uint gid, nint grp, nint buf, nuint buflen, out nint result);

    // The extended ACL in system.posix_acl_access / _default; null when there is none (ENODATA: the
    // mode bits are the whole story) or the file system has no ACLs
    internal static List<AclEntry>? ReadAcl(string path, string attribute)
    {
        try
        {
            var buffer = new byte[4 + 8 * 64];
            var size = GetXattr(path, attribute, buffer, (nuint)buffer.Length);
            if (size < 0 && Marshal.GetLastPInvokeError() == 34 /* ERANGE */)
            {
                buffer = new byte[64 * 1024];
                size = GetXattr(path, attribute, buffer, (nuint)buffer.Length);
            }
            return size <= 0 ? null : ParsePosixAcl(buffer.AsSpan(0, (int)size));
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return null; }
    }

    private static Stat? StatOf(string path)
    {
        try
        {
            var buffer = new byte[256];
            // AT_FDCWD, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS
            if (StatX(-100, path, 0x100, 0x7ff, buffer) != 0) return null;
            var uid = BitConverter.ToUInt32(buffer, 20);
            var gid = BitConverter.ToUInt32(buffer, 24);
            var mode = BitConverter.ToUInt16(buffer, 28);
            return new Stat(uid, gid, mode & 0xFFF, (mode & 0xF000) == 0x4000, (mode & 0xF000) == 0xA000);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            // No statx (an old libc): the mode is known, the owner is not
            try { return new Stat(uint.MaxValue, uint.MaxValue, (int)File.GetUnixFileMode(path), Directory.Exists(path), false); }
            catch (Exception) { return null; }
        }
    }

    internal static string? LookupUser(uint uid) => LookupName(uid, user: true);
    internal static string? LookupGroup(uint gid) => LookupName(gid, user: false);

    // pw_name and gr_name are the first member of struct passwd and struct group on glibc and musl
    private static string? LookupName(uint id, bool user)
    {
        if (id == uint.MaxValue) return null;
        var record = Marshal.AllocHGlobal(256);
        var buflen = 16 * 1024;
        var buf = Marshal.AllocHGlobal(buflen);
        try
        {
            var rc = user ? GetPwUidR(id, record, buf, (nuint)buflen, out var found) : GetGrGidR(id, record, buf, (nuint)buflen, out found);
            if (rc != 0 || found == 0) return null;
            var name = Marshal.ReadIntPtr(record, 0);
            return name == 0 ? null : Marshal.PtrToStringUTF8(name);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return null; }
        finally
        {
            Marshal.FreeHGlobal(record);
            Marshal.FreeHGlobal(buf);
        }
    }
}
