using FileAccessMonitor.Services;

#pragma warning disable CA1416 // the agent targets Linux; the scan itself only runs there (the parsers run anywhere)

public class PermissionLinuxTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "fam-perm-linux-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (!Directory.Exists(_root)) return;
        if (OperatingSystem.IsLinux())
            foreach (var d in Directory.EnumerateDirectories(_root, "*", SearchOption.AllDirectories))
                File.SetUnixFileMode(d, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Directory.Delete(_root, recursive: true);
    }

    // What getxattr returned for system.posix_acl_access on CT115 (Rocky Linux 9) after
    // "setfacl -m u:nobody:rwx,g::r-x d": user::rwx user:nobody:rwx group::r-x mask::rwx other::r-x
    private static readonly byte[] Captured = Convert.FromHexString(
        "02000000" + "0100" + "0700" + "FFFFFFFF" + "0200" + "0700" + "FEFF0000" + "0400" + "0500" + "FFFFFFFF"
        + "1000" + "0700" + "FFFFFFFF" + "2000" + "0500" + "FFFFFFFF");

    [Fact]
    public void Captured_acl_bytes_parse()
    {
        var acl = PermissionScanLinux.ParsePosixAcl(Captured)!;
        Assert.Equal([PermissionScanLinux.TagUserObj, PermissionScanLinux.TagUser, PermissionScanLinux.TagGroupObj,
            PermissionScanLinux.TagMask, PermissionScanLinux.TagOther], acl.Select(e => e.Tag).ToArray());
        Assert.Equal(65534u, acl[1].Id);
        Assert.Equal([7, 7, 5, 7, 5], acl.Select(e => (int)e.Perm).ToArray());
    }

    [Theory]
    [InlineData("")]
    [InlineData("01000000")]
    [InlineData("02000000" + "0100" + "0700")]
    [InlineData("02000000" + "0900" + "0700" + "FFFFFFFF")]
    public void Garbage_is_not_an_acl(string hex) => Assert.Null(PermissionScanLinux.ParsePosixAcl(Convert.FromHexString(hex)));

    [Fact]
    public void The_mask_limits_named_entries()
    {
        var acl = PermissionScanLinux.ParsePosixAcl(Captured)!;
        // mode 0o750 with the mask in the group bits: r-x
        var entries = PermissionScanLinux.EntriesOf(0b111_101_000,
            0, 0, acl.Select(e => e.Tag == PermissionScanLinux.TagMask ? e with { Perm = 4 } : e).ToList(), true, id => id.ToString(), id => id.ToString());
        var nobody = entries.Single(e => e.Principal == "user:65534");
        Assert.Equal((1, 23), (nobody.Level, nobody.Before));
    }

    [Fact]
    public void Share_settings_come_from_testparm_output()
    {
        var shares = PermissionScanLinux.ParseShares("[global]\n\tworkgroup = X\n\n[share]\n\tguest ok = Yes\n\tpath = /srv/share\n\tread only = No\n\tvfs objects = full_audit\n");
        var share = Assert.Single(shares);
        Assert.Equal(("share", "/srv/share", true, false, false), (share.Name, share.Path, share.GuestOk, share.ReadOnly, share.NtAcl));
    }

    [Fact]
    public void A_scan_lists_the_root_and_what_differs_from_its_folder()
    {
        if (!OperatingSystem.IsLinux()) return;
        Directory.CreateDirectory(Path.Combine(_root, "same"));
        Directory.CreateDirectory(Path.Combine(_root, "open"));
        File.WriteAllText(Path.Combine(_root, "same", "a.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "open", "b.txt"), "x");
        File.WriteAllText(Path.Combine(_root, "open", "world.txt"), "x");
        File.SetUnixFileMode(_root, (UnixFileMode)0b111_101_101);
        File.SetUnixFileMode(Path.Combine(_root, "same"), (UnixFileMode)0b111_101_101);
        File.SetUnixFileMode(Path.Combine(_root, "same", "a.txt"), (UnixFileMode)0b110_100_100);
        File.SetUnixFileMode(Path.Combine(_root, "open"), (UnixFileMode)0b111_111_111);
        File.SetUnixFileMode(Path.Combine(_root, "open", "b.txt"), (UnixFileMode)0b110_100_100);
        File.SetUnixFileMode(Path.Combine(_root, "open", "world.txt"), (UnixFileMode)0b110_110_110);

        var result = PermissionScanLinux.Scan(_root, new PermissionScanOptions(), CancellationToken.None);
        var rows = result["rows"]!.AsArray().Select(r => r![0]!.GetValue<string>()).ToArray();
        Assert.Equal(["", "open", "open/b.txt"], rows); // b.txt is stricter than its open folder; world.txt matches it, a.txt matches its folder
        Assert.Equal(("linux", 3, 3, false), (result["os"]!.GetValue<string>(), result["folders"]!.GetValue<int>(), result["files"]!.GetValue<int>(), result["truncated"]!.GetValue<bool>()));

        // the "other" entry of the open folder: read, write, delete, traverse
        var principals = result["principals"]!.AsArray().Select(p => p![0]!.GetValue<string>()).ToList();
        var open = result["rows"]!.AsArray().Single(r => r![0]!.GetValue<string>() == "open")!;
        var other = open[3]!.AsArray().Single(a => principals[a![0]!.GetValue<int>()] == "other")!;
        Assert.Equal(23, other[2]!.GetValue<int>());
        Assert.Contains(principals, p => p.StartsWith("user:") && p.Length > "user:".Length); // the owner has a name or a number
    }

    [Fact]
    public void A_symlink_is_not_followed_and_depth_and_folder_limits_apply()
    {
        if (!OperatingSystem.IsLinux()) return;
        Directory.CreateDirectory(Path.Combine(_root, "a", "b"));
        File.CreateSymbolicLink(Path.Combine(_root, "loop"), _root);
        var all = PermissionScanLinux.Scan(_root, new PermissionScanOptions(), CancellationToken.None);
        Assert.Equal((3, false), (all["folders"]!.GetValue<int>(), all["truncated"]!.GetValue<bool>()));

        var shallow = PermissionScanLinux.Scan(_root, new PermissionScanOptions(MaxDepth: 1), CancellationToken.None);
        Assert.Equal(("depth", 2), (shallow["limit"]!.GetValue<string>(), shallow["folders"]!.GetValue<int>()));

        var few = PermissionScanLinux.Scan(_root, new PermissionScanOptions(MaxFolders: 1), CancellationToken.None);
        Assert.Equal("folders", few["limit"]!.GetValue<string>());
    }

    [Fact]
    public void Owner_and_group_names_are_looked_up_or_fall_back_to_numbers()
    {
        if (!OperatingSystem.IsLinux()) return;
        Assert.Equal("root", PermissionScanLinux.LookupUser(0));
        Assert.Null(PermissionScanLinux.LookupUser(uint.MaxValue));
    }
}
