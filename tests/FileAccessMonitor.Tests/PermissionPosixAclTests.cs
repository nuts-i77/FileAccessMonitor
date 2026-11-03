using FileAccessMonitor.Services;

#pragma warning disable CA1416 // the parser and the share parser do not depend on the platform

namespace FileAccessMonitor.Tests;

// The binary form of system.posix_acl_access / _default. The captured bytes are what getxattr
// returned on CT115 (Rocky Linux 9) for a folder after
// "setfacl -m u:nobody:rwx,g::r-x d; setfacl -d -m u:nobody:rx,g:users:rx d" (cross-checked with getfacl -p).
public class PermissionPosixAclTests
{
    private static byte[] Acl(params (ushort Tag, ushort Perm, uint Id)[] entries)
    {
        var bytes = new List<byte>(BitConverter.GetBytes(2u));
        foreach (var (tag, perm, id) in entries)
        {
            bytes.AddRange(BitConverter.GetBytes(tag));
            bytes.AddRange(BitConverter.GetBytes(perm));
            bytes.AddRange(BitConverter.GetBytes(id));
        }
        return [.. bytes];
    }

    private const uint None = 0xFFFFFFFF;

    // Access ACL: user::rwx user:nobody:rwx group::r-x mask::rwx other::r-x
    private static readonly byte[] CapturedAccess = Convert.FromHexString(
        "02000000" + "0100" + "0700" + "FFFFFFFF" + "0200" + "0700" + "FEFF0000" + "0400" + "0500" + "FFFFFFFF"
        + "1000" + "0700" + "FFFFFFFF" + "2000" + "0500" + "FFFFFFFF");

    [Fact]
    public void Captured_access_acl_parses()
    {
        var acl = PermissionScanLinux.ParsePosixAcl(CapturedAccess)!;
        Assert.Equal(5, acl.Count);
        Assert.Equal((PermissionScanLinux.TagUser, (ushort)7, 65534u), (acl[1].Tag, acl[1].Perm, acl[1].Id));
        Assert.Equal(PermissionScanLinux.TagMask, acl[3].Tag);
        Assert.Equal(CapturedAccess, Acl((1, 7, None), (2, 7, 65534), (4, 5, None), (0x10, 7, None), (0x20, 5, None)));
    }

    [Fact]
    public void Default_acl_with_a_named_group_parses()
    {
        var acl = PermissionScanLinux.ParsePosixAcl(Acl((1, 7, None), (2, 5, 65534), (4, 5, None), (8, 5, 100), (0x10, 5, None), (0x20, 5, None)))!;
        Assert.Equal(6, acl.Count);
        Assert.Equal((PermissionScanLinux.TagGroup, (ushort)5, 100u), (acl[3].Tag, acl[3].Perm, acl[3].Id));
    }

    [Fact]
    public void An_acl_without_a_mask_is_valid_when_it_has_the_base_entries()
    {
        Assert.NotNull(PermissionScanLinux.ParsePosixAcl(Acl((1, 6, None), (4, 4, None), (0x20, 0, None))));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0200")] // too short
    [InlineData("01000000")] // wrong version
    [InlineData("02000000" + "0100" + "0700")] // half an entry
    [InlineData("02000000" + "0900" + "0700" + "FFFFFFFF")] // unknown tag
    [InlineData("02000000" + "0100" + "0F00" + "FFFFFFFF")] // permission bits beyond rwx
    public void Garbage_is_not_an_acl(string hex) =>
        Assert.Null(PermissionScanLinux.ParsePosixAcl(Convert.FromHexString(hex)));

    [Fact]
    public void An_acl_missing_a_base_entry_or_repeating_one_is_rejected()
    {
        Assert.Null(PermissionScanLinux.ParsePosixAcl(Acl((1, 7, None), (0x20, 5, None))));
        Assert.Null(PermissionScanLinux.ParsePosixAcl(Acl((1, 7, None), (1, 5, None), (4, 5, None), (0x20, 5, None))));
        Assert.Null(PermissionScanLinux.ParsePosixAcl(Acl((1, 7, None), (4, 5, None), (0x10, 7, None), (0x10, 7, None), (0x20, 5, None))));
    }

    private static string User(uint id) => id == 65534 ? "nobody" : id.ToString();
    private static string Group(uint id) => id == 100 ? "users" : id.ToString();

    [Fact]
    public void Mode_bits_give_owner_group_and_other()
    {
        var e = PermissionScanLinux.EntriesOf(0b111_101_100, 1000, 100, null, folder: true, User, Group);
        Assert.Equal(["user:1000", "group:users", "other"], e.Select(x => x.Principal).ToArray());
        Assert.Equal([23, 17, 1], e.Select(x => x.Level).ToArray());
    }

    [Fact]
    public void A_file_has_no_delete_bit_for_write()
    {
        var e = PermissionScanLinux.EntriesOf(0b110_100_110, 1000, 100, null, folder: false, User, Group);
        Assert.Equal([3, 1, 3], e.Select(x => x.Level).ToArray());
    }

    [Fact]
    public void The_mask_limits_group_and_named_entries_and_the_level_before_is_kept()
    {
        // user::rwx user:nobody:rwx group::r-x mask::r-- other::r-x
        var acl = PermissionScanLinux.ParsePosixAcl(Acl((1, 7, None), (2, 7, 65534), (4, 5, None), (0x10, 4, None), (0x20, 5, None)))!;
        var e = PermissionScanLinux.EntriesOf(0b111_100_101, 0, 0, acl, folder: true, User, Group);
        Assert.Equal(["user:0", "user:nobody", "group:0", "other"], e.Select(x => x.Principal).ToArray());
        Assert.Equal([23, 1, 1, 17], e.Select(x => x.Level).ToArray()); // owner and other are not limited
        Assert.Equal([0, 23, 17, 0], e.Select(x => x.Before).ToArray());
    }

    private const string Testparm = """
        # Global parameters
        [global]
        	map to guest = Bad User
        	workgroup = SAMBA

        [homes]
        	browseable = No
        	read only = No
        	valid users = %S %D%w%S

        [print$]
        	path = /var/lib/samba/drivers
        	write list = printadmin root

        [share]
        	guest ok = Yes
        	path = /srv/share
        	read only = No
        	vfs objects = full_audit
        	full_audit:syslog = true

        [secure]
        	path = /srv/secure
        	valid users = @staff
        	vfs objects = acl_xattr full_audit

        [docs]
        	path = /srv/share/docs
        	writable = Yes
        	public = Yes
        """;

    [Fact]
    public void Testparm_output_gives_the_shares_with_their_effective_settings()
    {
        var shares = PermissionScanLinux.ParseShares(Testparm.Replace("\r\n", "\n"));
        Assert.Equal(["print$", "share", "secure", "docs"], shares.Select(s => s.Name).ToArray()); // global and homes (no path) are not shares of a folder
        var share = shares.Single(s => s.Name == "share");
        Assert.Equal(("/srv/share", true, false, false), (share.Path, share.GuestOk, share.ReadOnly, share.NtAcl));
        var secure = shares.Single(s => s.Name == "secure");
        Assert.Equal((false, true, "@staff", true), (secure.GuestOk, secure.ReadOnly, secure.ValidUsers, secure.NtAcl)); // read only is the default
        Assert.Equal("printadmin root", shares.Single(s => s.Name == "print$").WriteList);
        var docs = shares.Single(s => s.Name == "docs");
        Assert.Equal((true, false), (docs.GuestOk, docs.ReadOnly)); // public and writable are the old names
    }

    [Fact]
    public void Shares_holding_the_folder_or_inside_it_are_found()
    {
        var shares = PermissionScanLinux.ParseShares(Testparm.Replace("\r\n", "\n"));
        Assert.Equal(["share"], PermissionScanLinux.SharesHolding(shares, "/srv/share/video").Select(s => s.Name).ToArray());
        Assert.Equal(["share", "docs"], PermissionScanLinux.SharesHolding(shares, "/srv/share").Select(s => s.Name).ToArray());
        Assert.Empty(PermissionScanLinux.SharesHolding(shares, "/data/other"));
        Assert.Empty(PermissionScanLinux.SharesHolding(shares, "/srv/shares")); // a prefix of the name is not the folder
    }
}
