using System.Security.AccessControl;
using System.Security.Principal;
using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class PermissionRightsMapTests
{
    private static int Map(FileSystemRights rights) => PermissionScanWindows.MapRights(rights);

    [Theory]
    [InlineData(FileSystemRights.FullControl, 31, "full")]
    [InlineData(FileSystemRights.Modify, 23, "modify")]
    [InlineData(FileSystemRights.ReadAndExecute, 17, "read")]
    [InlineData(FileSystemRights.Read, 1, "list")]
    [InlineData(FileSystemRights.Write, 2, "write")]
    [InlineData(FileSystemRights.ReadData | FileSystemRights.WriteData, 3, "readWrite")]
    [InlineData(FileSystemRights.ListDirectory, 1, "list")]
    [InlineData(FileSystemRights.CreateFiles | FileSystemRights.CreateDirectories, 2, "write")]
    [InlineData(FileSystemRights.Traverse, 16, "traverse")]
    [InlineData(FileSystemRights.Delete, 4, "special")]
    [InlineData(FileSystemRights.DeleteSubdirectoriesAndFiles, 4, "special")]
    [InlineData(FileSystemRights.ChangePermissions, 8, "special")]
    [InlineData(FileSystemRights.TakeOwnership, 8, "special")]
    public void Rights_become_levels(FileSystemRights rights, int level, string code)
    {
        Assert.Equal(level, Map(rights));
        Assert.Equal(code, PermissionContract.LevelCode(level));
    }

    [Fact]
    public void Attributes_and_synchronize_alone_give_no_level()
    {
        Assert.Equal(0, Map(FileSystemRights.ReadAttributes | FileSystemRights.ReadExtendedAttributes | FileSystemRights.ReadPermissions));
        Assert.Equal(0, Map(FileSystemRights.Synchronize));
    }

    [Fact]
    public void Generic_modify_with_change_permissions_is_not_modify()
    {
        var level = Map(FileSystemRights.Modify | FileSystemRights.ChangePermissions);
        Assert.Equal(31, level);
        Assert.Equal("full", PermissionContract.LevelCode(level));
    }

    [Fact]
    public void Labels_are_readable()
    {
        Assert.Equal("Full", PermissionContract.LevelLabel(31));
        Assert.Equal("Modify", PermissionContract.LevelLabel(23));
        Assert.Equal("Read", PermissionContract.LevelLabel(17));
        Assert.Equal("List/Read data", PermissionContract.LevelLabel(1));
        Assert.Equal("Special (0xC)", PermissionContract.LevelLabel(12));
        Assert.Equal("This folder, subfolders and files", PermissionContract.ScopeLabel(7));
        Assert.Equal("Subfolders and files", PermissionContract.ScopeLabel(6));
    }

    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    private static FileSystemAccessRule Rule(InheritanceFlags inherit, PropagationFlags propagation,
        AccessControlType type = AccessControlType.Allow) =>
        new(Everyone, FileSystemRights.Modify, inherit, propagation, type);

    [Fact]
    public void Scope_follows_the_propagation_flags()
    {
        Assert.Equal(7, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None), true));
        Assert.Equal(1, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.None, PropagationFlags.None), true));
        Assert.Equal(6, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly), true));
        Assert.Equal(2, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.ContainerInherit, PropagationFlags.InheritOnly), true));
        Assert.Equal(4, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.ObjectInherit, PropagationFlags.InheritOnly), true));
    }

    [Fact]
    public void A_file_entry_applies_to_the_file_only() =>
        Assert.Equal(1, PermissionScanWindows.ScopeOf(Rule(InheritanceFlags.None, PropagationFlags.None), false));
}
