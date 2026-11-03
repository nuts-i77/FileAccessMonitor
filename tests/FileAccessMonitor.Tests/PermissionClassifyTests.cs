using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

public class PermissionClassifyTests
{
    [Theory]
    [InlineData("Everyone", "S-1-1-0", "everyone")]
    [InlineData("全員", "S-1-1-0", "everyone")] // localized names: the SID decides
    [InlineData("NT AUTHORITY\\Authenticated Users", "S-1-5-11", "authenticatedUsers")]
    [InlineData("BUILTIN\\Users", "S-1-5-32-545", "users")]
    [InlineData("BUILTIN\\Guests", "S-1-5-32-546", "guests")]
    [InlineData("NT AUTHORITY\\ANONYMOUS LOGON", "S-1-5-7", "anonymous")]
    [InlineData("NT AUTHORITY\\NETWORK", "S-1-5-2", "network")]
    [InlineData("NT AUTHORITY\\INTERACTIVE", "S-1-5-4", "interactive")]
    [InlineData("CORP\\Domain Users", "S-1-5-21-111-222-333-513", "domainUsers")]
    [InlineData("CORP\\Domain Guests", "S-1-5-21-111-222-333-514", "domainGuests")]
    [InlineData("CORP\\Domain Computers", "S-1-5-21-111-222-333-515", "domainComputers")]
    public void Windows_principals_are_classified_by_sid(string name, string sid, string expected) =>
        Assert.Equal(expected, PermissionAnalysis.BroadKind(name, sid));

    [Theory]
    [InlineData("Everyone", "S-1-5-21-111-222-333-1105")] // a user called Everyone is not Everyone
    [InlineData("BUILTIN\\Administrators", "S-1-5-32-544")]
    [InlineData("NT AUTHORITY\\SYSTEM", "S-1-5-18")]
    [InlineData("CORP\\Sales", "S-1-5-21-111-222-333-1200")]
    [InlineData("AppContainer", "S-1-15-3-1024-1")]
    public void Other_windows_principals_are_not_broad(string name, string sid) =>
        Assert.Null(PermissionAnalysis.BroadKind(name, sid));

    [Theory]
    [InlineData("other", "other")]
    [InlineData("group:users", "group")]
    [InlineData("group:Domain Users", "group")]
    [InlineData("group:CORP\\domain users", "group")]
    [InlineData("group:nogroup", "group")]
    [InlineData("user:taro", null)]
    [InlineData("group:sales", null)]
    [InlineData("user:users", null)]
    public void Linux_principals_have_no_sid(string name, string? expected) =>
        Assert.Equal(expected, PermissionAnalysis.BroadKind(name, null));

    [Fact]
    public void Extra_names_from_the_settings_are_broad_case_insensitively()
    {
        string[] extra = ["staff", "CORP\\Everybody"];
        Assert.Equal("custom", PermissionAnalysis.BroadKind("group:Staff", null, extra));
        Assert.Equal("custom", PermissionAnalysis.BroadKind("corp\\everybody", "S-1-5-21-1-2-3-1300", extra));
        Assert.Null(PermissionAnalysis.BroadKind("group:sales", null, extra));
    }

    [Theory]
    [InlineData(PermissionContract.Read, "medium")]
    [InlineData(PermissionContract.Read | PermissionContract.Exec, "medium")]
    [InlineData(PermissionContract.Read | PermissionContract.Write, "high")]
    [InlineData(PermissionContract.Write, "high")]
    [InlineData(PermissionContract.Delete, "high")]
    [InlineData(PermissionContract.Perm, "high")]
    [InlineData(15, "high")]
    [InlineData(PermissionContract.Exec, null)] // traversal only
    public void Severity_follows_what_a_broad_principal_may_do(int level, string? expected) =>
        Assert.Equal(expected, PermissionAnalysis.Severity("everyone", level, deny: false));

    [Fact]
    public void A_deny_entry_or_a_narrow_principal_is_not_flagged()
    {
        Assert.Null(PermissionAnalysis.Severity("everyone", 15, deny: true));
        Assert.Null(PermissionAnalysis.Severity(null, 15, deny: false));
    }

    [Theory]
    [InlineData(true, false, "high")]
    [InlineData(true, true, "medium")]
    [InlineData(false, false, null)]
    public void A_guest_share_is_high_when_writable(bool guestOk, bool readOnly, string? expected) =>
        Assert.Equal(expected, PermissionAnalysis.ShareSeverity(guestOk, readOnly));

    [Fact]
    public void Max_severity_takes_the_worst()
    {
        Assert.Equal("high", PermissionAnalysis.MaxSeverity("medium", "high"));
        Assert.Equal("medium", PermissionAnalysis.MaxSeverity("", "medium"));
        Assert.Equal("", PermissionAnalysis.MaxSeverity("", null));
    }
}
