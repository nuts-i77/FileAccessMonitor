using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// 1.11.1: failed sign-ins cannot lock a user out for everyone; signing out ends the token on the server;
// a registration code cannot take over another agent or this server's name
public class SignInAndEnrollTests : IDisposable
{
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly ServiceProvider _services;

    public SignInAndEnrollTests()
    {
        _conn.Open();
        var services = new ServiceCollection()
            .AddLogging()
            .AddDbContext<AccessDbContext>(o => o.UseSqlite(_conn));
        services.AddIdentityCore<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<AccessDbContext>();
        _services = services.BuildServiceProvider();
        using var scope = _services.CreateScope();
        scope.ServiceProvider.GetRequiredService<AccessDbContext>().Database.EnsureCreated();
    }

    public void Dispose()
    {
        _services.Dispose();
        _conn.Dispose();
    }

    // ---- failed sign-ins

    private static readonly IPAddress A = IPAddress.Parse("192.0.2.10");
    private static readonly IPAddress B = IPAddress.Parse("192.0.2.20");

    [Fact]
    public void Wrong_passwords_from_one_address_do_not_stop_the_user_elsewhere()
    {
        var now = new DateTime(2026, 11, 7, 0, 0, 0, DateTimeKind.Utc);
        var throttle = new LoginThrottle(() => now);
        for (var i = 0; i < LoginThrottle.PerUserAndAddress; i++)
        {
            Assert.False(throttle.IsBlocked("admin", A));
            throttle.Failed("admin", A);
        }
        Assert.True(throttle.IsBlocked("admin", A));
        Assert.True(throttle.IsBlocked("ADMIN", A));    // names are not case-sensitive
        Assert.False(throttle.IsBlocked("admin", B));   // the real administrator elsewhere
        Assert.False(throttle.IsBlocked("user1", A));

        now += LoginThrottle.Window;
        Assert.False(throttle.IsBlocked("admin", A));
    }

    [Fact]
    public void An_address_that_tries_many_names_is_stopped_but_loopback_is_not_counted_together()
    {
        var throttle = new LoginThrottle(() => DateTime.UtcNow);
        for (var i = 0; i < LoginThrottle.PerAddress; i++) throttle.Failed($"user{i}", A);
        Assert.True(throttle.IsBlocked("someone", A));
        Assert.False(throttle.IsBlocked("someone", B));

        // A reverse proxy on this machine: everyone comes from 127.0.0.1
        for (var i = 0; i < LoginThrottle.PerAddress; i++) throttle.Failed($"user{i}", IPAddress.Loopback);
        Assert.False(throttle.IsBlocked("someone", IPAddress.Loopback));
    }

    [Fact]
    public void A_name_that_fails_from_many_addresses_is_stopped()
    {
        var throttle = new LoginThrottle(() => DateTime.UtcNow);
        for (var i = 0; i < LoginThrottle.PerUser; i++) throttle.Failed("admin", IPAddress.Parse($"198.51.100.{i % 250 + 1}"));
        Assert.True(throttle.IsBlocked("admin", B));
    }

    [Fact]
    public void A_correct_password_ends_the_wait_for_that_address_only()
    {
        var throttle = new LoginThrottle(() => DateTime.UtcNow);
        for (var i = 0; i < LoginThrottle.PerUserAndAddress - 1; i++) { throttle.Failed("admin", A); throttle.Failed("admin", B); }
        throttle.Succeeded("admin", A);
        throttle.Failed("admin", A);
        throttle.Failed("admin", B);
        Assert.False(throttle.IsBlocked("admin", A));
        Assert.True(throttle.IsBlocked("admin", B));
    }

    [Fact]
    public async Task Sign_in_is_refused_after_repeated_failures_even_with_the_right_password()
    {
        var (controller, scope) = await Auth("Correct-horse-1");
        using var _ = scope;
        for (var i = 0; i < LoginThrottle.PerUserAndAddress - 1; i++)
            Assert.IsType<UnauthorizedObjectResult>(await controller.Login(new LoginRequest("admin", "wrong")));
        Assert.Equal(429, ((ObjectResult)await controller.Login(new LoginRequest("admin", "wrong"))).StatusCode);
        Assert.Equal(429, ((ObjectResult)await controller.Login(new LoginRequest("admin", "Correct-horse-1"))).StatusCode);

        // The account itself is not locked
        var user = await scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>().FindByNameAsync("admin");
        Assert.Equal(0, user!.AccessFailedCount);
        Assert.Null(user.LockoutEnd);
    }

    [Fact]
    public async Task Unknown_names_count_as_failures_too()
    {
        var (controller, scope) = await Auth("Correct-horse-1");
        using var _ = scope;
        for (var i = 0; i < LoginThrottle.PerUserAndAddress - 1; i++)
            Assert.IsType<UnauthorizedObjectResult>(await controller.Login(new LoginRequest("nobody", "x")));
        Assert.Equal(429, ((ObjectResult)await controller.Login(new LoginRequest("nobody", "x"))).StatusCode);
    }

    private async Task<(AuthController, IServiceScope)> Auth(string password)
    {
        var scope = _services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.FindByNameAsync("admin") == null)
            Assert.True((await users.CreateAsync(new ApplicationUser { UserName = "admin", DisplayName = "admin" }, password)).Succeeded);
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Jwt:Key"] = new string('k', 48), ["Jwt:Issuer"] = "t", ["Jwt:Audience"] = "t",
        }).Build();
        var http = new DefaultHttpContext();
        http.Connection.RemoteIpAddress = A;
        var controller = new AuthController(users, new TokenService(config, users),
            new AuditLog(_services.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditLog>.Instance), new LoginThrottle(() => DateTime.UtcNow))
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
        return (controller, scope);
    }

    // ---- signing out

    [Fact]
    public async Task A_signed_out_token_is_refused_and_other_sign_ins_stay()
    {
        using var scope = _services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var user = new ApplicationUser { UserName = "sato", DisplayName = "sato" };
        Assert.True((await users.CreateAsync(user, "Correct-horse-1")).Succeeded);
        var stamp = await users.GetSecurityStampAsync(user);
        ClaimsPrincipal Token(string jti) => new(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, user.Id), new Claim(TokenService.SecurityStampClaim, stamp),
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            new Claim(JwtRegisteredClaimNames.Exp, DateTimeOffset.UtcNow.AddHours(8).ToUnixTimeSeconds().ToString()),
        ], "test"));

        Assert.True(await TokenService.IsCurrentAsync(Token("one"), users, db));
        await TokenService.RevokeAsync(Token("one"), db);
        await TokenService.RevokeAsync(Token("one"), db);   // signing out twice is fine
        Assert.False(await TokenService.IsCurrentAsync(Token("one"), users, db));
        Assert.True(await TokenService.IsCurrentAsync(Token("two"), users, db));
        Assert.True(db.RevokedTokens.Single().ExpiresAt > DateTime.UtcNow.AddHours(7));
    }

    [Fact]
    public async Task Revoked_tokens_that_have_expired_are_removed()
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.RevokedTokens.Add(new RevokedToken { Jti = "old", ExpiresAt = DateTime.UtcNow.AddMinutes(-1) });
        await db.SaveChangesAsync();
        await TokenService.RevokeAsync(new ClaimsPrincipal(new ClaimsIdentity([new Claim(JwtRegisteredClaimNames.Jti, "new")], "test")), db);
        Assert.Equal(["new"], db.RevokedTokens.Select(t => t.Jti).ToList());
    }

    [Fact]
    public async Task The_new_tables_and_columns_are_added_to_an_older_database()
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        await db.Database.ExecuteSqlRawAsync(@"DROP TABLE ""RevokedTokens""");
        await db.Database.ExecuteSqlRawAsync(@"ALTER TABLE ""AgentEnrollments"" DROP COLUMN ""AgentId""");
        await SchemaV111.ApplyAsync(db);
        await SchemaV111.ApplyAsync(db);
        Assert.Empty(db.RevokedTokens.ToList());
        Assert.Empty(db.AgentEnrollments.ToList());
    }

    // ---- registration codes

    private async Task<IActionResult> Enroll(string code, string name)
    {
        using var scope = _services.CreateScope();
        var config = new ConfigurationBuilder().Build();
        var http = new DefaultHttpContext();
        http.Connection.LocalPort = AgentEndpoint.Port(config);
        http.Request.Scheme = "https";
        var controller = new AgentApiController(scope.ServiceProvider.GetRequiredService<AccessDbContext>(), null!,
            new AuditLog(_services.GetRequiredService<IServiceScopeFactory>(), NullLogger<AuditLog>.Instance),
            config, NullLogger<AgentApiController>.Instance, new LocalCollectorState())
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
        return await controller.Enroll(new EnrollRequest(code, name, "1.11.1"));
    }

    private string Code(string? agentId = null)
    {
        using var scope = _services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        var code = AgentSecrets.NewSecret();
        db.AgentEnrollments.Add(new AgentEnrollment { CodeHash = AgentSecrets.Hash(code), ExpiresAt = DateTime.UtcNow.AddHours(1), AgentId = agentId });
        db.SaveChanges();
        return code;
    }

    private Agent? AgentNamed(string name)
    {
        using var scope = _services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AccessDbContext>().Agents.AsNoTracking().SingleOrDefault(a => a.Name == name);
    }

    private int Codes()
    {
        using var scope = _services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AccessDbContext>().AgentEnrollments.Count();
    }

    [Fact]
    public async Task A_code_for_a_new_server_cannot_take_over_a_registered_agent()
    {
        Assert.IsType<OkObjectResult>(await Enroll(Code(), "FS01"));
        var original = AgentNamed("FS01")!;

        var code = Code();
        Assert.IsType<ConflictObjectResult>(await Enroll(code, "fs01"));
        Assert.Equal(original.KeyHash, AgentNamed("FS01")!.KeyHash);   // the real agent keeps working
        Assert.Equal(1, Codes());                                       // the refused code can still register a new server
        Assert.IsType<OkObjectResult>(await Enroll(code, "FS02"));
    }

    [Fact]
    public async Task A_code_issued_for_an_agent_registers_that_agent_again_and_nothing_else()
    {
        Assert.IsType<OkObjectResult>(await Enroll(Code(), "FS01"));
        var original = AgentNamed("FS01")!;

        var code = Code(original.Id);
        Assert.IsType<ConflictObjectResult>(await Enroll(code, "FS02"));   // another server
        Assert.Null(AgentNamed("FS02"));
        Assert.IsType<OkObjectResult>(await Enroll(code, "FS01"));
        var again = AgentNamed("FS01")!;
        Assert.Equal(original.Id, again.Id);
        Assert.NotEqual(original.KeyHash, again.KeyHash);
        Assert.Equal(0, Codes());
    }

    [Fact]
    public async Task Nothing_registers_under_the_monitoring_servers_own_name()
    {
        Assert.IsType<ConflictObjectResult>(await Enroll(Code(), ServerConfigService.LocalName.ToLowerInvariant()));
        Assert.Null(AgentNamed(ServerConfigService.LocalName));
    }

    [Fact]
    public void The_server_filter_can_leave_out_removed_agents()
    {
        string[] withRecords = ["FS01", "FS02", "OLD", "STORAGE"];
        Assert.Equal(["FS01", "FS02", "STORAGE"], StatsController.WithoutRemoved(withRecords, ["fs01", "FS02", "NEW"], "STORAGE"));
        Assert.Equal(["FS01"], StatsController.WithoutRemoved(withRecords, ["FS01"], null));   // this server does not collect
    }

    [Fact]
    public async Task A_code_for_an_agent_that_was_removed_is_refused()
    {
        var code = Code("gone");
        Assert.IsType<ConflictObjectResult>(await Enroll(code, "FS01"));
        Assert.Null(AgentNamed("FS01"));
    }
}
