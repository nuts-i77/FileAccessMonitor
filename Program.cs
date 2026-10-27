using System.Globalization;
using System.Text;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Localization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;

var logDir = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "FileAccessMonitor", "logs");
Directory.CreateDirectory(logDir);

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    // Framework logs (EF Core SQL, per-request ASP.NET Core) are too chatty for a service log
    .MinimumLevel.Override("Microsoft", Serilog.Events.LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", Serilog.Events.LogEventLevel.Information)
    .WriteTo.Console()
    .WriteTo.File(
        path: Path.Combine(logDir, "app-.log"),
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();

var userSettingsFile = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "FileAccessMonitor", "settings.json");
builder.Configuration.AddJsonFile(userSettingsFile, optional: true, reloadOnChange: true);

builder.Host.UseWindowsService(options =>
{
    options.ServiceName = "FileAccessMonitor";
});

var dbPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "FileAccessMonitor", "fileaccess.db");
Directory.CreateDirectory(Path.GetDirectoryName(dbPath)!);

builder.Services.AddDbContext<AccessDbContext>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 8;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
})
.AddEntityFrameworkStores<AccessDbContext>()
.AddErrorDescriber<LocalizedIdentityErrorDescriber>()
.AddDefaultTokenProviders();

// JWT: use the configured key only if it is a real secret; otherwise generate
// one per installation so the published sample key can never be used to forge tokens.
var jwtKey = builder.Configuration["Jwt:Key"];
if (string.IsNullOrWhiteSpace(jwtKey)
    || jwtKey.StartsWith("CHANGE_THIS", StringComparison.OrdinalIgnoreCase)
    || Encoding.UTF8.GetByteCount(jwtKey) < 32)
{
    if (!string.IsNullOrWhiteSpace(jwtKey))
        Log.Warning("Jwt:Key is a placeholder or shorter than 32 bytes; using a generated key instead.");
    jwtKey = SecretStore.GetOrCreateJwtKey();
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Jwt:Key"] = jwtKey });
}
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
    // Reject tokens of deleted users, or issued before a password/role change
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
            if (!await TokenService.IsCurrentAsync(context.Principal!, userManager))
                context.Fail("Token has been revoked.");
        }
    };
});

// Encrypts alert secrets (webhook URL, SMTP password) stored in settings.json
builder.Services.AddDataProtection()
    .SetApplicationName("FileAccessMonitor")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FileAccessMonitor", "keys")))
    .ProtectKeysWithDpapi(protectToLocalMachine: true);

// Behind a reverse proxy, take the client IP (for the operation log) from X-Forwarded-For,
// but only from the proxies listed in ReverseProxy:KnownProxies.
var knownProxies = builder.Configuration.GetSection("ReverseProxy:KnownProxies").Get<string[]>() ?? [];
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor;
    foreach (var proxy in knownProxies)
        if (System.Net.IPAddress.TryParse(proxy, out var ip)) options.KnownProxies.Add(ip);
});

builder.Services.AddAuthorization();
builder.Services.AddHttpClient();
builder.Services.AddSingleton<SaclManagerService>();
builder.Services.AddSingleton<DnsResolverService>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton<AlertService>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddHostedService<EventLogCollectorService>();
builder.Services.AddSingleton<RetentionService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<RetentionService>());
builder.Services.AddControllers();

var app = builder.Build();

// DB migration + seed initial admin
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
    db.Database.EnsureCreated(); // new DB: creates all tables

    // Existing DB upgrade: create Identity tables if missing
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetRoles"" (
    ""Id"" TEXT NOT NULL CONSTRAINT ""PK_AspNetRoles"" PRIMARY KEY,
    ""Name"" TEXT NULL, ""NormalizedName"" TEXT NULL, ""ConcurrencyStamp"" TEXT NULL)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetUsers"" (
    ""Id"" TEXT NOT NULL CONSTRAINT ""PK_AspNetUsers"" PRIMARY KEY,
    ""DisplayName"" TEXT NOT NULL DEFAULT '',
    ""UserName"" TEXT NULL, ""NormalizedUserName"" TEXT NULL,
    ""Email"" TEXT NULL, ""NormalizedEmail"" TEXT NULL,
    ""EmailConfirmed"" INTEGER NOT NULL, ""PasswordHash"" TEXT NULL,
    ""SecurityStamp"" TEXT NULL, ""ConcurrencyStamp"" TEXT NULL,
    ""PhoneNumber"" TEXT NULL, ""PhoneNumberConfirmed"" INTEGER NOT NULL,
    ""TwoFactorEnabled"" INTEGER NOT NULL, ""LockoutEnd"" TEXT NULL,
    ""LockoutEnabled"" INTEGER NOT NULL, ""AccessFailedCount"" INTEGER NOT NULL)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetRoleClaims"" (
    ""Id"" INTEGER NOT NULL CONSTRAINT ""PK_AspNetRoleClaims"" PRIMARY KEY AUTOINCREMENT,
    ""RoleId"" TEXT NOT NULL, ""ClaimType"" TEXT NULL, ""ClaimValue"" TEXT NULL,
    CONSTRAINT ""FK_AspNetRoleClaims_AspNetRoles_RoleId"" FOREIGN KEY (""RoleId"") REFERENCES ""AspNetRoles"" (""Id"") ON DELETE CASCADE)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetUserClaims"" (
    ""Id"" INTEGER NOT NULL CONSTRAINT ""PK_AspNetUserClaims"" PRIMARY KEY AUTOINCREMENT,
    ""UserId"" TEXT NOT NULL, ""ClaimType"" TEXT NULL, ""ClaimValue"" TEXT NULL,
    CONSTRAINT ""FK_AspNetUserClaims_AspNetUsers_UserId"" FOREIGN KEY (""UserId"") REFERENCES ""AspNetUsers"" (""Id"") ON DELETE CASCADE)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetUserLogins"" (
    ""LoginProvider"" TEXT NOT NULL, ""ProviderKey"" TEXT NOT NULL,
    ""ProviderDisplayName"" TEXT NULL, ""UserId"" TEXT NOT NULL,
    CONSTRAINT ""PK_AspNetUserLogins"" PRIMARY KEY (""LoginProvider"", ""ProviderKey""),
    CONSTRAINT ""FK_AspNetUserLogins_AspNetUsers_UserId"" FOREIGN KEY (""UserId"") REFERENCES ""AspNetUsers"" (""Id"") ON DELETE CASCADE)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetUserRoles"" (
    ""UserId"" TEXT NOT NULL, ""RoleId"" TEXT NOT NULL,
    CONSTRAINT ""PK_AspNetUserRoles"" PRIMARY KEY (""UserId"", ""RoleId""),
    CONSTRAINT ""FK_AspNetUserRoles_AspNetRoles_RoleId"" FOREIGN KEY (""RoleId"") REFERENCES ""AspNetRoles"" (""Id"") ON DELETE CASCADE,
    CONSTRAINT ""FK_AspNetUserRoles_AspNetUsers_UserId"" FOREIGN KEY (""UserId"") REFERENCES ""AspNetUsers"" (""Id"") ON DELETE CASCADE)");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AspNetUserTokens"" (
    ""UserId"" TEXT NOT NULL, ""LoginProvider"" TEXT NOT NULL, ""Name"" TEXT NOT NULL, ""Value"" TEXT NULL,
    CONSTRAINT ""PK_AspNetUserTokens"" PRIMARY KEY (""UserId"", ""LoginProvider"", ""Name""),
    CONSTRAINT ""FK_AspNetUserTokens_AspNetUsers_UserId"" FOREIGN KEY (""UserId"") REFERENCES ""AspNetUsers"" (""Id"") ON DELETE CASCADE)");
    await db.Database.ExecuteSqlRawAsync(@"CREATE UNIQUE INDEX IF NOT EXISTS ""RoleNameIndex"" ON ""AspNetRoles"" (""NormalizedName"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""IX_AspNetRoleClaims_RoleId"" ON ""AspNetRoleClaims"" (""RoleId"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""EmailIndex"" ON ""AspNetUsers"" (""NormalizedEmail"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE UNIQUE INDEX IF NOT EXISTS ""UserNameIndex"" ON ""AspNetUsers"" (""NormalizedUserName"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""IX_AspNetUserClaims_UserId"" ON ""AspNetUserClaims"" (""UserId"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""IX_AspNetUserLogins_UserId"" ON ""AspNetUserLogins"" (""UserId"")");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""IX_AspNetUserRoles_RoleId"" ON ""AspNetUserRoles"" (""RoleId"")");

    // v2: add client connection info columns (only if missing, so no failed SQL is logged)
    var accessColumns = await db.Database
        .SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_table_info('AccessRecords')")
        .ToListAsync();
    var addColumnSql = new Dictionary<string, string>
    {
        ["ClientIp"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""ClientIp"" TEXT NULL",
        ["ClientMachine"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""ClientMachine"" TEXT NULL",
    };
    foreach (var (column, sql) in addColumnSql)
    {
        if (!accessColumns.Contains(column, StringComparer.OrdinalIgnoreCase))
            await db.Database.ExecuteSqlRawAsync(sql);
    }

    // v3: operation log and collector position
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""AuditLogs"" (
    ""Id"" INTEGER NOT NULL CONSTRAINT ""PK_AuditLogs"" PRIMARY KEY AUTOINCREMENT,
    ""Time"" TEXT NOT NULL, ""UserName"" TEXT NOT NULL, ""Action"" TEXT NOT NULL,
    ""Detail"" TEXT NULL, ""ClientIp"" TEXT NULL)");
    await db.Database.ExecuteSqlRawAsync(@"CREATE INDEX IF NOT EXISTS ""IX_AuditLogs_Time"" ON ""AuditLogs"" (""Time"")");
    await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""CollectorStates"" (
    ""Key"" TEXT NOT NULL CONSTRAINT ""PK_CollectorStates"" PRIMARY KEY,
    ""Value"" TEXT NOT NULL)");

    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Admin", "Viewer" })
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }

    // Create default admin if no users exist
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    if (!userManager.Users.Any())
    {
        var admin = new ApplicationUser
        {
            UserName = "admin",
            DisplayName = "Administrator",
            Email = "admin@localhost"
        };
        var password = SecretStore.CreateInitialAdminPassword();
        var result = await userManager.CreateAsync(admin, password);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(admin, "Admin");
            Log.Information("Default admin user created. Username: admin / Password is in {File} (readable by Administrators only).",
                SecretStore.InitialAdminPasswordFile);
        }
        else
        {
            SecretStore.DeleteInitialAdminPassword();
            Log.Error("Failed to create default admin: {Errors}",
                string.Join(" ", result.Errors.Select(e => e.Description)));
        }
    }
}

// Load DNS server setting
var dnsResolver = app.Services.GetRequiredService<DnsResolverService>();
dnsResolver.SetDnsServer(app.Configuration["DnsServer"]);

// Security headers. All assets are served locally, so the CSP only allows 'self'.
// 'unsafe-inline' is still needed for the inline onclick handlers / style attributes in the UI.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    headers["X-Content-Type-Options"] = "nosniff";
    headers["X-Frame-Options"] = "DENY";
    headers["Referrer-Policy"] = "no-referrer";
    await next();
});

// API messages follow the GUI language (Accept-Language). Formatting stays culture-invariant.
var uiCultures = new[] { new CultureInfo("en"), new CultureInfo("ja") };
app.UseRequestLocalization(new RequestLocalizationOptions
{
    DefaultRequestCulture = new RequestCulture(CultureInfo.InvariantCulture, uiCultures[0]),
    SupportedCultures = [CultureInfo.InvariantCulture],
    SupportedUICultures = uiCultures,
});

if (knownProxies.Length > 0) app.UseForwardedHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapFallbackToFile("index.html");

app.Run();
