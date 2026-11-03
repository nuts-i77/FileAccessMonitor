using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using System.Security.Cryptography;

namespace FileAccessMonitor.Tests;

// A real SQLite file with the interceptor, the schema and the chain starts, for the tamper-detection tests
internal sealed class ChainEnv : IDisposable
{
    public string Dir { get; } = Path.Combine(Path.GetTempPath(), "fam-chain-" + Guid.NewGuid().ToString("N"));
    public string DbPath => Path.Combine(Dir, "test.db");
    public byte[] Key { get; }
    public ChainInterceptor Interceptor { get; }
    public ServiceProvider Services { get; }
    public IServiceScopeFactory Scopes => Services.GetRequiredService<IServiceScopeFactory>();

    // What the service under test "sent" and "logged", and its clock
    public List<(string Type, string Title, string Body, bool High, object[] Args)> Notifications { get; } = [];
    public List<string> OsLog { get; } = [];
    public DateTime Now { get; set; } = DateTime.UtcNow;
    public bool AnchorNotify { get; set; }

    public ChainEnv(int busySeconds = 30, bool genesis = true, byte[]? key = null, TimeSpan? watchdog = null)
    {
        Directory.CreateDirectory(Dir);
        Key = key ?? RandomNumberGenerator.GetBytes(32);
        Interceptor = new ChainInterceptor(Key, watchdog);
        var sc = new ServiceCollection();
        sc.AddLogging();
        sc.AddSingleton(Interceptor);
        sc.AddDbContext<AccessDbContext>((sp, o) =>
            o.UseSqlite($"Data Source={DbPath};Default Timeout={busySeconds}").AddInterceptors(Interceptor));
        sc.AddSingleton<AuditLog>();
        Services = sc.BuildServiceProvider();

        using var scope = Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.Database.EnsureCreated();
        if (genesis) SchemaV110Integrity.ApplyAsync(db, Key).GetAwaiter().GetResult();
    }

    public IntegrityService NewService(ChainInterceptor? interceptor = null) =>
        new(Scopes, interceptor ?? Interceptor, Services.GetRequiredService<AuditLog>(),
            (type, title, body, high, args) =>
            {
                Notifications.Add((type, title, body, high, args));
                return Task.CompletedTask;
            },
            NullLogger.Instance,
            new IntegrityOptions { DataDir = Dir, UtcNow = () => Now, OsLog = line => OsLog.Add(line), AnchorNotify = () => AnchorNotify });

    public RetentionService NewRetention() => new(Scopes, Interceptor, NullLogger<RetentionService>.Instance);

    public static AccessRecord Rec(int i, DateTime? time = null) => new()
    {
        ServerName = "S1", FilePath = $@"D:\share\f{i}.txt", FileName = $"f{i}.txt", FolderPath = @"D:\share", UserName = "taro",
        AccessType = "Read", AccessTime = time ?? DateTime.UtcNow,
    };

    // Saves n records in one SaveChanges
    public async Task AddRecordsAsync(int n, DateTime? time = null, int first = 1)
    {
        using var scope = Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.AccessRecords.AddRange(Enumerable.Range(first, n).Select(i => Rec(i, time)));
        await db.SaveChangesAsync();
    }

    public async Task AddRecordsAsync(params DateTime[] times)
    {
        using var scope = Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
        db.AccessRecords.AddRange(times.Select((t, i) => Rec(i + 1, t)));
        await db.SaveChangesAsync();
    }

    public List<AccessRecord> Records()
    {
        using var scope = Scopes.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AccessDbContext>().AccessRecords.AsNoTracking().OrderBy(r => r.Id).ToList();
    }

    public ChainHead Head(string chain)
    {
        using var scope = Scopes.CreateScope();
        return scope.ServiceProvider.GetRequiredService<AccessDbContext>().ChainHeads.AsNoTracking().First(h => h.Chain == chain);
    }

    // SQL as somebody editing the file behind the program's back would run it
    public void Exec(string sql)
    {
        using var conn = new SqliteConnection($"Data Source={DbPath};Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    public T Scalar<T>(string sql)
    {
        using var conn = new SqliteConnection($"Data Source={DbPath};Pooling=False");
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        return (T)Convert.ChangeType(cmd.ExecuteScalar()!, typeof(T));
    }

    public void Dispose()
    {
        Services.Dispose();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
