using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Tests;

[Collection("LocalCollects")] // these tests switch LocalCollects, which the local collector tests read
public class ServerConfigTests
{
    [Fact]
    public async Task A_monitoring_only_server_lists_just_the_agents()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        conn.Open();
        using var db = new AccessDbContext(new DbContextOptionsBuilder<AccessDbContext>().UseSqlite(conn).Options);
        db.Database.EnsureCreated();
        db.Agents.AddRange(
            new Agent { Id = "b", Name = "NAS02", KeyHash = "x", CreatedAt = DateTime.UtcNow },
            new Agent { Id = "a", Name = "FS01", KeyHash = "x", CreatedAt = DateTime.UtcNow });
        db.SaveChanges();
        var servers = new ServerConfigService(db);

        try
        {
            Assert.Equal([ServerConfigService.LocalName, "FS01", "NAS02"], await servers.ServerNamesAsync());
            ServerConfigService.LocalCollects = false;
            Assert.Equal(["FS01", "NAS02"], await servers.ServerNamesAsync());
        }
        finally
        {
            ServerConfigService.LocalCollects = true;
        }
    }
}
