using FileAccessMonitor.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

public class AccessDbContext : IdentityDbContext<ApplicationUser>
{
    public AccessDbContext(DbContextOptions<AccessDbContext> options) : base(options) { }

    public DbSet<AccessRecord> AccessRecords { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AccessRecord>(entity =>
        {
            entity.HasIndex(r => r.FilePath);
            entity.HasIndex(r => r.FolderPath);
            entity.HasIndex(r => r.AccessTime);
            entity.HasIndex(r => r.UserName);
            entity.HasIndex(r => new { r.FilePath, r.AccessTime });
        });
    }
}
