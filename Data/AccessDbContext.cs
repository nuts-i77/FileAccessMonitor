using FileAccessMonitor.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

public class AccessDbContext : IdentityDbContext<ApplicationUser>
{
    public AccessDbContext(DbContextOptions<AccessDbContext> options) : base(options) { }

    public DbSet<AccessRecord> AccessRecords { get; set; }
    public DbSet<AuditLogEntry> AuditLogs { get; set; }
    public DbSet<CollectorState> CollectorStates { get; set; }
    public DbSet<UserScope> UserScopes { get; set; }
    public DbSet<Agent> Agents { get; set; }
    public DbSet<AgentEnrollment> AgentEnrollments { get; set; }
    public DbSet<RevokedToken> RevokedTokens { get; set; }
    public DbSet<ChainHead> ChainHeads { get; set; }
    public DbSet<ChainCheckpoint> ChainCheckpoints { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AccessRecord>(entity =>
        {
            entity.HasIndex(r => r.FilePath);
            entity.Property(r => r.AtCreation).HasDefaultValue(false);   // same default as the column the migration adds
            entity.HasIndex(r => r.FolderPath);
            entity.HasIndex(r => r.AccessTime);
            entity.HasIndex(r => r.UserName);
            entity.HasIndex(r => r.ServerName);
            entity.HasIndex(r => new { r.FilePath, r.AccessTime });
        });

        modelBuilder.Entity<AuditLogEntry>(entity => entity.HasIndex(e => e.Time));
    }
}
