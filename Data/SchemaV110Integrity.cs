using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// Tamper detection (1.10): chain tables. Unique ChainSeq indexes and the genesis checkpoint are
// added by the tamper-detection work.
public static class SchemaV110Integrity
{
    public static async Task ApplyAsync(AccessDbContext db)
    {
        await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""ChainHeads"" (
    ""Chain"" TEXT NOT NULL CONSTRAINT ""PK_ChainHeads"" PRIMARY KEY,
    ""Seq"" INTEGER NOT NULL, ""Hash"" BLOB NOT NULL, ""UpdatedAt"" TEXT NOT NULL,
    ""LegacyMaxId"" INTEGER NOT NULL, ""LegacyCount"" INTEGER NOT NULL, ""StartedAt"" TEXT NOT NULL,
    ""VerifiedSeq"" INTEGER NOT NULL, ""VerifiedHash"" BLOB NULL, ""VerifiedAt"" TEXT NULL)");
        await db.Database.ExecuteSqlRawAsync(@"
CREATE TABLE IF NOT EXISTS ""ChainCheckpoints"" (
    ""Id"" INTEGER NOT NULL CONSTRAINT ""PK_ChainCheckpoints"" PRIMARY KEY AUTOINCREMENT,
    ""Chain"" TEXT NOT NULL, ""UpToSeq"" INTEGER NOT NULL, ""Hash"" BLOB NOT NULL, ""DeletedRows"" INTEGER NOT NULL,
    ""CreatedAt"" TEXT NOT NULL, ""Reason"" TEXT NOT NULL, ""Note"" TEXT NULL, ""KeyId"" TEXT NOT NULL, ""Mac"" BLOB NOT NULL)");
    }
}
