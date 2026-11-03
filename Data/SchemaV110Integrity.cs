using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// Tamper detection (1.10): chain tables, unique ChainSeq indexes, and the start (genesis) of each chain.
// Old rows are not hashed: they are counted (LegacyMaxId / LegacyCount) and reported as not protected.
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

        // A failing index (duplicate ChainSeq values) must not stop the service; verification reports it
        string[] indexes =
        [
            @"CREATE UNIQUE INDEX IF NOT EXISTS ""IX_AccessRecords_ChainSeq"" ON ""AccessRecords"" (""ChainSeq"") WHERE ""ChainSeq"" IS NOT NULL",
            @"CREATE UNIQUE INDEX IF NOT EXISTS ""IX_AuditLogs_ChainSeq"" ON ""AuditLogs"" (""ChainSeq"") WHERE ""ChainSeq"" IS NOT NULL",
        ];
        foreach (var sql in indexes)
        {
            try { await db.Database.ExecuteSqlRawAsync(sql); }
            catch (Exception ex)
            {
                Serilog.Log.Warning(ex, "Could not create a unique ChainSeq index; verification will report duplicates.");
            }
        }

        try { EnsureGenesis(db, SecretStore.GetOrCreateChainKey()); }
        catch (Exception ex)
        {
            Serilog.Log.Warning(ex, "Tamper detection is off: the chain key or its start could not be set up.");
        }
    }

    // Creates the head and the genesis checkpoint of every chain that has none; safe to call again.
    // Synchronous on purpose: it runs once per chain, and also from inside a save (ChainInterceptor).
    public static void EnsureGenesis(AccessDbContext db, byte[] key)
    {
        var have = db.ChainHeads.AsNoTracking().Select(h => h.Chain).ToList();
        foreach (var chain in ChainHasher.Chains)
        {
            if (have.Contains(chain)) continue;
            var access = chain == ChainHasher.Access;

            var ownTransaction = db.Database.CurrentTransaction == null;
            using var tx = ownTransaction ? db.Database.BeginTransaction() : null;

            var legacyMaxId = db.Database.SqlQueryRaw<long>(access
                ? @"SELECT COALESCE(MAX(""Id""), 0) AS ""Value"" FROM ""AccessRecords"""
                : @"SELECT COALESCE(MAX(""Id""), 0) AS ""Value"" FROM ""AuditLogs""").AsEnumerable().First();
            var legacyCount = db.Database.SqlQueryRaw<long>(access
                ? @"SELECT COUNT(*) AS ""Value"" FROM ""AccessRecords"""
                : @"SELECT COUNT(*) AS ""Value"" FROM ""AuditLogs""").AsEnumerable().First();
            var now = DateTime.UtcNow;

            using var hasher = new ChainHasher(key);
            var hash = hasher.Genesis(chain, now, legacyMaxId, legacyCount);
            var keyId = ChainHasher.KeyId(key);
            var checkpoint = new ChainCheckpoint
            {
                Chain = chain, UpToSeq = 0, Hash = hash, DeletedRows = 0, CreatedAt = now, Reason = "genesis", KeyId = keyId,
            };
            var mac = hasher.CheckpointMac(checkpoint, []);

            // Both inserts skip when another start already wrote this chain
            var inserted = db.Database.ExecuteSql($@"
INSERT INTO ""ChainHeads"" (""Chain"", ""Seq"", ""Hash"", ""UpdatedAt"", ""LegacyMaxId"", ""LegacyCount"", ""StartedAt"", ""VerifiedSeq"")
SELECT {chain}, 0, {hash}, {now}, {legacyMaxId}, {legacyCount}, {now}, 0
WHERE NOT EXISTS (SELECT 1 FROM ""ChainHeads"" WHERE ""Chain"" = {chain})");
            if (inserted > 0)
                db.Database.ExecuteSql($@"
INSERT INTO ""ChainCheckpoints"" (""Chain"", ""UpToSeq"", ""Hash"", ""DeletedRows"", ""CreatedAt"", ""Reason"", ""KeyId"", ""Mac"")
VALUES ({chain}, 0, {hash}, 0, {now}, 'genesis', {keyId}, {mac})");
            tx?.Commit();
        }
    }
}
