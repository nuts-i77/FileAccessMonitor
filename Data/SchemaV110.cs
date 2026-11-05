using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// v12 (1.10): tamper-detection columns, the scheduled report opt-out, then each feature's own tables and indexes
public static class SchemaV110
{
    public static async Task ApplyAsync(AccessDbContext db)
    {
        await AddColumnsAsync(db, "AccessRecords", new()
        {
            ["ChainSeq"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""ChainSeq"" INTEGER NULL",
            ["ChainHash"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""ChainHash"" BLOB NULL",
            ["AtCreation"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""AtCreation"" INTEGER NOT NULL DEFAULT 0",
        });
        await AddColumnsAsync(db, "AuditLogs", new()
        {
            ["ChainSeq"] = @"ALTER TABLE ""AuditLogs"" ADD COLUMN ""ChainSeq"" INTEGER NULL",
            ["ChainHash"] = @"ALTER TABLE ""AuditLogs"" ADD COLUMN ""ChainHash"" BLOB NULL",
        });
        await AddColumnsAsync(db, "UserScopes", new()
        {
            ["SendReport"] = @"ALTER TABLE ""UserScopes"" ADD COLUMN ""SendReport"" INTEGER NOT NULL DEFAULT 1",
        });

        await SchemaV110History.ApplyAsync(db);
        await SchemaV110Integrity.ApplyAsync(db);
    }

    private static async Task AddColumnsAsync(AccessDbContext db, string table, Dictionary<string, string> addColumnSql)
    {
        var columns = await db.Database
            .SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_table_info({0})", table)
            .ToListAsync();
        if (columns.Count == 0) return;   // no such table (yet): created with all columns
        foreach (var (column, sql) in addColumnSql)
        {
            if (!columns.Contains(column, StringComparer.OrdinalIgnoreCase))
                await db.Database.ExecuteSqlRawAsync(sql);
        }
    }
}
