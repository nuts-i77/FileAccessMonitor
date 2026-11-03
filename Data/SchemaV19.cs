using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// v11 (1.9): denied accesses, the new path of renames, and the detail of permission changes
public static class SchemaV19
{
    public static async Task ApplyAsync(AccessDbContext db)
    {
        var columns = await db.Database
            .SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_table_info('AccessRecords')")
            .ToListAsync();
        var addColumnSql = new Dictionary<string, string>
        {
            ["Denied"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""Denied"" INTEGER NOT NULL DEFAULT 0",
            ["NewPath"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""NewPath"" TEXT NULL",
            ["Detail"] = @"ALTER TABLE ""AccessRecords"" ADD COLUMN ""Detail"" TEXT NULL",
        };
        foreach (var (column, sql) in addColumnSql)
        {
            if (!columns.Contains(column, StringComparer.OrdinalIgnoreCase))
                await db.Database.ExecuteSqlRawAsync(sql);
        }
        await db.Database.ExecuteSqlRawAsync(
            @"CREATE INDEX IF NOT EXISTS ""IX_AccessRecords_Denied"" ON ""AccessRecords"" (""AccessTime"") WHERE ""Denied"" = 1");
    }
}
