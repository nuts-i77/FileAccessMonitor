using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// v13 (1.11): a Viewer without folders sees nothing; seeing everything is the explicit UserScopes.AllFolders flag
public static class SchemaV111
{
    // CollectorStates key: set once the Viewers of an older version were converted
    public const string ViewerScopeMarker = "Schema.ViewerScope111";

    public static async Task ApplyAsync(AccessDbContext db)
    {
        await AddColumnsAsync(db, "UserScopes", new()
        {
            ["AllFolders"] = @"ALTER TABLE ""UserScopes"" ADD COLUMN ""AllFolders"" INTEGER NOT NULL DEFAULT 0",
        });
        // What an agent reports about its outbox
        await AddColumnsAsync(db, "Agents", new()
        {
            ["OutboxFull"] = @"ALTER TABLE ""Agents"" ADD COLUMN ""OutboxFull"" INTEGER NOT NULL DEFAULT 0",
            ["OutboxBytes"] = @"ALTER TABLE ""Agents"" ADD COLUMN ""OutboxBytes"" INTEGER NOT NULL DEFAULT 0",
        });

        await ConvertEmptyViewerScopesAsync(db);
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

    // Before 1.11 a Viewer without folders saw everything. So that nothing changes on upgrade, every such
    // user becomes "all folders" once; the marker keeps this from running again (a Viewer whose folders an
    // administrator removed later must not become "all folders" at the next start).
    internal static async Task ConvertEmptyViewerScopesAsync(AccessDbContext db)
    {
        var done = await db.Database
            .SqlQueryRaw<string>(@"SELECT ""Value"" FROM ""CollectorStates"" WHERE ""Key"" = {0}", ViewerScopeMarker)
            .ToListAsync();
        if (done.Count > 0) return;

        await using var tx = await db.Database.BeginTransactionAsync();
        // Everyone who is not an Admin: users without a scope row, and rows without folders
        const string viewers = @"SELECT u.""Id"" FROM ""AspNetUsers"" u WHERE u.""Id"" NOT IN (
    SELECT ur.""UserId"" FROM ""AspNetUserRoles"" ur JOIN ""AspNetRoles"" r ON r.""Id"" = ur.""RoleId"" WHERE r.""Name"" = 'Admin')";
        await db.Database.ExecuteSqlRawAsync(@"
INSERT INTO ""UserScopes"" (""UserId"", ""Paths"", ""NotifyEmail"", ""SendReport"", ""AllFolders"")
SELECT v.""Id"", '', NULL, 1, 1 FROM (" + viewers + @") v
WHERE v.""Id"" NOT IN (SELECT ""UserId"" FROM ""UserScopes"")");
        await db.Database.ExecuteSqlRawAsync(@"
UPDATE ""UserScopes"" SET ""AllFolders"" = 1
WHERE TRIM(""Paths"", ' ' || char(9) || char(10) || char(13)) = '' AND ""UserId"" IN (" + viewers + ")");
        await db.Database.ExecuteSqlRawAsync(
            @"INSERT OR REPLACE INTO ""CollectorStates"" (""Key"", ""Value"") VALUES ({0}, '1')", ViewerScopeMarker);
        await tx.CommitAsync();
    }
}
