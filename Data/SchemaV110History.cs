using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Data;

// File history (1.10): finding where a file came from needs the renames by destination.
public static class SchemaV110History
{
    // Partial (only renames hold a NewPath, so it stays small). NOCASE because Windows paths ignore case
    // and the history looks the destination up that way (EfHistorySource.RenamedToAsync).
    public static async Task ApplyAsync(AccessDbContext db)
    {
        var columns = await db.Database
            .SqlQueryRaw<string>(@"SELECT ""name"" AS ""Value"" FROM pragma_table_info('AccessRecords')")
            .ToListAsync();
        if (!columns.Contains("NewPath", StringComparer.OrdinalIgnoreCase)) return;   // no such table or column (yet)
        await db.Database.ExecuteSqlRawAsync(
            @"CREATE INDEX IF NOT EXISTS ""IX_AccessRecords_NewPath"" ON ""AccessRecords"" (""NewPath"" COLLATE NOCASE) WHERE ""NewPath"" IS NOT NULL");
    }
}
