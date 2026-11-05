using FileAccessMonitor.Services;

namespace FileAccessMonitor.Tests;

// The history algorithm over an in-memory source (no database)
public class FileHistoryTests
{
    private static readonly DateTime T0 = new(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Now = new(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);

    // Records are added in time order; ids follow the order of the calls unless given
    private sealed class Mem : IHistorySource
    {
        public readonly List<HistoryRecord> All = [];
        public int Lookups;
        private long _id;

        public Mem Add(double minutes, string type, string path, string? newPath = null, string user = "u", bool folder = false,
            bool denied = false, long? id = null, string? detail = null)
        {
            All.Add(new HistoryRecord(id ?? ++_id, T0.AddMinutes(minutes), type, denied, folder, user, path, newPath, detail, null, null));
            return this;
        }

        private static bool Same(string a, string b) => a.Equals(b, PathText.ComparisonOf(a));

        public Task<HistoryRecord?> AnchorAsync(string server, string path, DateTime? at)
        {
            Lookups++;
            var of = All.Where(r => Same(r.Path, path)).OrderBy(r => r.Key).ToList();
            if (of.Count == 0) return Task.FromResult<HistoryRecord?>(null);
            if (at == null) return Task.FromResult<HistoryRecord?>(of[^1]);
            return Task.FromResult<HistoryRecord?>(of.LastOrDefault(r => r.Time <= at.Value.AddMilliseconds(1)) ?? of[0]);
        }

        public Task<HistoryRecord?> BoundaryAsync(string server, string path, HistoryKey notAfter, DateTime? notBefore)
        {
            Lookups++;
            return Task.FromResult(All.Where(r => Same(r.Path, path) && !r.Denied && r.Type is "Create" or "Delete" && r.Key <= notAfter
                    && (notBefore == null || r.Time >= notBefore)).OrderByDescending(r => r.Key).FirstOrDefault());
        }

        public Task<List<HistoryRecord>> RenamedToAsync(string server, IReadOnlyList<string> paths, HistoryKey notAfter, DateTime? notBefore, int limit)
        {
            Lookups++;
            return Task.FromResult(All.Where(r => r.Type == "Rename" && !r.Denied && r.NewPath != null && paths.Any(p => Same(r.NewPath, p))
                    && r.Key <= notAfter && (notBefore == null || r.Time >= notBefore)).OrderByDescending(r => r.Key).Take(limit).ToList());
        }

        public Task<List<HistoryRecord>> EndsAsync(string server, IReadOnlyList<string> paths, HistoryKey notBefore, int limit)
        {
            Lookups++;
            return Task.FromResult(All.Where(r => r.Type is "Rename" or "Delete" && !r.Denied && paths.Any(p => Same(r.Path, p))
                    && r.Key >= notBefore).OrderBy(r => r.Key).Take(limit).ToList());
        }

        public Task<List<HistoryRecord>> RecordsAsync(string server, string path, HistoryKey? from, HistoryKey? to, int limit)
        {
            Lookups++;
            var list = All.Where(r => Same(r.Path, path) && (from == null || r.Key >= from) && (to == null || r.Key <= to))
                .OrderBy(r => r.Key).ToList();
            return Task.FromResult(list.Count > limit ? list.Skip(list.Count - limit).ToList() : list);
        }
    }

    private static Task<HistoryOutcome> Run(Mem m, string path, DateTime? at = null, IReadOnlyList<ScopeEntry>? scope = null,
        int days = 0, bool collapse = true, int maxEvents = 500) =>
        new FileHistory(m, () => Now).BuildAsync(new HistoryRequest("FS01", path, at, days, collapse, maxEvents), scope);

    private static HistoryResult Ok(HistoryOutcome o)
    {
        Assert.Equal(HistoryStatus.Ok, o.Status);
        return o.Result!;
    }

    private static string[] Kinds(HistoryResult r) => r.Steps.Select(s => s.Kind).ToArray();

    [Fact]
    public async Task Create_rename_write_delete_is_one_story()
    {
        var m = new Mem().Add(1, "Create", @"D:\a\b.txt").Add(2, "Write", @"D:\a\b.txt")
            .Add(3, "Rename", @"D:\a\b.txt", @"D:\a\c.txt").Add(4, "Write", @"D:\a\c.txt").Add(5, "Delete", @"D:\a\c.txt");
        // starting from the old name or the new one gives the same history
        foreach (var start in new[] { @"D:\a\b.txt", @"D:\a\c.txt" })
        {
            var r = Ok(await Run(m, start));
            Assert.Equal(["create", "write", "rename", "write", "delete"], Kinds(r));
            Assert.Equal("created", r.Origin);
            Assert.Equal("deleted", r.End);
            Assert.Equal([@"D:\a\b.txt", @"D:\a\c.txt"], r.Paths.Select(p => p.Path));
        }
    }

    [Fact]
    public async Task A_rename_into_another_folder_is_a_move()
    {
        var m = new Mem().Add(1, "Create", @"D:\a\f.txt").Add(2, "Rename", @"D:\a\f.txt", @"D:\b\f.txt").Add(3, "Rename", @"D:\b\f.txt", @"D:\b\g.txt");
        var r = Ok(await Run(m, @"D:\a\f.txt"));
        Assert.Equal(["create", "move", "rename"], Kinds(r));
        Assert.Equal("exists", r.End);
        Assert.Equal(@"D:\b\g.txt", r.Paths[^1].Path);
    }

    [Fact]
    public async Task Renaming_back_to_the_first_name_is_three_segments_and_ends()
    {
        var m = new Mem().Add(1, "Create", "/s/a").Add(2, "Rename", "/s/a", "/s/b").Add(3, "Rename", "/s/b", "/s/c")
            .Add(4, "Rename", "/s/c", "/s/a").Add(5, "Read", "/s/a");
        foreach (var start in new[] { "/s/a", "/s/b", "/s/c" })
        {
            var r = Ok(await Run(m, start));
            Assert.Equal(["create", "rename", "rename", "rename", "read"], Kinds(r));
            Assert.Equal(["/s/a", "/s/b", "/s/c", "/s/a"], r.Paths.Select(p => p.Path));
            Assert.Equal("exists", r.End);
        }
    }

    [Fact]
    public async Task A_rename_without_destination_ends_in_a_gap()
    {
        var m = new Mem().Add(1, "Create", @"D:\a.txt").Add(2, "Rename", @"D:\a.txt");
        var r = Ok(await Run(m, @"D:\a.txt"));
        Assert.Equal(["create", "move", "gap"], Kinds(r));
        Assert.Equal("unknownDestination", r.End);
        Assert.Equal("unknownDestination", r.Steps[^1].Gap!.Reason);
        Assert.Null(r.Steps[1].NewPath);
    }

    [Fact]
    public async Task Unknown_origin_when_recording_started_later()
    {
        var m = new Mem().Add(1, "Read", @"D:\a.txt");
        var r = Ok(await Run(m, @"D:\a.txt"));
        Assert.Equal("unknown", r.Origin);
        Assert.Equal(["gap", "read"], Kinds(r));
        Assert.Equal("unknownOrigin", r.Steps[0].Gap!.Reason);
    }

    [Fact]
    public async Task A_renamed_parent_folder_moves_the_file_forward_and_backward()
    {
        var m = new Mem().Add(1, "Create", @"D:\x\a\f.txt").Add(2, "Rename", @"D:\x\a", @"D:\x\b", folder: true, user: "admin")
            .Add(3, "Read", @"D:\x\b\f.txt");
        foreach (var start in new[] { @"D:\x\a\f.txt", @"D:\x\b\f.txt" })
        {
            var r = Ok(await Run(m, start));
            Assert.Equal(["create", "move", "read"], Kinds(r));
            Assert.Equal(@"D:\x\a", r.Steps[1].ViaFolder);
            Assert.Equal(@"D:\x\b\f.txt", r.Steps[1].NewPath);
            Assert.Equal("admin", r.Steps[1].User);
            Assert.Equal([@"D:\x\a\f.txt", @"D:\x\b\f.txt"], r.Paths.Select(p => p.Path));
        }
    }

    [Fact]
    public async Task A_deleted_parent_folder_deletes_the_file()
    {
        var m = new Mem().Add(1, "Create", @"D:\x\a\f.txt").Add(2, "Delete", @"D:\x\a", folder: true);
        var r = Ok(await Run(m, @"D:\x\a\f.txt"));
        Assert.Equal(["create", "delete"], Kinds(r));
        Assert.Equal(@"D:\x\a", r.Steps[1].ViaFolder);
        Assert.Equal("deleted", r.End);
    }

    [Fact]
    public async Task A_folder_history_follows_its_own_renames()
    {
        var m = new Mem().Add(1, "Rename", @"D:\x\a", @"D:\x\b", folder: true).Add(2, "Delete", @"D:\x\b", folder: true);
        var r = Ok(await Run(m, @"D:\x\a"));
        Assert.Equal(["gap", "rename", "delete"], Kinds(r));
    }

    [Fact]
    public async Task A_reused_path_has_two_lives_and_at_picks_one()
    {
        var m = new Mem().Add(1, "Create", @"D:\a.txt").Add(2, "Write", @"D:\a.txt").Add(3, "Delete", @"D:\a.txt")
            .Add(60, "Create", @"D:\a.txt", user: "second").Add(61, "Read", @"D:\a.txt");

        var first = Ok(await Run(m, @"D:\a.txt", T0.AddMinutes(2)));
        Assert.Equal(["create", "write", "delete"], Kinds(first));
        Assert.Equal("deleted", first.End);

        var second = Ok(await Run(m, @"D:\a.txt", T0.AddMinutes(61)));
        Assert.Equal(["create", "read"], Kinds(second));
        Assert.Equal("exists", second.End);

        // no `at`: the newest life
        Assert.Equal(["create", "read"], Kinds(Ok(await Run(m, @"D:\a.txt"))));
        // the delete record itself belongs to the first life
        Assert.Equal(["create", "write", "delete"], Kinds(Ok(await Run(m, @"D:\a.txt", T0.AddMinutes(3)))));
    }

    [Fact]
    public async Task A_denied_delete_does_not_end_the_file()
    {
        var m = new Mem().Add(1, "Create", @"D:\a.txt").Add(2, "Delete", @"D:\a.txt", denied: true, user: "bob").Add(3, "Write", @"D:\a.txt");
        var r = Ok(await Run(m, @"D:\a.txt"));
        Assert.Equal(["create", "denied", "write"], Kinds(r));
        Assert.Equal("exists", r.End);
        Assert.Equal("Delete", r.Steps[1].Type);
    }

    [Fact]
    public async Task Paths_match_case_insensitively_on_windows_but_not_on_linux()
    {
        var win = new Mem().Add(1, "Create", @"D:\Docs\a.txt").Add(2, "Rename", @"D:\Docs\a.txt", @"D:\DOCS\B.txt").Add(3, "Read", @"d:\docs\b.txt");
        Assert.Equal(["create", "rename", "read"], Kinds(Ok(await Run(win, @"d:\docs\b.txt"))));

        var linux = new Mem().Add(1, "Create", "/s/a").Add(2, "Rename", "/s/a", "/s/B").Add(3, "Read", "/s/b");
        // /s/b is another file than /s/B
        Assert.Equal(["gap", "read"], Kinds(Ok(await Run(linux, "/s/b"))));
    }

    [Fact]
    public async Task A_case_only_rename_does_not_loop()
    {
        var m = new Mem().Add(1, "Create", @"D:\a.txt").Add(2, "Rename", @"D:\a.txt", @"D:\A.txt").Add(3, "Read", @"D:\A.txt");
        var r = Ok(await Run(m, @"D:\A.txt"));
        Assert.Equal("exists", r.End);
        Assert.Equal(3, r.Steps.Count);
    }

    [Fact]
    public async Task Records_of_the_same_second_are_ordered_by_id()
    {
        var m = new Mem().Add(1, "Create", @"D:\a.txt", id: 1).Add(2, "Rename", @"D:\a.txt", @"D:\b.txt", id: 20)
            .Add(2, "Write", @"D:\a.txt", id: 10);
        var r = Ok(await Run(m, @"D:\a.txt"));
        Assert.Equal(["create", "write", "rename"], Kinds(r));
    }

    [Fact]
    public async Task No_records_is_none_and_unknown_start_outside_scope_is_refused()
    {
        var m = new Mem().Add(1, "Create", @"D:\pub\a.txt");
        Assert.Equal(HistoryStatus.None, (await Run(m, @"D:\pub\missing.txt")).Status);
        var outside = await Run(m, @"D:\pub\a.txt", scope: AccessScope.Parse([@"D:\other"]));
        Assert.Equal(HistoryStatus.Outside, outside.Status);
        Assert.Null(outside.Result);
    }

    // ---- scope

    private static readonly IReadOnlyList<ScopeEntry> Pub = AccessScope.Parse([@"D:\pub"]);

    [Fact]
    public async Task A_file_moved_out_of_scope_shows_a_move_without_destination_and_one_gap()
    {
        var m = new Mem().Add(1, "Create", @"D:\pub\f.txt").Add(2, "Rename", @"D:\pub\f.txt", @"D:\priv\f.txt", user: "mover")
            .Add(3, "Write", @"D:\priv\f.txt", user: "secret").Add(4, "Rename", @"D:\priv\f.txt", @"D:\priv2\f.txt")
            .Add(5, "Rename", @"D:\priv2\f.txt", @"D:\pub\g.txt").Add(6, "Read", @"D:\pub\g.txt");
        var r = Ok(await Run(m, @"D:\pub\g.txt", scope: Pub));
        Assert.Equal(["create", "move", "gap", "read"], Kinds(r));
        Assert.Null(r.Steps[1].NewPath);
        Assert.Equal("outOfScope", r.Steps[2].Gap!.Reason);
        Assert.Null(r.Steps[2].User);
        Assert.Null(r.Steps[2].Path);
        Assert.Equal([@"D:\pub\f.txt", @"D:\pub\g.txt"], r.Paths.Select(p => p.Path));
        Assert.DoesNotContain(r.Steps, s => s.User == "secret");
        // unscoped sees all of it
        Assert.Equal(6, Ok(await Run(m, @"D:\pub\g.txt")).Steps.Count);
    }

    [Fact]
    public async Task A_file_that_came_from_outside_the_scope_starts_with_a_gap()
    {
        var m = new Mem().Add(1, "Create", @"D:\priv\h.txt").Add(2, "Rename", @"D:\priv\h.txt", @"D:\pub\h.txt").Add(3, "Read", @"D:\pub\h.txt");
        var r = Ok(await Run(m, @"D:\pub\h.txt", scope: Pub));
        Assert.Equal("outOfScope", r.Origin);
        Assert.Equal(["gap", "read"], Kinds(r));
    }

    [Fact]
    public async Task A_file_that_left_the_scope_for_good_ends_out_of_scope()
    {
        var m = new Mem().Add(1, "Create", @"D:\pub\f.txt").Add(2, "Rename", @"D:\pub\f.txt", @"D:\priv\f.txt");
        var r = Ok(await Run(m, @"D:\pub\f.txt", scope: Pub));
        Assert.Equal("outOfScope", r.End);
        Assert.Equal(["create", "move", "gap"], Kinds(r));
    }

    [Fact]
    public async Task The_parent_folder_is_shown_only_when_visible()
    {
        var m = new Mem().Add(1, "Create", @"D:\pub\a\f.txt").Add(2, "Rename", @"D:\pub\a", @"D:\pub\b", folder: true);
        Assert.Equal(@"D:\pub\a", Ok(await Run(m, @"D:\pub\a\f.txt", scope: Pub)).Steps[1].ViaFolder);

        // the folder was renamed from outside the scope into it: the file's earlier path is not visible
        var n = new Mem().Add(1, "Create", @"D:\priv\a\f.txt").Add(2, "Rename", @"D:\priv\a", @"D:\pub\b", folder: true).Add(3, "Read", @"D:\pub\b\f.txt");
        var r = Ok(await Run(n, @"D:\pub\b\f.txt", scope: Pub));
        Assert.Equal(["gap", "read"], Kinds(r));
    }

    [Fact]
    public async Task A_scope_entry_of_another_server_does_not_apply()
    {
        var m = new Mem().Add(1, "Create", @"D:\pub\f.txt");
        var scope = AccessScope.Parse([@"OTHER|D:\pub"]);
        Assert.Equal(HistoryStatus.Outside, (await Run(m, @"D:\pub\f.txt", scope: scope)).Status);
    }

    // ---- limits

    [Fact]
    public async Task The_hop_limit_stops_a_long_chain()
    {
        var m = new Mem().Add(0, "Create", "/s/p0");
        for (var i = 0; i < 70; i++) m.Add(i + 1, "Rename", $"/s/p{i}", $"/s/p{i + 1}");
        var forward = Ok(await Run(m, "/s/p0", T0));
        Assert.Equal("hopLimit", forward.End);
        Assert.True(forward.Truncated.Hops);
        Assert.Equal(FileHistory.MaxHops, forward.Paths.Count);

        var backward = Ok(await Run(m, "/s/p70"));
        Assert.True(backward.Truncated.Hops);
        Assert.Equal("renamedIn", backward.Origin);
        Assert.True(backward.Paths.Count <= FileHistory.MaxHops);
    }

    [Fact]
    public async Task The_days_limit_stops_the_walk_back_in_time()
    {
        // renamed 100 days ago, written yesterday
        var m = new Mem().Add(-100 * 1440 + 1, "Create", @"D:\a.txt").Add(-100 * 1440 + 2, "Rename", @"D:\a.txt", @"D:\b.txt")
            .Add(2 * 1440 - 100, "Write", @"D:\b.txt");
        var r = Ok(await Run(m, @"D:\b.txt", days: 30));
        Assert.True(r.Truncated.Window);
        Assert.Equal("renamedIn", r.Origin);
        Assert.Equal(["write"], Kinds(r));
        Assert.Equal("created", Ok(await Run(m, @"D:\b.txt")).Origin);
    }

    [Fact]
    public async Task Reads_of_one_user_are_collapsed_and_the_event_cap_keeps_the_newest()
    {
        var m = new Mem().Add(0, "Create", @"D:\a.txt", user: "alice");
        for (var i = 1; i <= 1000; i++) m.Add(i, "Read", @"D:\a.txt", user: i % 500 == 0 ? "bob" : "alice");
        var collapsed = Ok(await Run(m, @"D:\a.txt"));
        // alice's reads, then bob, ... : every 500th read is bob's, so 4 groups of reads
        Assert.Equal(1 + 4, collapsed.Steps.Count);
        var first = collapsed.Steps[1];
        Assert.Equal(499, first.Count);
        Assert.Equal(T0.AddMinutes(1), first.FirstTime);
        Assert.Equal(T0.AddMinutes(499), first.LastTime);

        var capped = Ok(await Run(m, @"D:\a.txt", collapse: false, maxEvents: 100));
        Assert.Equal(100, capped.Steps.Count);
        Assert.True(capped.Truncated.Events);
        Assert.Equal("create", capped.Steps[0].Kind);   // the origin stays
        Assert.Equal(T0.AddMinutes(1000), capped.Steps[^1].Time);
    }

    [Fact]
    public async Task Reads_more_than_ten_minutes_apart_or_with_another_step_between_are_not_merged()
    {
        var m = new Mem().Add(1, "Read", @"D:\a.txt").Add(5, "Read", @"D:\a.txt").Add(30, "Read", @"D:\a.txt")
            .Add(31, "Write", @"D:\a.txt").Add(32, "Read", @"D:\a.txt");
        var r = Ok(await Run(m, @"D:\a.txt"));
        Assert.Equal(["gap", "read", "read", "write", "read"], Kinds(r));
        Assert.Equal(2, r.Steps[1].Count);
    }

    [Fact]
    public async Task A_typical_history_needs_few_lookups()
    {
        var m = new Mem().Add(1, "Create", @"D:\a\f.txt").Add(2, "Rename", @"D:\a\f.txt", @"D:\b\f.txt")
            .Add(3, "Rename", @"D:\b\f.txt", @"D:\c\f.txt").Add(4, "Read", @"D:\c\f.txt");
        await Run(m, @"D:\c\f.txt");
        // anchor + per segment (boundary, rename-in, ends, records) over 3 segments
        Assert.InRange(m.Lookups, 1, 1 + 3 * 4);
    }

    // ---- helpers

    [Theory]
    [InlineData(@"D:\a\b\c.txt", new[] { @"D:\a\b", @"D:\a" })]
    [InlineData(@"D:\c.txt", new string[0])]
    [InlineData(@"\\srv\share\a\b.txt", new[] { @"\\srv\share\a" })]
    [InlineData("/srv/share/a/b", new[] { "/srv/share/a", "/srv/share", "/srv" })]
    [InlineData("/a", new string[0])]
    public void Ancestors_exclude_the_drive_or_share_root(string path, string[] expected) =>
        Assert.Equal(expected, FileHistory.Ancestors(path));

    [Fact]
    public void Ancestors_are_limited_in_depth()
    {
        var deep = "/" + string.Join("/", Enumerable.Repeat("d", 100)) + "/f";
        Assert.Equal(FileHistory.MaxDepth, FileHistory.Ancestors(deep).Count);
    }

    // A copy: the permissions are set (4670) a moment before the first write, which becomes the Create
    private static Mem Copy(double permissionMinutes, double createMinutes) => new Mem()
        .Add(permissionMinutes, "Permission", @"C:\s\a.txt")
        .Add(createMinutes, "Create", @"C:\s\a.txt")
        .Add(createMinutes + 0.1, "Write", @"C:\s\a.txt")
        .Add(createMinutes + 1, "Read", @"C:\s\a.txt");

    [Fact]
    public async Task Permission_record_of_a_copied_file_starts_at_the_create_after_it()
    {
        var r = Ok(await Run(Copy(0, 0.05), @"C:\s\a.txt", T0));
        Assert.Equal("created", r.Origin);
        Assert.DoesNotContain(r.Steps, s => s.Gap?.Reason == "unknownOrigin");
        Assert.Equal(["create", "permission", "write", "read"], Kinds(r));
    }

    [Fact]
    public async Task History_from_the_create_record_of_a_copied_file_is_unchanged()
    {
        var r = Ok(await Run(Copy(0, 0.05), @"C:\s\a.txt", T0.AddSeconds(3)));
        Assert.Equal("created", r.Origin);
        Assert.Equal(["create", "write", "read"], Kinds(r));
    }

    [Fact]
    public async Task Permission_without_a_create_within_a_minute_stays_unknown()
    {
        var r = Ok(await Run(new Mem().Add(0, "Permission", @"C:\s\a.txt"), @"C:\s\a.txt", T0));
        Assert.Equal("unknown", r.Origin);
        Assert.Contains(r.Steps, s => s.Gap?.Reason == "unknownOrigin");
    }

    [Fact]
    public async Task A_create_two_minutes_after_the_permission_is_not_used()
    {
        var r = Ok(await Run(Copy(0, 2), @"C:\s\a.txt", T0));
        Assert.Equal("unknown", r.Origin);
    }
}
