using System.Globalization;
using System.Text.Json;

namespace FileAccessMonitor.Services;

// Stored under "Reports" in settings.json. SMTP, proxy, recipients and language come from AlertSettings.
// Off by default. Times are the server's local time.
public class ReportSettings
{
    public const string SettingsKey = "Reports";
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    public bool Enabled { get; set; }
    public string Frequency { get; set; } = "weekly";   // daily | weekly | monthly
    public int DayOfWeek { get; set; } = 1;             // 0 = Sunday .. 6 (weekly)
    public int DayOfMonth { get; set; } = 1;            // 1..28 (monthly): every month has these days
    public string Time { get; set; } = "09:00";         // HH:mm
    public bool Csv { get; set; } = true;               // CSV attachments
    public bool ScopedViewers { get; set; } = true;     // also mail the scoped report to viewers with a notification address
    public bool Webhook { get; set; }                   // a summary (no file names) to the webhook
    public int TopN { get; set; } = 10;

    public static ReportSettings Load() => Load(SettingsStore.Load());

    internal static ReportSettings Load(System.Text.Json.Nodes.JsonObject root) =>
        root[SettingsKey]?.Deserialize<ReportSettings>(JsonOptions) ?? new ReportSettings();

    public void Save() => SettingsStore.Update(root => root[SettingsKey] = JsonSerializer.SerializeToNode(this, JsonOptions));

    public ReportSettings Clone() => (ReportSettings)MemberwiseClone();

    public TimeSpan TimeOfDay => TryParseTime(Time, out var t) ? t : TimeSpan.FromHours(9);

    public static bool TryParseTime(string? text, out TimeSpan time) =>
        TimeSpan.TryParseExact(text, @"hh\:mm", CultureInfo.InvariantCulture, out time) && time < TimeSpan.FromDays(1);

    // A message key for what is wrong, or null
    public string? Validate()
    {
        if (Frequency is not ("daily" or "weekly" or "monthly")) return "report.invalidFrequency";
        if (DayOfWeek is < 0 or > 6 || DayOfMonth is < 1 or > 28) return "report.invalidDay";
        if (!TryParseTime(Time, out _)) return "report.invalidTime";
        if (TopN is < 1 or > 50) return "report.invalidTopN";
        return null;
    }

    // The schedule fields: a change moves the first slot into the future
    public bool SameSchedule(ReportSettings other) =>
        Frequency == other.Frequency && DayOfWeek == other.DayOfWeek && DayOfMonth == other.DayOfMonth && Time == other.Time;
}

// When the report is due. Pure functions of the settings, the clock and the time zone.
// Slots are local times (Kind Unspecified). A local time that does not exist (spring forward) is moved
// forward by the gap; one that happens twice (fall back) counts at its first occurrence.
public static class ReportSchedule
{
    public static DateTime LatestSlotAtOrBefore(ReportSettings s, DateTime nowUtc, TimeZoneInfo tz)
    {
        var today = TimeZoneInfo.ConvertTimeFromUtc(nowUtc, tz).Date;
        var date = DateOnOrBefore(s, today);
        for (var i = 0; i < 4; i++)
        {
            var slot = SlotOn(s, date, tz);
            if (ToUtc(slot, tz) <= nowUtc) return slot;
            date = DateOnOrBefore(s, date.AddDays(-1));
        }
        return SlotOn(s, date, tz);
    }

    // The first slot after the latest one
    public static DateTime NextSlot(ReportSettings s, DateTime nowUtc, TimeZoneInfo tz)
    {
        var date = DateOnOrBefore(s, LatestSlotAtOrBefore(s, nowUtc, tz).Date);
        for (var i = 0; i < 6; i++)
        {
            date = s.Frequency switch
            {
                "daily" => date.AddDays(1),
                "monthly" => new DateTime(date.Year, date.Month, 1).AddMonths(1).AddDays(s.DayOfMonth - 1),
                _ => date.AddDays(7),
            };
            var slot = SlotOn(s, date, tz);
            if (ToUtc(slot, tz) > nowUtc) return slot;
        }
        return SlotOn(s, date, tz);
    }

    // The period of the report that ends at the slot: 24 hours, 7 days, or one month (local times)
    public static (DateTime FromLocal, DateTime ToLocal) Period(ReportSettings s, DateTime slot) => s.Frequency switch
    {
        "daily" => (slot.AddDays(-1), slot),
        "monthly" => (slot.AddMonths(-1), slot),
        _ => (slot.AddDays(-7), slot),
    };

    // The same length before it (for the comparison with the previous period)
    public static DateTime PreviousFrom(ReportSettings s, DateTime from) => s.Frequency switch
    {
        "daily" => from.AddDays(-1),
        "monthly" => from.AddMonths(-1),
        _ => from.AddDays(-7),
    };

    // A service that was down at the slot still sends when it is back within this time; later it skips
    public static TimeSpan CatchUpWindow(string frequency) => frequency switch
    {
        "daily" => TimeSpan.FromHours(6),
        "monthly" => TimeSpan.FromHours(48),
        _ => TimeSpan.FromHours(24),
    };

    public static DateTime ToUtc(DateTime local, TimeZoneInfo tz)
    {
        local = DateTime.SpecifyKind(local, DateTimeKind.Unspecified);
        if (tz.IsInvalidTime(local)) return TimeZoneInfo.ConvertTimeToUtc(Resolve(local, tz), tz);
        if (tz.IsAmbiguousTime(local))
            return DateTime.SpecifyKind(local - tz.GetAmbiguousTimeOffsets(local).Max(), DateTimeKind.Utc);   // first occurrence
        return TimeZoneInfo.ConvertTimeToUtc(local, tz);
    }

    private static DateTime SlotOn(ReportSettings s, DateTime date, TimeZoneInfo tz) =>
        Resolve(DateTime.SpecifyKind(date.Date + s.TimeOfDay, DateTimeKind.Unspecified), tz);

    // A time inside the gap of a DST change moves forward by the gap
    private static DateTime Resolve(DateTime local, TimeZoneInfo tz)
    {
        if (!tz.IsInvalidTime(local)) return local;
        var before = tz.GetUtcOffset(local.AddHours(-3));
        var utc = DateTime.SpecifyKind(local - before, DateTimeKind.Utc);
        return DateTime.SpecifyKind(TimeZoneInfo.ConvertTimeFromUtc(utc, tz), DateTimeKind.Unspecified);
    }

    // The newest day on or before `date` that has a slot
    private static DateTime DateOnOrBefore(ReportSettings s, DateTime date) => s.Frequency switch
    {
        "daily" => date,
        "monthly" => date.Day >= s.DayOfMonth
            ? new DateTime(date.Year, date.Month, s.DayOfMonth)
            : new DateTime(date.Year, date.Month, 1).AddMonths(-1).AddDays(s.DayOfMonth - 1),
        _ => date.AddDays(-(((int)date.DayOfWeek - s.DayOfWeek + 7) % 7)),
    };
}
