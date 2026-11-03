namespace FileAccessMonitor.Models;

// AccessRecord.AccessType values, and the event types a monitored folder records (the checkboxes
// on the Settings tab). Create is recorded with Write, Rename with Delete.
public static class AccessTypes
{
    public const string Read = "Read", Write = "Write", Create = "Create", Delete = "Delete", Rename = "Rename",
        Permission = "Permission";

    public const string EventRead = "Read", EventWrite = "Write", EventDelete = "Delete", EventPermission = "Permission";

    public static string EventTypeOf(string accessType) => accessType switch
    {
        Create => EventWrite,
        Rename => EventDelete,
        _ => accessType,
    };
}
