using System.ComponentModel.DataAnnotations;

namespace FileAccessMonitor.Models;

// Folders a Viewer may see. A Viewer without a row (or with no paths) sees everything,
// as before scopes existed; Admins always see everything.
public class UserScope
{
    [Key, MaxLength(450)]
    public string UserId { get; set; } = "";

    // Folder paths, one per line
    public string Paths { get; set; } = "";

    // Alerts about files in the scope are also mailed here (null = none)
    [MaxLength(256)]
    public string? NotifyEmail { get; set; }

    // The scheduled report, limited to the scope, is mailed to NotifyEmail too
    public bool SendReport { get; set; } = true;
}
