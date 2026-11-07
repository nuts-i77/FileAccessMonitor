using System.ComponentModel.DataAnnotations;

namespace FileAccessMonitor.Models;

// What a Viewer may see: the folders in Paths, or everything when AllFolders is set (an explicit choice).
// A Viewer without a row, or with no paths and no AllFolders, sees nothing. Admins always see everything.
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

    // The Viewer sees every folder (Paths is then empty)
    public bool AllFolders { get; set; }
}
