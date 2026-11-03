using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FileAccessMonitor.Models;

public class AccessRecord
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required, MaxLength(2000)]
    public string FilePath { get; set; } = "";

    [Required, MaxLength(500)]
    public string FileName { get; set; } = "";

    [Required, MaxLength(2000)]
    public string FolderPath { get; set; } = "";

    [Required, MaxLength(200)]
    public string UserName { get; set; } = "";

    [Required, MaxLength(20)]
    public string AccessType { get; set; } = ""; // Read, Write, Delete, Rename

    // Folders are recorded only when deleted or renamed
    public bool IsFolder { get; set; }

    // File server the access happened on
    [Required, MaxLength(255)]
    public string ServerName { get; set; } = "";

    public DateTime AccessTime { get; set; }

    [MaxLength(100)]
    public string? ClientIp { get; set; }

    [MaxLength(200)]
    public string? ClientMachine { get; set; }

    // The access was refused (not a successful access); AccessType is what was refused
    public bool Denied { get; set; }

    // Rename: where the file went (null = unknown)
    [MaxLength(2000)]
    public string? NewPath { get; set; }

    // Permission: the change, before and after; null otherwise
    [MaxLength(2000)]
    public string? Detail { get; set; }
}
