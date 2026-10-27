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
    public string AccessType { get; set; } = ""; // Read, Write, Delete

    public DateTime AccessTime { get; set; }

    [MaxLength(100)]
    public string? ClientIp { get; set; }

    [MaxLength(200)]
    public string? ClientMachine { get; set; }
}
