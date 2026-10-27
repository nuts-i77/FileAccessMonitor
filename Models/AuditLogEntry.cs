using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FileAccessMonitor.Models;

// Operations performed through the web GUI / API, plus notable system events
// (alerts sent, events lost while the service was stopped).
public class AuditLogEntry
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    public DateTime Time { get; set; }

    [Required, MaxLength(200)]
    public string UserName { get; set; } = "";

    [Required, MaxLength(100)]
    public string Action { get; set; } = "";

    [MaxLength(4000)]
    public string? Detail { get; set; }

    [MaxLength(100)]
    public string? ClientIp { get; set; }
}
