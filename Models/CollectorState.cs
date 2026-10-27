using System.ComponentModel.DataAnnotations;

namespace FileAccessMonitor.Models;

// Key/value state of the event collector, e.g. the last processed Security log record id.
public class CollectorState
{
    [Key, MaxLength(100)]
    public string Key { get; set; } = "";

    [Required]
    public string Value { get; set; } = "";
}
