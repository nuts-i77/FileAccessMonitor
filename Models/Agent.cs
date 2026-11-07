using System.ComponentModel.DataAnnotations;

namespace FileAccessMonitor.Models;

// A file server that sends its records to this monitoring server.
public class Agent
{
    [Key, MaxLength(64)]
    public string Id { get; set; } = "";

    // The file server's name; stamped on its records as ServerName
    [Required, MaxLength(255)]
    public string Name { get; set; } = "";

    // SHA-256 of the agent's key (the key itself is only known to the agent)
    [Required, MaxLength(64)]
    public string KeyHash { get; set; } = "";

    public DateTime CreatedAt { get; set; }
    public DateTime? LastSeenAt { get; set; }

    [MaxLength(50)]
    public string? Version { get; set; }

    // Sequence number of the last batch saved, so a batch sent twice is saved once
    public long LastBatchSeq { get; set; }

    public bool Disabled { get; set; }

    // Monitored folders and recording rules for this server, as kept in settings.json
    // ({"MonitoredPaths": [...], "Recording": {...}}); the agent fetches them when ConfigVersion changes
    public string? Config { get; set; }
    public int ConfigVersion { get; set; }

    // Reported by the agent: batches waiting to be sent, and whether File System auditing is on
    public int OutboxCount { get; set; }
    public bool? AuditPolicyOk { get; set; }

    // Reported by the agent (from 1.11): its outbox is full and collection is paused there; the outbox size in bytes
    public bool OutboxFull { get; set; }
    public long OutboxBytes { get; set; }

    // Reported by the agent: "Windows Server 2022 Standard", "Ubuntu 24.04 LTS" (null before 1.7)
    [MaxLength(100)]
    public string? Os { get; set; }
}

// A one-time registration code issued by an Admin (stored hashed)
public class AgentEnrollment
{
    [Key, MaxLength(64)]
    public string CodeHash { get; set; } = "";

    public DateTime ExpiresAt { get; set; }
}
