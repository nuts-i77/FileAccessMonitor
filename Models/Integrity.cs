using System.ComponentModel.DataAnnotations;

namespace FileAccessMonitor.Models;

// Tamper detection: the newest link of a chain ("access" = AccessRecords, "audit" = AuditLogs)
public class ChainHead
{
    [Key, MaxLength(20)]
    public string Chain { get; set; } = "";

    public long Seq { get; set; }
    public byte[] Hash { get; set; } = [];
    public DateTime UpdatedAt { get; set; }

    // Rows made before tamper detection started (not chained)
    public long LegacyMaxId { get; set; }
    public long LegacyCount { get; set; }
    public DateTime StartedAt { get; set; }

    // How far verification has got
    public long VerifiedSeq { get; set; }
    public byte[]? VerifiedHash { get; set; }
    public DateTime? VerifiedAt { get; set; }
}

// Where a chain restarts from: its start, rows deleted by retention, or a break accepted by an admin
public class ChainCheckpoint
{
    [Key]
    public long Id { get; set; }

    [MaxLength(20)]
    public string Chain { get; set; } = "";

    public long UpToSeq { get; set; }
    public byte[] Hash { get; set; } = [];
    public long DeletedRows { get; set; }
    public DateTime CreatedAt { get; set; }

    [MaxLength(40)]
    public string Reason { get; set; } = "";   // genesis | retention | accepted

    [MaxLength(1000)]
    public string? Note { get; set; }

    [MaxLength(16)]
    public string KeyId { get; set; } = "";

    // HMAC over this checkpoint and the previous one's Mac
    public byte[] Mac { get; set; } = [];
}

// One finding of a verification (kept in the integrity state until an admin accepts it); not a table
public class IntegrityBreak
{
    // chain|kind|first seq (first Id for unchained rows): the same finding keeps the same id
    public string Id { get; set; } = "";
    public string Chain { get; set; } = "";

    // altered | missing | truncatedTail | headMismatch | headRollback | unchained | checkpoint | keyChanged | duplicate
    public string Kind { get; set; } = "";

    public long FromSeq { get; set; }
    public long ToSeq { get; set; }
    public long? FromId { get; set; }
    public long? ToId { get; set; }
    public long Count { get; set; }

    // Time of the last intact record before the finding and of the first one after it
    public DateTime? TimeBefore { get; set; }
    public DateTime? TimeAfter { get; set; }

    public DateTime DetectedAt { get; set; }
    public bool Accepted { get; set; }
    public string? AcceptedBy { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public string? Note { get; set; }
}
