using FileAccessMonitor.Data;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// Notices when an agent stops contacting this server (stopped service, shut-down machine, network)
// and when it is back, so a file server that stopped being recorded does not go unnoticed. The collector
// service of this server counts as an agent here: when it is stopped, this machine is not recorded.
public class AgentMonitorService(IServiceScopeFactory scopeFactory, AlertService alerts, AuditLog audit,
    LocalCollectorState collector, ILogger<AgentMonitorService> logger) : BackgroundService
{
    private readonly AgentStatusTracker _tracker = new();
    private readonly AgentOutboxTracker _outboxTracker = new();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var startedUtc = DateTime.UtcNow;
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AccessDbContext>();
                var agents = await db.Agents.AsNoTracking()
                    .Select(a => new AgentStatus(a.Name, a.LastSeenAt ?? a.CreatedAt, a.Disabled))
                    .ToListAsync(stoppingToken);
                // Never heard from since this service started: counted from the start
                if (ServerConfigService.LocalCollects)
                    agents.Add(new AgentStatus(ServerConfigService.LocalName, collector.LastSeenUtc ?? startedUtc, false));

                foreach (var (agent, offline) in _tracker.Check(agents, alerts.Settings.AgentOfflineMinutes, startedUtc, DateTime.UtcNow))
                {
                    logger.LogWarning(offline ? "Agent {Name} has not been in touch since {LastSeen:u}." : "Agent {Name} is in touch again.",
                        agent.Name, agent.LastSeenUtc);
                    await audit.WriteAsync(AuditLog.SystemUser, offline ? "agent.offline" : "agent.online",
                        $"name={agent.Name}, lastSeen={agent.LastSeenUtc:O}");
                    await alerts.NotifyAgentStatusAsync(agent.Name, offline, agent.LastSeenUtc);
                }

                // Agents whose send queue is full (collection is paused there): notified once, logged when it clears
                var outboxes = await db.Agents.AsNoTracking().Where(a => !a.Disabled)
                    .Select(a => new AgentOutboxState(a.Name, a.OutboxFull, a.OutboxBytes))
                    .ToListAsync(stoppingToken);
                foreach (var (agent, full) in _outboxTracker.Check(outboxes))
                {
                    logger.LogWarning(full
                        ? "The send queue of agent {Name} is full ({Bytes:N0} bytes); its collection is paused until the queue has been sent."
                        : "The send queue of agent {Name} has room again.", agent.Name, agent.Bytes);
                    await audit.WriteAsync(AuditLog.SystemUser, full ? "agent.outboxFull" : "agent.outboxRoom", $"name={agent.Name}, bytes={agent.Bytes}");
                    if (full) await alerts.NotifyAgentOutboxFullAsync(agent.Name);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Checking the agents failed.");
            }
        }
    }
}

public record AgentStatus(string Name, DateTime LastSeenUtc, bool Disabled);

public record AgentOutboxState(string Name, bool Full, long Bytes);

// Decides which agents just reported a full send queue, or room again. Kept apart from the service for testing.
public class AgentOutboxTracker
{
    private readonly HashSet<string> _full = new(StringComparer.OrdinalIgnoreCase);

    public List<(AgentOutboxState Agent, bool Full)> Check(IEnumerable<AgentOutboxState> agents)
    {
        var changes = new List<(AgentOutboxState, bool)>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var agent in agents)
        {
            names.Add(agent.Name);
            if (agent.Full && _full.Add(agent.Name)) changes.Add((agent, true));
            else if (!agent.Full && _full.Remove(agent.Name)) changes.Add((agent, false));
        }
        _full.RemoveWhere(n => !names.Contains(n)); // removed or disabled: forgotten, reported again if it comes back full
        return changes;
    }
}

// Decides which agents just went offline or came back. Kept apart from the service for testing.
public class AgentStatusTracker
{
    private readonly HashSet<string> _offline = new(StringComparer.OrdinalIgnoreCase);

    public List<(AgentStatus Agent, bool Offline)> Check(IEnumerable<AgentStatus> agents, int offlineMinutes,
        DateTime startedUtc, DateTime nowUtc)
    {
        var changes = new List<(AgentStatus, bool)>();
        if (offlineMinutes <= 0)
        {
            _offline.Clear();
            return changes;
        }
        var limit = TimeSpan.FromMinutes(offlineMinutes);
        // Agents cannot reach a stopped monitoring server: give them the same time after it starts
        var judging = nowUtc - startedUtc >= limit;

        foreach (var agent in agents)
        {
            if (agent.Disabled)
            {
                _offline.Remove(agent.Name); // disabled on purpose: neither offline nor back
                continue;
            }
            var silent = nowUtc - agent.LastSeenUtc >= limit;
            if (silent && judging && _offline.Add(agent.Name))
                changes.Add((agent, true));
            else if (!silent && _offline.Remove(agent.Name))
                changes.Add((agent, false));
        }
        return changes;
    }
}
