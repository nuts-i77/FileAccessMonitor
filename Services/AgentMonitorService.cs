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
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogWarning(ex, "Checking the agents failed.");
            }
        }
    }
}

public record AgentStatus(string Name, DateTime LastSeenUtc, bool Disabled);

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
