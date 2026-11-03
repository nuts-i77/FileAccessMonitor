using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using Microsoft.EntityFrameworkCore;

namespace FileAccessMonitor.Services;

// Monitored folders and recording rules per file server. This machine keeps its own in
// settings.json; an agent's are kept in the Agents table and fetched by the agent.
public class ServerConfigService(AccessDbContext db)
{
    public static readonly string LocalName = Environment.MachineName;

    // null or empty: this machine
    public static bool IsLocal(string? server) =>
        string.IsNullOrWhiteSpace(server) || server.Equals(LocalName, StringComparison.OrdinalIgnoreCase);

    public async Task<Agent?> FindAgentAsync(string server)
    {
        var upper = server.ToUpperInvariant();
        return await db.Agents.FirstOrDefaultAsync(a => a.Name.ToUpper() == upper);
    }

    // This machine first, then the agents
    public async Task<List<string>> ServerNamesAsync() =>
        [LocalName, .. await db.Agents.OrderBy(a => a.Name).Select(a => a.Name).ToListAsync()];

    public async Task<JsonObject> LoadAsync(string? server)
    {
        if (IsLocal(server)) return SettingsStore.Load();
        var agent = await FindAgentAsync(server!) ?? throw new KeyNotFoundException(server);
        return string.IsNullOrEmpty(agent.Config) ? [] : JsonNode.Parse(agent.Config)?.AsObject() ?? [];
    }

    public async Task<PathConfig[]> GetPathsAsync(string? server) =>
        SettingsController.ParseSettings(await LoadAsync(server)).configs;

    public async Task<RecordingSettings> GetRecordingAsync(string? server) =>
        RecordingSettings.FromNode((await LoadAsync(server))[RecordingSettings.SettingsKey]);

    public Task SavePathsAsync(string? server, PathConfig[] configs) =>
        UpdateAsync(server, root => root["MonitoredPaths"] = SettingsController.PathConfigsToJson(configs));

    public Task SaveRecordingAsync(string? server, RecordingSettings settings) =>
        UpdateAsync(server, root => root[RecordingSettings.SettingsKey] = JsonSerializer.SerializeToNode(settings));

    private async Task UpdateAsync(string? server, Action<JsonObject> change)
    {
        if (IsLocal(server))
        {
            SettingsStore.Update(change);
            return;
        }
        var agent = await FindAgentAsync(server!) ?? throw new KeyNotFoundException(server);
        var root = string.IsNullOrEmpty(agent.Config) ? new JsonObject() : JsonNode.Parse(agent.Config)!.AsObject();
        change(root);
        agent.Config = root.ToJsonString();
        agent.ConfigVersion++;
        await db.SaveChangesAsync();
    }
}

// Jobs (AgentJob) handed over when an agent asks for work. Kept in memory: a job waits only as
// long as the GUI request that started it.
public class AgentJobs
{
    private readonly ConcurrentDictionary<string, Channel<AgentJob>> _queues = new();
    private readonly ConcurrentDictionary<string, (string AgentId, TaskCompletionSource<JsonObject> Result)> _running = new();

    private Channel<AgentJob> Queue(string agentId) =>
        _queues.GetOrAdd(agentId, _ => Channel.CreateUnbounded<AgentJob>());

    // Throws TimeoutException when the agent does not answer in time (offline or busy)
    public async Task<JsonObject> RunAsync(string agentId, string type, JsonObject args, TimeSpan timeout,
        CancellationToken ct)
    {
        var job = new AgentJob(Guid.NewGuid().ToString("N"), type, args);
        var result = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _running[job.Id] = (agentId, result);
        try
        {
            await Queue(agentId).Writer.WriteAsync(job, ct);
            return await result.Task.WaitAsync(timeout, ct);
        }
        finally
        {
            _running.TryRemove(job.Id, out _);
        }
    }

    // Long poll: the next job for the agent, or null when none came within the wait
    public async Task<AgentJob?> NextAsync(string agentId, TimeSpan wait, CancellationToken ct)
    {
        var reader = Queue(agentId).Reader;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(wait);
        try
        {
            while (true)
            {
                var job = await reader.ReadAsync(timeout.Token);
                if (_running.ContainsKey(job.Id)) return job; // skip jobs whose GUI request gave up
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    // Only the agent the job was given to can answer it
    public bool Complete(string agentId, string jobId, JsonObject result) =>
        _running.TryGetValue(jobId, out var r) && r.AgentId == agentId && r.Result.TrySetResult(result);
}
