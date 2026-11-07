using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Data;
using FileAccessMonitor.Models;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace FileAccessMonitor.Tests;

// The local collector (the privileged process of this server) as the web part sees it: the pseudo-agent
// "local" that proves itself with the secret whose hash is in collector\key.hash
[Collection("LocalCollects")]
public class LocalCollectorTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "fam-collector-" + Guid.NewGuid().ToString("N"));
    private readonly SqliteConnection _conn = new("Data Source=:memory:");
    private readonly ServiceProvider _services;
    private readonly LocalCollectorState _state = new();
    private readonly AgentJobs _jobs = new();
    private readonly JsonObject _settings = new()
    {
        ["MonitoredPaths"] = new JsonArray(new JsonObject { ["path"] = @"D:\Share", ["eventTypes"] = new JsonArray("Read") }),
        ["DnsServer"] = "10.0.0.1",
    };

    public LocalCollectorTests()
    {
        _conn.Open();
        _services = new ServiceCollection()
            .AddLogging()
            .AddDataProtection().Services
            .AddHttpClient().AddDbContext<AccessDbContext>(o => o.UseSqlite(_conn))
            .AddSingleton<AuditLog>().AddSingleton<AlertService>()
            .BuildServiceProvider();
        using (var scope = _services.CreateScope()) scope.ServiceProvider.GetRequiredService<AccessDbContext>().Database.EnsureCreated();
        AgentApiController.LocalFolder = _folder;
        AgentApiController.LocalSettings = () => (JsonObject)_settings.DeepClone();
        LocalCollector.EnsureFolder(_folder);
    }

    public void Dispose()
    {
        AgentApiController.LocalFolder = null;
        AgentApiController.LocalSettings = SettingsStore.Load;
        _services.Dispose();
        _conn.Dispose();
        if (Directory.Exists(_folder)) Directory.Delete(_folder, recursive: true);
    }

    // A new controller, as for each request; its context belongs to a scope that lives as long as the test
    private AgentApiController Ctl(string? secret, IPAddress? remote = null, string id = "local")
    {
        var sp = _services.CreateScope().ServiceProvider;
        var db = sp.GetRequiredService<AccessDbContext>();
        var http = new DefaultHttpContext();
        http.Request.Scheme = "https";
        http.Connection.LocalPort = AgentEndpoint.DefaultPort;
        http.Connection.RemoteIpAddress = remote ?? IPAddress.Loopback;
        if (secret != null) http.Request.Headers.Authorization = $"Bearer {id}.{secret}";
        var controller = new AgentApiController(db, sp.GetRequiredService<AlertService>(), sp.GetRequiredService<AuditLog>(),
            new ConfigurationBuilder().Build(), NullLogger<AgentApiController>.Instance, _state)
        {
            ControllerContext = new ControllerContext { HttpContext = http },
        };
        return controller;
    }

    private AccessDbContext NewDb() => _services.CreateScope().ServiceProvider.GetRequiredService<AccessDbContext>();

    private static AgentBatch Batch(long seq, params string[] names) => new()
    {
        Seq = seq,
        Records = names.Select(n => new AgentRecord
        {
            FilePath = $@"D:\Share\{n}", FileName = n, FolderPath = @"D:\Share", UserName = @"CORP\sato", AccessType = "Read",
            AccessTime = new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc),
        }).ToList(),
    };

    private DnsResolverService Dns => new(NullLogger<DnsResolverService>.Instance);

    // ---- the secret and its hash

    [Fact]
    public void The_collector_makes_a_secret_once_and_publishes_its_hash()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        Assert.True(secret.Length >= 32);
        Assert.Equal(secret, LocalCollector.GetOrCreateSecret(_folder));
        Assert.Equal(AgentSecrets.Hash(secret), LocalCollector.ReadKeyHash(_folder));
        Assert.True(File.Exists(Path.Combine(_folder, LocalCollector.SecretFileName)));

        // The hash file is written again when it is lost; the secret stays
        File.Delete(Path.Combine(_folder, LocalCollector.KeyHashFileName));
        Assert.Null(LocalCollector.ReadKeyHash(_folder));
        Assert.Equal(secret, LocalCollector.GetOrCreateSecret(_folder));
        Assert.Equal(AgentSecrets.Hash(secret), LocalCollector.ReadKeyHash(_folder));
    }

    [Fact]
    public void Only_the_secret_matches_and_no_key_hash_means_no_collector()
    {
        Assert.False(LocalCollector.Matches("anything", _folder)); // never started
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        Assert.True(LocalCollector.Matches(secret, _folder));
        Assert.False(LocalCollector.Matches(secret + "x", _folder));
        Assert.False(LocalCollector.Matches("", _folder));
        File.WriteAllText(Path.Combine(_folder, LocalCollector.KeyHashFileName), "not a hash");
        Assert.False(LocalCollector.Matches(secret, _folder));
    }

    [Fact]
    public void The_secret_file_is_for_administrators_only_and_the_hash_file_can_be_read_by_the_web_account()
    {
        LocalCollector.GetOrCreateSecret(_folder);
        if (OperatingSystem.IsWindows())
        {
            var secretRules = new FileInfo(Path.Combine(_folder, LocalCollector.SecretFileName)).GetAccessControl()
                .GetAccessRules(true, false, typeof(System.Security.Principal.SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList();
            var self = System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value;
            Assert.All(secretRules, r => Assert.Contains(r.IdentityReference.Value, new[] { "S-1-5-18", "S-1-5-32-544", self })); // SYSTEM, Administrators, the account that wrote it
            Assert.True(new FileInfo(Path.Combine(_folder, LocalCollector.SecretFileName)).GetAccessControl().AreAccessRulesProtected);
        }
        else
        {
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(Path.Combine(_folder, LocalCollector.SecretFileName)));
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
                File.GetUnixFileMode(Path.Combine(_folder, LocalCollector.KeyHashFileName)));
        }
    }

    [Fact]
    public void Protected_files_name_the_accounts_that_may_open_them()
    {
        if (!OperatingSystem.IsWindows()) return;
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var admins = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);

        // Agent key and collector secret: no one else (but the account that writes them, which is SYSTEM in the service)
        var self = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var adminOnly = SecretStore.WindowsRules(SecretStore.Audience.Administrators);
        Assert.Equal(new[] { system, admins, self }.Distinct().ToArray(), adminOnly.Select(r => r.Sid).ToArray());
        Assert.All(adminOnly, r => Assert.Equal(FileSystemRights.FullControl, r.Rights));

        // The web part's secrets: also the web service account (when it exists) and the account that writes them
        var web = SecretStore.WindowsRules(SecretStore.Audience.WebService);
        Assert.Contains(system, web.Select(r => r.Sid));
        Assert.Contains(admins, web.Select(r => r.Sid));
        Assert.Contains(System.Security.Principal.WindowsIdentity.GetCurrent().User!, web.Select(r => r.Sid));
        Assert.All(web, r => Assert.Equal(FileSystemRights.FullControl, r.Rights));

        // key.hash: the web account may read, nothing more
        var hash = SecretStore.WindowsRules(SecretStore.Audience.AdministratorsWebRead);
        Assert.All(hash.Where(r => r.Sid != system && r.Sid != admins && r.Sid != self), r => Assert.Equal(FileSystemRights.Read, r.Rights));
    }

    // ---- authentication

    [Fact]
    public async Task The_collector_is_accepted_with_its_secret_only()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        var hb = new HeartbeatRequest("1.11.0", 0, true, "Windows Server 2022");

        Assert.IsType<OkObjectResult>(await Ctl(secret).Heartbeat(hb));
        Assert.IsType<UnauthorizedResult>(await Ctl(secret + "x").Heartbeat(hb));
        Assert.IsType<UnauthorizedResult>(await Ctl(null).Heartbeat(hb));
        Assert.IsType<UnauthorizedResult>(await Ctl(secret, id: "someone").Heartbeat(hb)); // not the reserved id: looked up as an agent, found none
        // From another machine the local credential is useless, even with the right secret
        Assert.IsType<UnauthorizedResult>(await Ctl(secret, IPAddress.Parse("192.168.0.20")).Heartbeat(hb));
    }

    [Fact]
    public async Task Without_key_hash_there_is_no_local_collector()
    {
        var c = Ctl("whatever");
        Assert.IsType<UnauthorizedResult>(await c.Heartbeat(new HeartbeatRequest("1.11.0")));
        Assert.False(_state.IsConnected(DateTime.UtcNow));
    }

    [Fact]
    public async Task A_heartbeat_keeps_the_collector_state_in_memory_and_no_agent_row()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        Assert.False(_state.IsConnected(DateTime.UtcNow));
        Assert.Null(_state.AuditPolicyOk);

        var c = Ctl(secret);
        var db = NewDb();
        var result = Assert.IsType<OkObjectResult>(await c.Heartbeat(new HeartbeatRequest("1.11.0", 3, false, "Windows Server 2022")));
        Assert.True(_state.IsConnected(DateTime.UtcNow));
        Assert.False(_state.IsConnected(DateTime.UtcNow.AddMinutes(10))); // a stopped collector is noticed
        Assert.Equal(("1.11.0", 3, false, "Windows Server 2022"), (_state.Version, _state.Outbox, _state.AuditPolicyOk, _state.Os));
        Assert.Empty(db.Agents);
        var json = System.Text.Json.JsonSerializer.Serialize(result.Value);
        Assert.Contains("\"protocol\":" + AgentProtocol.Version, json);
        Assert.Contains("\"configVersion\":" + LocalCollector.ConfigVersion(LocalCollector.ConfigFrom(_settings)), json);
    }

    // ---- batches

    [Fact]
    public async Task A_batch_from_the_collector_is_saved_under_the_name_of_this_server()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        {
        var c = Ctl(secret);
        var db = NewDb();
            Assert.IsType<OkObjectResult>(await c.Batch(Batch(1, "a.txt", "b.txt"), Dns));
            var saved = db.AccessRecords.AsNoTracking().OrderBy(r => r.FileName).ToList();
            Assert.Equal(["a.txt", "b.txt"], saved.Select(r => r.FileName).ToList());
            Assert.All(saved, r => Assert.Equal(ServerConfigService.LocalName, r.ServerName));
            Assert.Empty(db.Agents); // not an agent of the Agents tab
        }
        Assert.True(_state.IsConnected(DateTime.UtcNow));
    }

    [Fact]
    public async Task A_batch_that_was_saved_is_not_saved_twice_even_after_a_restart()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        Assert.IsType<OkObjectResult>(await Ctl(secret).Batch(Batch(1, "a.txt"), Dns));
        {
            var c = Ctl(secret); // a new controller: the sequence is in the database
            var db = NewDb();
            var again = Assert.IsType<OkObjectResult>(await c.Batch(Batch(1, "a.txt"), Dns));
            Assert.Contains("duplicate", System.Text.Json.JsonSerializer.Serialize(again.Value));
            Assert.Single(db.AccessRecords);
            Assert.IsType<OkObjectResult>(await c.Batch(Batch(2, "b.txt"), Dns));
            Assert.Equal(2, db.AccessRecords.Count());
        }

        // A collector that started over with a new secret numbers its batches from 1 again: they count
        File.Delete(Path.Combine(_folder, LocalCollector.SecretFileName));
        var fresh = LocalCollector.GetOrCreateSecret(_folder);
        {
        var c = Ctl(fresh);
        var db = NewDb();
            Assert.IsType<OkObjectResult>(await c.Batch(Batch(1, "c.txt"), Dns));
            Assert.Equal(3, db.AccessRecords.Count());
        }
    }

    [Fact]
    public async Task A_gap_report_of_the_collector_is_accepted()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        var c = Ctl(secret);
        var batch = new AgentBatch { Seq = 1, Gap = new AgentGap { AuditDetail = "reason=logCleared", MessageKey = "gap.cleared", Args = ["admin"] } };
        Assert.IsType<OkObjectResult>(await c.Batch(batch, Dns));
    }

    // ---- config

    [Fact]
    public async Task The_config_is_this_machines_own_settings_in_the_shape_agents_get()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        {
        var c = Ctl(secret);
        var db = NewDb();
            db.CollectorStates.Add(new CollectorState { Key = "LastRecordId", Value = "4711" }); // from the collector inside the web service
            await db.SaveChangesAsync();
            var ok = Assert.IsType<OkObjectResult>(await c.Config());
            var body = JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(ok.Value))!;
            Assert.Equal(LocalCollector.ConfigVersion(LocalCollector.ConfigFrom(_settings)), body["version"]!.GetValue<int>());
            Assert.Equal(@"D:\Share", body["config"]!["MonitoredPaths"]![0]!["path"]!.GetValue<string>());
            Assert.Null(body["config"]!["DnsServer"]); // only folders and recording rules
            Assert.Equal("4711", body["position"]!.GetValue<string>());

            // Once the new collector has saved a batch, the old position is no longer offered
            Assert.IsType<OkObjectResult>(await c.Batch(Batch(1, "a.txt"), Dns));
            var after = JsonNode.Parse(System.Text.Json.JsonSerializer.Serialize(((OkObjectResult)await c.Config()).Value))!;
            Assert.Equal("", after["position"]!.GetValue<string>());
        }
        Assert.IsType<UnauthorizedResult>(await Ctl("wrong").Config());
    }

    [Fact]
    public void The_config_version_follows_the_config()
    {
        var a = LocalCollector.ConfigFrom(_settings);
        var b = LocalCollector.ConfigFrom(_settings);
        Assert.Equal(LocalCollector.ConfigVersion(a), LocalCollector.ConfigVersion(b));
        ((JsonArray)b["MonitoredPaths"]!).Add(new JsonObject { ["path"] = @"E:\Other" });
        Assert.NotEqual(LocalCollector.ConfigVersion(a), LocalCollector.ConfigVersion(b));
        Assert.True(LocalCollector.ConfigVersion(b) >= 0);
    }

    // ---- jobs

    [Fact]
    public async Task A_job_for_this_machine_goes_to_the_collector_and_its_answer_comes_back()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        await Ctl(secret).Heartbeat(new HeartbeatRequest("1.11.0"));

        var running = _state.RunJobAsync(_jobs, "applySacl", new JsonObject { ["path"] = @"D:\Share" }, TimeSpan.FromSeconds(10), default);
        var job = await _jobs.NextAsync(LocalCollector.AgentId, TimeSpan.FromSeconds(5), default); // what the collector's long poll gets
        Assert.NotNull(job);
        Assert.Equal("applySacl", job!.Type);
        Assert.Equal(@"D:\Share", job.Args["path"]!.GetValue<string>());
        Assert.False(_jobs.Complete("someone-else", job.Id, new JsonObject()));
        Assert.True(_jobs.Complete(LocalCollector.AgentId, job.Id, new JsonObject { ["exists"] = true, ["count"] = 7 }));
        Assert.Equal(7, (await running)["count"]!.GetValue<int>());
    }

    [Fact]
    public async Task A_job_fails_at_once_when_the_collector_is_not_connected_and_reports_its_errors()
    {
        var none = await Assert.ThrowsAsync<LocalCollectorException>(() =>
            _state.RunJobAsync(_jobs, "scan", new JsonObject(), TimeSpan.FromSeconds(10), default));
        Assert.Equal(503, none.Status);

        _state.Touch(DateTime.UtcNow);
        var running = _state.RunJobAsync(_jobs, "scan", new JsonObject(), TimeSpan.FromSeconds(10), default);
        var job = await _jobs.NextAsync(LocalCollector.AgentId, TimeSpan.FromSeconds(5), default);
        _jobs.Complete(LocalCollector.AgentId, job!.Id, new JsonObject { ["error"] = "Access denied" });
        var failed = await Assert.ThrowsAsync<LocalCollectorException>(() => running);
        Assert.Equal((400, "Access denied"), (failed.Status, failed.Reported));

        var silent = await Assert.ThrowsAsync<LocalCollectorException>(() =>
            _state.RunJobAsync(_jobs, "scan", new JsonObject(), TimeSpan.FromMilliseconds(50), default));
        Assert.Equal(504, silent.Status);
    }

    [Fact]
    public async Task The_collector_polls_for_jobs_with_its_credential()
    {
        var secret = LocalCollector.GetOrCreateSecret(_folder);
        var running = _state.RunJobAsync(_jobs, "scan", new JsonObject { ["folder"] = @"D:\Share" }, TimeSpan.FromSeconds(10), default);
        // Connected only once it has been heard from
        Assert.False(_state.IsConnected(DateTime.UtcNow));
        await Assert.ThrowsAsync<LocalCollectorException>(() => running);

        _state.Touch(DateTime.UtcNow);
        running = _state.RunJobAsync(_jobs, "scan", new JsonObject { ["folder"] = @"D:\Share" }, TimeSpan.FromSeconds(10), default);
        var c = Ctl(secret);
        var lifetime = new TestLifetime();
        var next = Assert.IsType<OkObjectResult>(await c.NextJob(_jobs, lifetime));
        var job = Assert.IsType<AgentJob>(next.Value);
        Assert.IsType<OkResult>(await c.JobResult(job.Id, new JsonObject { ["exists"] = true }, _jobs));
        Assert.True((await running)["exists"]!.GetValue<bool>());
    }

    // ---- the certificate the collector pins

    [Fact]
    public void The_collector_reads_the_agent_endpoint_fingerprint_from_the_data_folder()
    {
        using var cert = SelfSignedCertificate.Create(AgentEndpoint.Subject, AgentEndpoint.Names(), AgentEndpoint.ValidityYears);
        File.WriteAllBytes(Path.Combine(_folder, AgentEndpoint.PfxFileName), cert.Export(X509ContentType.Pfx));
        Assert.Equal(AgentSecrets.Fingerprint(cert), AgentEndpoint.ReadFingerprint(_folder));
    }

    [Fact]
    public void The_fingerprint_is_read_again_only_after_a_minute()
    {
        var reads = 0;
        var cache = new FingerprintCache(() => ++reads == 1 ? null : "AB");
        Assert.Null(cache.Get());   // not made yet; asked again next time
        Assert.Equal("AB", cache.Get());
        Assert.Equal("AB", cache.Get());
        Assert.Equal(2, reads);
    }

    private sealed class TestLifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }
}
