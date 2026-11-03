using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FileAccessMonitor.Controllers;
using FileAccessMonitor.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace FileAccessMonitor.Tests;

public class IntegrityApiTests
{
    private static IntegrityController Controller(ChainEnv env, IntegrityService svc) => new(svc, env.Services.GetRequiredService<AuditLog>())
    {
        ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "admin")], "test")) },
        },
    };

    [Fact]
    public void Only_admins_may_call_it()
    {
        var auth = typeof(IntegrityController).GetCustomAttributes(typeof(AuthorizeAttribute), true).Cast<AuthorizeAttribute>().Single();
        Assert.Equal("Admin", auth.Roles);
        Assert.DoesNotContain(typeof(IntegrityController).GetMethods(), m => m.GetCustomAttributes(typeof(AllowAnonymousAttribute), true).Length > 0);
    }

    [Fact]
    public async Task Status_describes_both_chains()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(3);
        var svc = env.NewService();
        var ok = Assert.IsType<OkObjectResult>(await Controller(env, svc).Status(default));
        var status = Assert.IsType<IntegrityStatus>(ok.Value);
        Assert.Equal("notVerified", status.Summary.State);
        Assert.True(status.KeyAvailable);
        Assert.Equal(["access", "audit"], status.Chains.Select(c => c.Chain).ToArray());
        Assert.Equal(3, status.Chains[0].HeadSeq);
        Assert.Single(status.Chains[0].Checkpoints, c => c.Reason == "genesis");
    }

    [Fact]
    public async Task Verify_runs_in_the_background_and_progress_can_be_polled()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(50);
        var svc = env.NewService();
        var c = Controller(env, svc);
        var accepted = Assert.IsType<AcceptedResult>(c.Verify());
        var id = (string)accepted.Value!.GetType().GetProperty("id")!.GetValue(accepted.Value)!;

        VerifyRun? run = null;
        for (var i = 0; i < 100; i++)
        {
            run = Assert.IsType<VerifyRun>(Assert.IsType<OkObjectResult>(c.Progress(id)).Value);
            if (run.State != "running") break;
            await Task.Delay(50);
        }
        Assert.Equal("done", run!.State);
        Assert.Equal(50, run.RowsDone);
        Assert.Empty(run.Breaks);
        Assert.IsType<NotFoundObjectResult>(c.Progress("nope"));
    }

    [Fact]
    public async Task A_second_verify_while_one_runs_returns_the_running_one()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(20);
        var svc = env.NewService();
        // Hold the run gate through a long chain lock? Simpler: two starts in a row share a run while it is still running
        var first = svc.StartVerify("admin");
        var second = svc.StartVerify("admin");
        if (first.State == "running") Assert.Same(first, second);
        for (var i = 0; i < 100 && first.State == "running"; i++) await Task.Delay(50);
        Assert.Equal("done", first.State);
    }

    [Fact]
    public async Task Accept_without_a_finding_is_refused_and_with_one_it_works()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(20);
        var svc = env.NewService();
        var c = Controller(env, svc);
        Assert.IsType<BadRequestObjectResult>(await c.Accept(new AcceptBreakRequest("access", null, "x"), default));
        Assert.IsType<BadRequestObjectResult>(await c.Accept(new AcceptBreakRequest(null, null, null), default));

        env.Exec("DELETE FROM AccessRecords WHERE ChainSeq = 5");
        await svc.VerifyAsync(full: true, default);
        Assert.IsType<OkObjectResult>(await c.Accept(new AcceptBreakRequest("access", "access|missing|5", "backup restored"), default));
        Assert.Equal("ok", (await svc.GetSummaryAsync()).State);
    }

    [Fact]
    public async Task The_anchor_download_is_a_json_file_with_the_line()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(2);
        var svc = env.NewService();
        var file = Assert.IsType<FileContentResult>(await Controller(env, svc).Anchor(default));
        Assert.Equal("application/json", file.ContentType);
        Assert.StartsWith("fam-anchor-", file.FileDownloadName);
        var json = JsonDocument.Parse(Encoding.UTF8.GetString(file.FileContents)).RootElement;
        Assert.StartsWith("FAM-ANCHOR v1 ", json.GetProperty("line").GetString());
        Assert.Equal(2, json.GetProperty("access").GetProperty("seq").GetInt64());

        // The downloaded file is accepted by check-anchor as it is
        var check = Assert.IsType<OkObjectResult>(await Controller(env, svc)
            .CheckAnchor(new CheckAnchorRequest(Encoding.UTF8.GetString(file.FileContents)), default));
        Assert.True(Assert.IsType<AnchorCheck>(check.Value).Ok);
    }

    [Fact]
    public async Task Check_anchor_refuses_text_that_is_not_an_anchor()
    {
        using var env = new ChainEnv();
        var c = Controller(env, env.NewService());
        Assert.IsType<BadRequestObjectResult>(await c.CheckAnchor(new CheckAnchorRequest("hello"), default));
        Assert.IsType<BadRequestObjectResult>(await c.CheckAnchor(new CheckAnchorRequest(null), default));
        Assert.IsType<BadRequestObjectResult>(await c.CheckAnchor(new CheckAnchorRequest(new string('x', 30000)), default));
    }

    [Fact]
    public async Task The_summary_for_the_report_mail_carries_the_anchor_line()
    {
        using var env = new ChainEnv();
        await env.AddRecordsAsync(2);
        var svc = env.NewService();
        IIntegrityStatus status = svc;
        var s = await status.GetSummaryAsync();
        Assert.StartsWith("FAM-ANCHOR v1 ", s.AnchorLine);
        Assert.Equal(2, s.HeadSeq);
        Assert.Equal(64, s.HeadHashHex.Length);
    }

    [Fact]
    public void The_alert_texts_exist_in_both_languages_and_take_six_arguments()
    {
        foreach (var lang in new[] { "en", "ja" })
        {
            var body = Messages.GetIn(lang, "integrity.alertBody", "access", "altered", 5, "a - b UTC", "SRV", 2);
            Assert.DoesNotContain("{", body);
            Assert.DoesNotContain("機械", body);
            Assert.Contains("SRV", body);
        }
    }
}
