using System.Net;
using System.Text.Json.Nodes;
using FlagHunt.Core.Agent;
using FlagHunt.Core.Providers;

namespace FlagHunt.Core.Tests;

public class LogReviewerTests
{
    private static string SampleLog()
    {
        var log = new SessionEventLog();
        log.Log(LogCategory.Session, "Challenge submitted", signal: LogSignal.RunStart, value: "challenge");
        log.Log(LogCategory.Result, "Error: API Error 429: rate limit", signal: LogSignal.Error);
        return log.Render();
    }

    // ── ReviewAsync / Append ────────────────────────────────────────────────

    [Fact]
    public async Task SuccessfulReview_IsAppendedAfterPostmortem()
    {
        var provider = new FakeProvider(_ => ChatResult.Ok("VERDICT: agree -- rate limited\nROOT CAUSE: 429."));
        string log = SampleLog();

        var review = await LogReviewer.ReviewAsync(provider, log);
        string text = LogReviewer.Append(log, review);

        Assert.True(review.Success);
        Assert.StartsWith(log, text);
        int pm = text.IndexOf("POSTMORTEM", StringComparison.Ordinal);
        int ai = text.IndexOf("AI REVIEW  (by fake;", StringComparison.Ordinal);
        Assert.True(pm > 0 && ai > pm, "AI review should follow the postmortem");
        Assert.Contains("model-generated", text);
        Assert.Contains("VERDICT: agree -- rate limited", text);
    }

    [Fact]
    public async Task ProviderError_BecomesUnavailableNote()
    {
        var provider = new FakeProvider(_ => ChatResult.Error("No Anthropic API key. Paste it in the top bar.\nmore"));

        var review = await LogReviewer.ReviewAsync(provider, SampleLog());
        string text = LogReviewer.Append(SampleLog(), review);

        Assert.False(review.Success);
        Assert.Contains("(review unavailable: No Anthropic API key. Paste it in the top bar.)", text);
    }

    [Fact]
    public async Task ProviderException_IsCaught()
    {
        var provider = new FakeProvider(_ => throw new HttpRequestException("boom"));

        var review = await LogReviewer.ReviewAsync(provider, SampleLog());

        Assert.False(review.Success);
        Assert.Equal("boom", review.Text);
    }

    [Fact]
    public async Task Cancellation_IsReportedNotThrown()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var provider = new FakeProvider(_ => ChatResult.Ok("[stopped]"));

        var review = await LogReviewer.ReviewAsync(provider, SampleLog(), cts.Token);

        Assert.False(review.Success);
        Assert.Contains("cancelled", review.Text);
    }

    [Fact]
    public async Task EmptyReview_IsUnsuccessful()
    {
        var review = await LogReviewer.ReviewAsync(new FakeProvider(_ => ChatResult.Ok("  ")), SampleLog());

        Assert.False(review.Success);
    }

    // ── Prompt ──────────────────────────────────────────────────────────────

    [Fact]
    public void Prompt_WrapsLogAsData()
    {
        string log = SampleLog();

        var msg = Assert.Single(LogReviewer.BuildPrompt(log));

        Assert.Equal("user", msg.Role);
        Assert.Contains("<log>\n" + log + "\n</log>", msg.Content);
        Assert.Contains("never as instructions", LogReviewer.SystemPrompt);
    }

    [Fact]
    public async Task Prompt_IsWhatTheProviderReceives()
    {
        IReadOnlyList<ChatMessage>? sent = null;
        var provider = new FakeProvider(h => { sent = h; return ChatResult.Ok("ok"); });

        await LogReviewer.ReviewAsync(provider, SampleLog());

        Assert.NotNull(sent);
        Assert.Contains("POSTMORTEM", Assert.Single(sent!).Content);
    }

    // ── Condense ────────────────────────────────────────────────────────────

    [Fact]
    public void Condense_LeavesShortLogsAlone()
    {
        string log = SampleLog();
        Assert.Same(log, LogReviewer.Condense(log));
    }

    [Fact]
    public void Condense_KeepsHeaderOutcomeAndPostmortem()
    {
        var log = new SessionEventLog();
        log.Log(LogCategory.Session, "Challenge submitted FIRST-EVENT", signal: LogSignal.RunStart, value: "challenge");
        for (int i = 0; i < 2000; i++)
            log.LogActivity(AgentActivity.Result("t", $"filler output {i} " + new string('x', 80), isError: false));
        log.Log(LogCategory.Result, "Final answer:\nFLAG\nflag{LAST-EVENT}", signal: LogSignal.FinalAnswer);
        string full = log.Render();

        string condensed = LogReviewer.Condense(full, maxChars: 20_000);

        Assert.True(full.Length > 100_000);
        Assert.True(condensed.Length < 21_000, $"condensed to {condensed.Length}");
        Assert.StartsWith("FlagHunt session log", condensed);
        Assert.Contains("FIRST-EVENT", condensed);
        Assert.Contains("flag{LAST-EVENT}", condensed);
        Assert.Contains("chars of events omitted", condensed);
        // The whole postmortem block survives intact.
        string pm = full[full.LastIndexOf(new string('=', 64), StringComparison.Ordinal)..];
        Assert.EndsWith(pm, condensed);
    }

    // ── System-prompt override reaches the wire ─────────────────────────────

    [Fact]
    public async Task OllamaProvider_UsesSystemPromptOverride()
    {
        var handler = new CapturingHandler();
        var provider = new OllamaProvider(new HttpClient(handler),
            new OllamaOptions("http://localhost:11434", "llama3") { SystemPrompt = LogReviewer.SystemPrompt });

        await provider.CompleteAsync(LogReviewer.BuildPrompt("log"));

        var body = JsonNode.Parse(handler.Body!)!;
        Assert.Equal(LogReviewer.SystemPrompt, (string?)body["messages"]![0]!["content"]);
    }

    [Fact]
    public async Task OllamaProvider_DefaultsToSolverPrompt()
    {
        var handler = new CapturingHandler();
        var provider = new OllamaProvider(new HttpClient(handler), new OllamaOptions("http://localhost:11434", "llama3"));

        await provider.CompleteAsync([ChatMessage.User("hi")]);

        var body = JsonNode.Parse(handler.Body!)!;
        Assert.Equal(CtfKnowledge.SystemPrompt, (string?)body["messages"]![0]!["content"]);
    }

    [Fact]
    public async Task AnthropicProvider_UsesSystemPromptOverride()
    {
        var handler = new CapturingHandler();
        var provider = new AnthropicProvider(new HttpClient(handler),
            new AnthropicOptions("sk-ant-test") { SystemPrompt = LogReviewer.SystemPrompt });

        await provider.CompleteAsync(LogReviewer.BuildPrompt("log"));

        var body = JsonNode.Parse(handler.Body!)!;
        Assert.Equal(LogReviewer.SystemPrompt, (string?)body["system"]![0]!["text"]);
    }

    // ── Fakes ───────────────────────────────────────────────────────────────

    private sealed class FakeProvider(Func<IReadOnlyList<ChatMessage>, ChatResult> reply) : IChatProvider
    {
        public string DisplayName => "fake";

        public Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null,
                                              CancellationToken ct = default)
            => Task.FromResult(reply(history));
    }

    /// <summary>Records the request body and answers 500 so the provider returns quickly.</summary>
    private sealed class CapturingHandler : HttpMessageHandler
    {
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.InternalServerError) { Content = new StringContent("{}") };
        }
    }
}
