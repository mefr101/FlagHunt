using FlagHunt.Core.Agent;

namespace FlagHunt.Core.Tests;

public class PostmortemAnalyzerTests
{
    private const string Answer = """
        ANALYSIS
        Base64-encoded string.

        SOLUTION
        Decode it with base64_decode.

        FLAG
        picoCTF{b4s3_64_rul3s}

        EXPLANATION
        The tool decoded it.
        """;

    // ── Verdicts ────────────────────────────────────────────────────────────

    [Fact]
    public void FlagSeenInToolOutput_IsSolvedVerified()
    {
        var log = new LogBuilder()
            .Challenge().Agent()
            .Iteration(1).Call("base64_decode", "data=\"cGljb0NURn...\"")
            .ToolOk("base64_decode", "picoCTF{b4s3_64_rul3s}")
            .Iteration(2).Stop("end_turn")
            .Final(Answer);

        var run = Single(log);

        Assert.Equal(RunVerdict.Solved, run.Verdict);
        Assert.Equal("picoCTF{b4s3_64_rul3s}", run.Flag);
        Assert.StartsWith("seen in output of base64_decode", run.FlagEvidence);
        Assert.Equal(2, run.Iterations);
        Assert.Equal(1, run.ToolCalls);
        Assert.True(run.AgentMode);
    }

    [Fact]
    public void FlagOnlyInModelText_IsSolvedUnverified()
    {
        var log = new LogBuilder()
            .Challenge().Agent()
            .Iteration(1).Call("file_type", "path=\"a.bin\"").ToolOk("file_type", "data")
            .Final(Answer);

        var run = Single(log);

        Assert.Equal(RunVerdict.SolvedUnverified, run.Verdict);
        Assert.Null(run.FlagEvidence);
        Assert.Contains(run.Findings, f => f.Cause.Contains("only in the model's text"));
    }

    [Fact]
    public void UnverifiedHedgedFlag_IsPartial()
    {
        var log = new LogBuilder().Challenge()
            .Final("FLAG\nThe flag is probably flag{maybe_this}\n");

        var run = Single(log);

        Assert.Equal(RunVerdict.Partial, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.Contains("hedged") && f.Cause.Contains("probably"));
    }

    [Fact]
    public void VerifiedHedgedFlag_StaysSolvedWithNote()
    {
        var log = new LogBuilder()
            .Challenge().Agent().Iteration(1).Call("strings_extract", "p").ToolOk("strings_extract", "xx flag{real} yy")
            .Final("FLAG\nLikely flag{real}");

        var run = Single(log);

        Assert.Equal(RunVerdict.Solved, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.Contains("hedged"));
    }

    [Fact]
    public void ScriptInsteadOfFlag_IsPartialWithScriptFinding()
    {
        var log = new LogBuilder().Challenge()
            .Final("ANALYSIS\nRSA.\n\nFLAG\nRun this python script:\n```python\nprint(decrypt(c))\n```\n\nEXPLANATION\nSmall e.");

        var run = Single(log);

        Assert.Equal(RunVerdict.Partial, run.Verdict);
        Assert.Null(run.Flag);
        Assert.Contains(run.Findings, f => f.Cause.Contains("no flag-shaped string"));
        Assert.Contains(run.Findings, f => f.Cause.Contains("script"));
    }

    [Fact]
    public void FollowUpWithoutFlag_IsAnswered_AndOverallUsesTheChallengeRun()
    {
        var log = new LogBuilder()
            .Challenge().Final("FLAG\nflag{abc}")
            .FollowUp().Final("Step 2 XORs each byte with 0x20.");

        var pm = PostmortemAnalyzer.Analyze(log.Entries);

        Assert.Equal(RunVerdict.Answered, pm.Runs[1].Verdict);
        Assert.Equal(RunVerdict.SolvedUnverified, pm.Overall);
        Assert.Equal(1, pm.OverallRun);
    }

    [Fact]
    public void Overall_IsBestVerdictAcrossRuns()
    {
        var log = new LogBuilder()
            .Challenge().Error("API Error 429: rate_limit_error")
            .FollowUp().Final("FLAG\nflag{second_try}");

        var pm = PostmortemAnalyzer.Analyze(log.Entries);

        Assert.Equal(RunVerdict.Failed, pm.Runs[0].Verdict);
        Assert.Equal(RunVerdict.SolvedUnverified, pm.Overall);
        Assert.Equal(2, pm.OverallRun);
    }

    [Fact]
    public void FollowUpRestatingEarlierVerifiedFlag_KeepsEvidence()
    {
        var log = new LogBuilder()
            .Challenge().Agent().Iteration(1).Call("rot13", "t").ToolOk("rot13", "flag{rot}")
            .Final("FLAG\nflag{rot}")
            .FollowUp().Final("To recap, the flag is flag{rot}.");

        var pm = PostmortemAnalyzer.Analyze(log.Entries);

        Assert.Equal(RunVerdict.Solved, pm.Runs[1].Verdict);
    }

    [Fact]
    public void ProviderError_IsFailedWithClassifiedCause()
    {
        var log = new LogBuilder().Challenge().Error("Anthropic API 429: Number of request tokens has exceeded your rate limit");

        var run = Single(log);

        Assert.Equal(RunVerdict.Failed, run.Verdict);
        var f = Assert.Single(run.Findings);
        Assert.StartsWith("rate limited", f.Cause);
        Assert.NotNull(f.Fix);
    }

    [Fact]
    public void McpUnreachable_IsFailedWithDockerFix()
    {
        var log = new LogBuilder()
            .Challenge().Agent()
            .Signal(LogSignal.McpUnreachable, "MCP toolbox unreachable: connection refused", "connection refused")
            .Error("Cannot reach the MCP toolbox at http://localhost:8000/mcp\n\nError: connection refused");

        var run = Single(log);

        Assert.Equal(RunVerdict.Failed, run.Verdict);
        Assert.Contains(run.Findings, f => f.Fix!.Contains("docker compose up"));
        Assert.DoesNotContain(run.Findings, f => f.Cause.Contains("never called a tool"));
    }

    [Fact]
    public void UserStop_IsStoppedWithLastEvent()
    {
        var log = new LogBuilder()
            .Challenge().Agent().Iteration(1).Call("http_fetch", "url=\"http://x\"")
            .Outcome(LogSignal.Stopped, "Stopped by user before any answer streamed.");

        var run = Single(log);

        Assert.Equal(RunVerdict.Stopped, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.StartsWith("stopped by the user") && f.Cause.Contains("http_fetch"));
    }

    [Fact]
    public void Timeout_IsTimedOut()
    {
        var log = new LogBuilder().Challenge().Outcome(LogSignal.TimedOut, "Timed out after 20 min before any answer streamed.");

        var run = Single(log);

        Assert.Equal(RunVerdict.TimedOut, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.Contains("safety timeout"));
    }

    [Fact]
    public void StopAfterFlag_NotesTheFlag()
    {
        var log = new LogBuilder().Challenge()
            .Outcome(LogSignal.Stopped, "Stopped by user. Partial answer kept:\nFLAG\nflag{got_it}");

        var run = Single(log);

        Assert.Equal(RunVerdict.Stopped, run.Verdict);
        Assert.Equal("flag{got_it}", run.Flag);
    }

    [Fact]
    public void MissingOutcome_IsNoOutcome()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1);

        Assert.Equal(RunVerdict.NoOutcome, Single(log).Verdict);
    }

    [Fact]
    public void EmptyAgentAnswer_IsFailed()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1)
            .Final("[The agent finished without producing a text answer.]");

        var run = Single(log);

        Assert.Equal(RunVerdict.Failed, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.Contains("no text answer"));
    }

    // ── Causes ──────────────────────────────────────────────────────────────

    [Fact]
    public void IterationCap_IsReported()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(25)
            .Signal(LogSignal.IterationCap, "reached the 25-iteration tool cap; stopping.", number: 25)
            .Final("Progress so far...\n\n[Agent stopped after the tool-iteration cap was reached.]");

        var run = Single(log);

        Assert.Equal(RunVerdict.Partial, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause == "hit the 25-iteration tool cap");
        Assert.Contains(run.Findings, f => f.Cause.Contains("ran out of iterations"));
    }

    [Theory]
    [InlineData("max_tokens")]
    [InlineData("length")]
    public void TruncatedOutput_IsReported(string reason)
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1)
            .Signal(LogSignal.StopReason, $"stop reason: {reason}", reason)
            .Final("ANALYSIS\nThis is a long");

        Assert.Contains(Single(log).Findings, f => f.Cause.Contains("token limit") && f.Fix!.Contains("MaxTokens"));
    }

    [Fact]
    public void NoToolCalls_IsReportedWhenNotSolved()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1).Stop("stop")
            .Final("I would run strings on the file.");

        Assert.Contains(Single(log).Findings, f => f.Cause == "the model never called a tool");
    }

    [Fact]
    public void NoToolCalls_IsNotReportedWhenSolved()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1).Final("FLAG\nflag{easy}");

        Assert.DoesNotContain(Single(log).Findings, f => f.Cause.Contains("never called a tool"));
    }

    [Fact]
    public void ToolErrors_AreCountedAndGroupedByTool()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1)
            .Call("xor_brute", "a").ToolError("xor_brute", "tool error: unknown tool: xor_brute")
            .Call("xor_brute", "b").ToolError("xor_brute", "tool error: unknown tool: xor_brute")
            .Call("hex_decode", "c").ToolOk("hex_decode", "ok")
            .Final("no luck");

        var run = Single(log);

        Assert.Equal(2, run.ToolErrors);
        var f = Assert.Single(run.Findings, x => x.Cause.Contains("tool calls failed"));
        Assert.Contains("2 of 3", f.Cause);
        Assert.Contains("xor_brute x2", f.Cause);
        Assert.Contains("most tool calls failed", f.Fix);
        Assert.Contains("'auto' category", f.Fix);
    }

    [Fact]
    public void RepeatedIdenticalCalls_AreReportedAsLoop()
    {
        var b = new LogBuilder().Challenge().Agent();
        for (int i = 1; i <= 3; i++)
            b.Iteration(i).Call("file_type", "path=\"a.bin\"").ToolOk("file_type", "data");
        b.Call("file_type", "path=\"b.bin\"").ToolOk("file_type", "data");
        b.Final("still unknown");

        var run = Single(b);

        var loop = Assert.Single(run.Findings, f => f.Cause.Contains("identical arguments"));
        Assert.Contains("a.bin", loop.Cause);
        Assert.Contains("3 times", loop.Cause);
    }

    [Fact]
    public void ChatModeWithAttachments_SuggestsAgentMode()
    {
        var log = new LogBuilder().Challenge(attachments: 2).Final("Open it in a hex editor.");

        var run = Single(log);

        Assert.False(run.AgentMode);
        Assert.Contains(run.Findings, f => f.Cause.Contains("agent mode was off") && f.Cause.StartsWith("2 file(s)"));
    }

    [Fact]
    public void StageFailure_IsReported()
    {
        var log = new LogBuilder().Challenge(attachments: 1)
            .Signal(LogSignal.StageFailed, "could not stage a.bin: in use", "a.bin")
            .Agent().Iteration(1).Final("FLAG\nflag{x}");

        Assert.Contains(Single(log).Findings, f => f.Cause.Contains("could not stage a.bin"));
    }

    [Fact]
    public void Interruption_DowngradesUnverifiedAndIsClassified()
    {
        var log = new LogBuilder().Challenge().Agent().Iteration(1)
            .Signal(LogSignal.RequestFailed, "request failed: Anthropic API 529: Overloaded", "Anthropic API 529: Overloaded")
            .Final("FLAG\nflag{guess}\n\n[Run interrupted: Anthropic API 529: Overloaded]");

        var run = Single(log);

        Assert.Equal(RunVerdict.Partial, run.Verdict);
        Assert.Contains(run.Findings, f => f.Cause.Contains("interrupted") && f.Cause.Contains("overloaded"));
    }

    [Fact]
    public void ChatStreamInterruption_IsDetectedFromText()
    {
        var log = new LogBuilder().Challenge()
            .Final("partial text\n\n[stream interrupted: No such host is known.]");

        Assert.Contains(Single(log).Findings, f => f.Cause.Contains("interrupted") && f.Cause.Contains("unreachable"));
    }

    [Fact]
    public void StatsAreAggregated()
    {
        var log = new LogBuilder().Challenge().Agent()
            .Iteration(1).Usage(1000).Call("a", "1").ToolOk("a", "x").Call("b", "2").ToolOk("b", "y")
            .Iteration(2).Usage(500).Call("a", "3").ToolOk("a", "z")
            .Final("done");

        var run = Single(log);

        Assert.Equal(1500, run.Tokens);
        Assert.Equal(3, run.ToolCalls);
        Assert.Equal(2, run.DistinctTools);
        Assert.Equal(TimeSpan.FromSeconds(log.Entries.Count - 1), run.Duration);
    }

    // ── Error classification ────────────────────────────────────────────────

    [Theory]
    [InlineData("No Anthropic API key. Paste it in the top bar.", "no API key")]
    [InlineData("No model selected. Load a model in LM Studio and click 'fetch'.", "no model")]
    [InlineData("API Error 401: invalid x-api-key", "authentication failed")]
    [InlineData("Cursor Error 403: forbidden", "permission denied")]
    [InlineData("Anthropic API 529: Overloaded", "overloaded")]
    [InlineData("LM Studio Error 500: boom", "server error")]
    [InlineData("API Error 400: prompt is too long: 250000 tokens > 200000 maximum", "prompt was too large")]
    [InlineData("API Error 400: model not found", "rejected")]
    [InlineData("Cannot reach Ollama at http://localhost:11434\n\nRun: ollama serve", "unreachable")]
    [InlineData("Ollama returned an empty stream.", "returned nothing")]
    [InlineData("something odd", "provider error: something odd")]
    public void ClassifyError_MapsKnownFailures(string error, string expected)
    {
        Assert.Contains(expected, PostmortemAnalyzer.ClassifyError(error).Cause);
    }

    // ── Flag extraction ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("FLAG: picoCTF{inline}", "picoCTF{inline}")]
    [InlineData("**FLAG:** `HTB{bold_and_code}`", "HTB{bold_and_code}")]
    [InlineData("## Flag\n\nctf{heading}\n\n## Explanation\nflag{not_this}", "ctf{heading}")]
    [InlineData("SOLUTION\nbytes = byte{0x41}\n\nFLAG\nABC{custom_prefix}", "ABC{custom_prefix}")]
    [InlineData("FLAG\nflag{...}\nreal: flag{actual}", "flag{actual}")]
    [InlineData("No section, but the answer is flag{loose}.", "flag{loose}")]
    public void PickFlag_FindsTheReportedFlag(string answer, string expected)
    {
        Assert.Equal(expected, PostmortemAnalyzer.PickFlag(answer));
    }

    [Theory]
    [InlineData("SOLUTION\nx = byte{0x41, 0x42}")]
    [InlineData("FLAG\nflag{...}")]
    [InlineData("FLAG\nflag{FLAG_HERE}")]
    [InlineData("print(f\"{x}\")")]
    public void PickFlag_IgnoresCodeAndPlaceholders(string answer)
    {
        Assert.Null(PostmortemAnalyzer.PickFlag(answer));
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    [Fact]
    public void Render_AppendsPostmortemAfterEvents()
    {
        var log = new SessionEventLog();
        log.Log(LogCategory.Session, "Challenge submitted: decode this", signal: LogSignal.RunStart, value: "challenge");
        log.LogActivity(AgentActivity.Signaled(LogSignal.AgentStart, "connecting ..."));
        log.LogActivity(AgentActivity.Signaled(LogSignal.IterationStart, "-- iteration 1 --", number: 1));
        log.LogActivity(AgentActivity.Call("base64_decode", "base64_decode(data=...)"));
        log.LogActivity(AgentActivity.Result("base64_decode", "picoCTF{b4s3_64_rul3s}", isError: false));
        log.Log(LogCategory.Result, "Final answer:\n" + Answer, signal: LogSignal.FinalAnswer);

        string text = log.Render();

        int events = text.IndexOf("RESULT", StringComparison.Ordinal);
        int pm = text.IndexOf("POSTMORTEM", StringComparison.Ordinal);
        Assert.True(events > 0 && pm > events, "postmortem should follow the event lines");
        Assert.Contains("Run 1 (challenge)  SOLVED (verified)", text);
        Assert.Contains("flag    : picoCTF{b4s3_64_rul3s}", text);
        Assert.Contains("evidence: seen in output of base64_decode", text);
        Assert.Contains("Overall : SOLVED (verified) (run 1)", text);
    }

    [Fact]
    public void Render_ListsFindingsWithFixes()
    {
        var log = new SessionEventLog();
        log.Log(LogCategory.Session, "Challenge submitted", signal: LogSignal.RunStart, value: "challenge");
        log.Log(LogCategory.Result, "Error: API Error 429: rate limit", signal: LogSignal.Error);

        string text = log.Render();

        Assert.Contains("Run 1 (challenge)  FAILED", text);
        Assert.Contains("  - rate limited", text);
        Assert.Contains("    fix: wait and retry", text);
    }

    [Fact]
    public void Render_EmptyLogHasNoPostmortem()
    {
        Assert.DoesNotContain("POSTMORTEM", new SessionEventLog().Render());
    }

    [Fact]
    public void LogActivity_PreservesSignals()
    {
        var log = new SessionEventLog();
        log.LogActivity(AgentActivity.Result("hex_decode", "tool error: bad hex", isError: true));

        var e = Assert.Single(log.Snapshot());
        Assert.Equal(LogSignal.ToolError, e.Signal);
        Assert.Equal("hex_decode", e.Value);
        Assert.Equal(AgentActivityKind.ToolResult, e.Kind);
    }

    private static RunPostmortem Single(LogBuilder log) => Assert.Single(PostmortemAnalyzer.Analyze(log.Entries).Runs);
}
