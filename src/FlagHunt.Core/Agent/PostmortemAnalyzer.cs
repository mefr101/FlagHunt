using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace FlagHunt.Core.Agent;

/// <summary>How a run ended, best first (the enum order is the ranking used for the overall verdict).</summary>
public enum RunVerdict
{
    /// <summary>A flag was reported and the same string appears in a tool output.</summary>
    Solved,
    /// <summary>A flag was reported but only the model's own text contains it.</summary>
    SolvedUnverified,
    /// <summary>An answer came back without a (confident) flag, or the run was cut short.</summary>
    Partial,
    /// <summary>A follow-up that was answered; no flag was expected.</summary>
    Answered,
    /// <summary>The user pressed Stop.</summary>
    Stopped,
    /// <summary>The safety timeout cancelled the run.</summary>
    TimedOut,
    /// <summary>The provider errored or produced no answer.</summary>
    Failed,
    /// <summary>No outcome was recorded (still running when the log was exported).</summary>
    NoOutcome,
}

/// <summary>One likely cause behind a verdict, with an optional suggested fix.</summary>
public sealed record PostmortemFinding(string Cause, string? Fix = null);

/// <summary>The analysis of one run (a challenge submission or a follow-up).</summary>
public sealed record RunPostmortem(
    int Number,
    string Kind,
    RunVerdict Verdict,
    TimeSpan? Duration,
    bool AgentMode,
    int Iterations,
    int ToolCalls,
    int DistinctTools,
    int ToolErrors,
    long Tokens,
    string? Flag,
    string? FlagEvidence,
    IReadOnlyList<PostmortemFinding> Findings);

/// <summary>The analysis of a whole session log.</summary>
public sealed record Postmortem(IReadOnlyList<RunPostmortem> Runs, RunVerdict Overall, int? OverallRun);

/// <summary>
/// Rule-based postmortem over a <see cref="SessionEventLog"/>: splits the trail into runs at each
/// <see cref="LogSignal.RunStart"/>, decides whether each run found the flag, and lists the
/// evidence-backed reasons it succeeded or failed. Deterministic and offline -- it never calls
/// a model, so it works for every provider and cannot make up a verdict. There is no ground
/// truth for a flag, so "verified" means the reported flag also appears in a tool's output.
/// </summary>
public static class PostmortemAnalyzer
{
    /// <summary>Calls with identical arguments at or above this count are reported as a loop.</summary>
    internal const int LoopThreshold = 3;

    // name{...}: a letter-led prefix directly followed by a braced body on one line.
    private static readonly Regex FlagPattern =
        new(@"(?<![\w$])[A-Za-z][A-Za-z0-9_\-]{1,31}\{[^{}\r\n]{1,200}\}", RegexOptions.Compiled);

    private static readonly Regex FlagishPrefix = new(@"flag|ctf", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex Placeholder =
        new(@"^(\.{2,}|…|x+|_+|flag_?here|your_?flag.*|redacted|\?+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // "FLAG", "## Flag", "**FLAG**", "FLAG: picoCTF{..}" -- the header may carry the flag inline.
    private static readonly Regex FlagHeader =
        new(@"^[ \t#>*_]*flag[ \t*_]*(?::(?<rest>.*))?$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex NextHeader =
        new(@"^[ \t#>*_]*(analysis|solution|explanation)[ \t*_:]*$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex Hedge = new(
        @"\b(likely|probably|possibly|presumably|might be|may be|not certain|not sure|unsure|could not|couldn't|unable|best guess|unverified|cannot confirm)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ScriptHint = new(@"```|\b(python3?|bash|run this|script)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex InterruptMarker =
        new(@"\[(?:Run interrupted|stream interrupted|stream error): (?<msg>[^\]]*)\]", RegexOptions.Compiled);

    private static readonly Regex StatusCode = new(@"\b(?:Error|API)\s+(?<code>\d{3})\b", RegexOptions.Compiled);

    private const string CapMarker = "[Agent stopped after the tool-iteration cap was reached.]";

    private static readonly string[] EmptyAnswerMarkers =
    [
        "[The agent finished without producing a text answer.]",
        "[The agent ran tools but finished without producing a text answer.]",
        "[The model produced no answer and never called a tool.",
        "[stopped]",
    ];

    // ── Analysis ────────────────────────────────────────────────────────────

    /// <summary>Analyses every run in <paramref name="entries"/> (in log order).</summary>
    public static Postmortem Analyze(IReadOnlyList<LogEntry> entries)
    {
        var runs = new List<(int start, int end)>();
        for (int i = 0; i < entries.Count; i++)
        {
            if (entries[i].Signal != LogSignal.RunStart) continue;
            if (runs.Count > 0) runs[^1] = (runs[^1].start, i);
            runs.Add((i, entries.Count));
        }

        var results = new List<RunPostmortem>();
        for (int r = 0; r < runs.Count; r++)
        {
            var (start, end) = runs[r];
            var run = entries.Skip(start).Take(end - start).ToList();
            // A flag counts as verified if any tool output so far in the session contains it,
            // so a follow-up that restates run 1's flag keeps its evidence.
            var toolOutputs = entries.Take(end)
                .Where(e => e.Signal is LogSignal.ToolOk or LogSignal.ToolError)
                .ToList();
            results.Add(AnalyzeRun(r + 1, run, toolOutputs));
        }

        // Overall: the best verdict among runs that were expected to find a flag; answered
        // follow-ups only count when nothing else ran.
        var ranked = results.Where(x => x.Verdict != RunVerdict.Answered).ToList();
        if (ranked.Count == 0) ranked = results;
        var best = ranked.OrderBy(x => x.Verdict).ThenByDescending(x => x.Number).FirstOrDefault();

        return new Postmortem(results, best?.Verdict ?? RunVerdict.NoOutcome, best?.Number);
    }

    private static RunPostmortem AnalyzeRun(int number, List<LogEntry> run, List<LogEntry> toolOutputs)
    {
        var start = run[0];
        string kind = start.Value ?? "challenge";
        bool isFollowUp = kind == "follow-up";
        var findings = new List<PostmortemFinding>();

        var outcome = run.LastOrDefault(e => e.Signal is LogSignal.FinalAnswer or LogSignal.Error
                                                          or LogSignal.Stopped or LogSignal.TimedOut);
        bool agentMode = run.Any(e => e.Signal == LogSignal.AgentStart);
        int iterations = run.Count(e => e.Signal == LogSignal.IterationStart);
        var calls = run.Where(e => e.Signal == LogSignal.ToolCall).ToList();
        var errors = run.Where(e => e.Signal == LogSignal.ToolError).ToList();
        long tokens = run.Where(e => e.Signal == LogSignal.Usage).Sum(e => e.Number);
        int distinctTools = calls.Select(c => c.Value).Distinct().Count();
        TimeSpan? duration = (outcome ?? run[^1]).Time - start.Time;

        string? flag = null, evidence = null;
        RunVerdict verdict;

        switch (outcome?.Signal)
        {
            case null:
                verdict = RunVerdict.NoOutcome;
                findings.Add(new("no outcome was recorded -- the run was still going when the log was saved, or ended abnormally",
                                 "save the log again after the run finishes"));
                break;

            case LogSignal.Error:
                verdict = RunVerdict.Failed;
                findings.Add(ClassifyError(outcome.Text));
                break;

            case LogSignal.Stopped:
            case LogSignal.TimedOut:
            {
                bool timeout = outcome.Signal == LogSignal.TimedOut;
                verdict = timeout ? RunVerdict.TimedOut : RunVerdict.Stopped;
                string last = LastActivity(run, outcome);
                findings.Add(timeout
                    ? new($"cancelled by the safety timeout after {Format(duration)}{last}",
                          "the model or toolbox may be hung; check the events just before the timeout")
                    : new($"stopped by the user after {Format(duration)}{last}"));
                // A flag may already have surfaced before the stop.
                (flag, evidence) = FindFlag(outcome.Text, toolOutputs);
                if (flag is not null)
                    findings.Add(new($"a flag had already been reported before the run was cut short: {flag}"));
                break;
            }

            default: // FinalAnswer
                verdict = JudgeAnswer(outcome.Text, isFollowUp, agentMode, toolOutputs, findings, out flag, out evidence);
                string? interrupt = run.LastOrDefault(e => e.Signal == LogSignal.RequestFailed)?.Value
                                    ?? (InterruptMarker.Match(outcome.Text) is { Success: true } m ? m.Groups["msg"].Value : null);
                if (interrupt is not null)
                {
                    var why = ClassifyError(interrupt);
                    findings.Add(new($"the run was interrupted mid-way: {why.Cause}", why.Fix));
                    if (verdict == RunVerdict.SolvedUnverified) verdict = RunVerdict.Partial;
                }
                break;
        }

        bool solved = verdict is RunVerdict.Solved or RunVerdict.SolvedUnverified or RunVerdict.Answered;
        AddAgentFindings(run, calls, errors, agentMode, solved, findings);

        if (!agentMode && start.Number > 0 && !solved)
            findings.Add(new($"{start.Number} file(s) were attached but agent mode was off, so no tools ran on them",
                             "enable agent mode (Anthropic or LM Studio) so the toolbox can inspect the files"));

        foreach (var s in run.Where(e => e.Signal == LogSignal.StageFailed))
            findings.Add(new($"could not stage {s.Value} into the toolbox workspace",
                             "the file tools could not see it; check the file isn't locked and mcp/challenges is writable"));

        return new RunPostmortem(number, kind, verdict, duration, agentMode, iterations, calls.Count,
                                 distinctTools, errors.Count, tokens, flag, evidence, findings);
    }

    private static RunVerdict JudgeAnswer(string answer, bool isFollowUp, bool agentMode, List<LogEntry> toolOutputs,
                                          List<PostmortemFinding> findings, out string? flag, out string? evidence)
    {
        if (string.IsNullOrWhiteSpace(answer) || EmptyAnswerMarkers.Any(m => answer.TrimStart().StartsWith(m, StringComparison.Ordinal)))
        {
            flag = evidence = null;
            findings.Add(new("the model produced no text answer",
                             agentMode ? "make sure the model supports tool calling and check the last tool results"
                                       : "check the provider and model are working"));
            return RunVerdict.Failed;
        }

        (flag, evidence) = FindFlag(answer, toolOutputs);
        string section = FlagSection(answer) ?? "";

        if (flag is null)
        {
            if (isFollowUp) return RunVerdict.Answered;

            findings.Add(new("the answer contains no flag-shaped string (name{...})"));
            if (section.Length > 0 && ScriptHint.IsMatch(section))
                findings.Add(new("the FLAG section gives a script to extract the flag rather than the flag itself",
                                 agentMode ? "run the script yourself, or ask a follow-up to run it with the tools"
                                           : "run the script yourself, or rerun in agent mode so the tools can execute it"));
            if (answer.Contains(CapMarker, StringComparison.Ordinal))
                findings.Add(new("the agent ran out of iterations before writing a final answer"));
            return RunVerdict.Partial;
        }

        var hedge = Hedge.Match(section.Length > 0 ? section : answer);
        if (evidence is not null)
        {
            if (hedge.Success)
                findings.Add(new($"the model hedged about the flag (\"{hedge.Value}\") even though a tool output contains it"));
            return RunVerdict.Solved;
        }

        findings.Add(new($"the flag appears only in the model's text, not in any tool output",
                         agentMode
                             ? "treat it as unconfirmed -- it may be guessed. Tool outputs are logged as 600-char previews, so a flag deep in a long output can be missed here"
                             : "treat it as unconfirmed -- chat mode has no tool output to check it against"));
        if (hedge.Success)
        {
            findings.Add(new($"the model hedged about the flag (\"{hedge.Value}\")"));
            return RunVerdict.Partial;
        }
        return RunVerdict.SolvedUnverified;
    }

    private static void AddAgentFindings(List<LogEntry> run, List<LogEntry> calls, List<LogEntry> errors,
                                         bool agentMode, bool solved, List<PostmortemFinding> findings)
    {
        if (!agentMode) return;

        var cap = run.LastOrDefault(e => e.Signal == LogSignal.IterationCap);
        if (cap is not null)
            findings.Add(new($"hit the {cap.Number}-iteration tool cap",
                             "raise MaxToolIterations, or pick a specific category so the agent sees fewer, more relevant tools"));

        var stop = run.LastOrDefault(e => e.Signal == LogSignal.StopReason);
        if (stop?.Value is "max_tokens" or "length")
            findings.Add(new($"the model's output was cut off at the token limit (stop reason: {stop.Value})",
                             "raise MaxTokens so the write-up can finish"));

        bool connected = !run.Any(e => e.Signal == LogSignal.McpUnreachable);
        if (connected && calls.Count == 0 && run.Any(e => e.Signal == LogSignal.IterationStart) && !solved)
            findings.Add(new("the model never called a tool",
                             "use a model with function/tool calling (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct), or be explicit that tools are available"));

        if (errors.Count > 0)
        {
            var byTool = errors.GroupBy(e => e.Value ?? "?")
                               .Select(g => g.Count() > 1 ? $"{g.Key} x{g.Count()}" : g.Key);
            string first = FirstLine(errors[0].Text);
            bool most = errors.Count * 2 > calls.Count && calls.Count >= 2;
            findings.Add(new(
                $"{errors.Count} of {calls.Count} tool calls failed ({string.Join(", ", byTool)}); first error: {first}",
                ToolErrorFix(first, most)));
        }

        foreach (var g in calls.GroupBy(c => c.Text).Where(g => g.Count() >= LoopThreshold))
            findings.Add(new($"{Truncate(g.Key, 100)} was called {g.Count()} times with identical arguments",
                             "the agent is looping; a more specific challenge description or category may help it move on"));
    }

    private static string? ToolErrorFix(string firstError, bool mostFailed)
    {
        string? fix =
            firstError.Contains("unknown tool", StringComparison.OrdinalIgnoreCase)
                ? "the model asked for a tool outside the selected category -- try the 'auto' category"
            : Regex.IsMatch(firstError, @"no such file|not found|does not exist", RegexOptions.IgnoreCase)
                ? "the agent referenced a file that isn't in the workspace -- it should call list_workspace first"
            : Regex.IsMatch(firstError, @"parse|JSON", RegexOptions.IgnoreCase)
                ? "the model emitted malformed tool arguments -- a stronger tool-calling model may help"
            : null;

        if (mostFailed)
            fix = fix is null ? "most tool calls failed, so the agent was largely working blind"
                              : $"most tool calls failed; {fix}";
        return fix;
    }

    /// <summary>Maps a provider error message to a readable cause and a suggested fix.</summary>
    internal static PostmortemFinding ClassifyError(string text)
    {
        string first = FirstLine(text);
        int code = StatusCode.Match(text) is { Success: true } m ? int.Parse(m.Groups["code"].Value, CultureInfo.InvariantCulture) : 0;
        bool Has(string pattern) => Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase);

        if (Has("Cannot reach the MCP toolbox"))
            return new("the MCP toolbox was unreachable", "start it: cd mcp; docker compose up --build");
        if (Has(@"No (Anthropic|Cursor AI) API key"))
            return new("no API key was set", "paste the key in the top bar");
        if (Has(@"No (Ollama )?model selected"))
            return new("no model was selected", "load a model and click 'fetch'");
        if (code == 401 || Has("authentication|invalid x-api-key|invalid api key"))
            return new($"authentication failed ({first})", "check the API key");
        if (code == 403 || Has("permission_error|forbidden"))
            return new($"permission denied ({first})", "check the key has access to this model");
        if (code == 429 || Has(@"rate.?limit"))
            return new($"rate limited ({first})", "wait and retry; fewer parallel tools or a smaller prompt also help");
        if (code == 529 || Has("overloaded"))
            return new($"the provider was overloaded ({first})", "retry in a few minutes");
        if (code >= 500)
            return new($"the provider had a server error ({first})", "retry; if it persists, check the provider's status");
        if (Has(@"prompt is too long|context length|context window|too many tokens"))
            return new($"the prompt was too large ({first})", "attach fewer or smaller files, or clear the conversation");
        if (code == 400)
            return new($"the request was rejected ({first})", "check the model name and attachment sizes");
        if (Has(@"Cannot reach (Ollama|LM Studio)|actively refused|No connection could be made|No such host|Name or service not known"))
            return new($"the model server was unreachable ({first})", "make sure the local server is running and the host is correct");
        if (Has("empty stream"))
            return new($"the model returned nothing ({first})", "make sure a chat (not embedding) model is loaded");
        if (Has(@"timed out|timeout"))
            return new($"a request timed out ({first})", "retry; a slow local model may need a smaller prompt");
        return new($"provider error: {first}");
    }

    // ── Flag extraction ─────────────────────────────────────────────────────

    /// <summary>
    /// Picks the reported flag from an answer -- preferring the FLAG section and flag-like
    /// prefixes (flag{, picoCTF{, ...) -- and looks for it in the tool outputs.
    /// </summary>
    private static (string? flag, string? evidence) FindFlag(string answer, List<LogEntry> toolOutputs)
    {
        string? flag = PickFlag(answer);
        if (flag is null) return (null, null);

        var hit = toolOutputs.FirstOrDefault(e => e.Text.Contains(flag, StringComparison.Ordinal));
        return (flag, hit is null ? null : $"seen in output of {hit.Value ?? "a tool"} at {hit.Time:HH:mm:ss}");
    }

    internal static string? PickFlag(string answer)
    {
        string? section = FlagSection(answer);
        if (section is not null)
        {
            var inSection = Candidates(section).ToList();
            var pick = inSection.FirstOrDefault(IsFlagish) ?? inSection.FirstOrDefault();
            if (pick is not null) return pick;
        }
        // Outside the FLAG section only trust flag-like prefixes, so code such as byte{0x41}
        // in a solution script isn't mistaken for the flag.
        return Candidates(answer).FirstOrDefault(IsFlagish);
    }

    private static bool IsFlagish(string candidate) => FlagishPrefix.IsMatch(candidate[..candidate.IndexOf('{')]);

    private static IEnumerable<string> Candidates(string text)
    {
        foreach (Match m in FlagPattern.Matches(text))
        {
            string body = m.Value[(m.Value.IndexOf('{') + 1)..^1].Trim();
            if (!Placeholder.IsMatch(body)) yield return m.Value;
        }
    }

    /// <summary>The text of the answer's FLAG section (inline header text included), or null.</summary>
    internal static string? FlagSection(string answer)
    {
        var header = FlagHeader.Match(answer);
        if (!header.Success) return null;

        int bodyStart = header.Index + header.Length;
        var next = NextHeader.Match(answer, bodyStart);
        string body = answer[bodyStart..(next.Success ? next.Index : answer.Length)];
        return (header.Groups["rest"].Value + "\n" + body).Trim();
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    /// <summary>Appends the plain-text POSTMORTEM block for <paramref name="pm"/> to <paramref name="sb"/>.</summary>
    public static void Render(Postmortem pm, StringBuilder sb)
    {
        sb.AppendLine(new string('=', 64));
        sb.AppendLine("POSTMORTEM");
        if (pm.Runs.Count == 0)
        {
            sb.AppendLine("(no runs recorded)");
            return;
        }

        foreach (var r in pm.Runs)
        {
            sb.AppendLine();
            sb.AppendLine($"Run {r.Number} ({r.Kind})  {Label(r.Verdict)}");
            sb.AppendLine($"  stats   : {Stats(r)}");
            if (r.Flag is not null)
                sb.AppendLine($"  flag    : {r.Flag}");
            if (r.FlagEvidence is not null)
                sb.AppendLine($"  evidence: {r.FlagEvidence}");
            foreach (var f in r.Findings)
            {
                sb.AppendLine($"  - {f.Cause}");
                if (f.Fix is not null)
                    sb.AppendLine($"    fix: {f.Fix}");
            }
        }

        sb.AppendLine();
        sb.AppendLine(pm.OverallRun is int n
            ? $"Overall : {Label(pm.Overall)} (run {n})"
            : $"Overall : {Label(pm.Overall)}");
    }

    public static string Label(RunVerdict v) => v switch
    {
        RunVerdict.Solved           => "SOLVED (verified)",
        RunVerdict.SolvedUnverified => "SOLVED (unverified)",
        RunVerdict.Partial          => "PARTIAL",
        RunVerdict.Answered         => "ANSWERED",
        RunVerdict.Stopped          => "STOPPED",
        RunVerdict.TimedOut         => "TIMED OUT",
        RunVerdict.Failed           => "FAILED",
        _                           => "NO OUTCOME",
    };

    private static string Stats(RunPostmortem r)
    {
        var parts = new List<string> { Format(r.Duration), r.AgentMode ? "agent mode" : "chat mode" };
        if (r.AgentMode)
        {
            parts.Add($"{r.Iterations} iteration{(r.Iterations == 1 ? "" : "s")}");
            parts.Add($"{r.ToolCalls} tool call{(r.ToolCalls == 1 ? "" : "s")} ({r.DistinctTools} distinct, {r.ToolErrors} failed)");
        }
        if (r.Tokens > 0)
            parts.Add($"{r.Tokens.ToString("N0", CultureInfo.InvariantCulture)} tokens");
        return string.Join(", ", parts);
    }

    private static string Format(TimeSpan? t)
    {
        if (t is not { } d) return "?";
        if (d.TotalSeconds < 60) return $"{d.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)}s";
        if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes}m{d.Seconds:00}s";
        return $"{(int)d.TotalHours}h{d.Minutes:00}m";
    }

    private static string LastActivity(List<LogEntry> run, LogEntry outcome)
    {
        var last = run.LastOrDefault(e => e.Category == LogCategory.Agent && e.Time <= outcome.Time);
        return last is null ? "" : $" (last event: {Truncate(FirstLine(last.Text), 80)})";
    }

    private static string FirstLine(string text)
    {
        text = text.Trim();
        int nl = text.IndexOf('\n');
        return (nl < 0 ? text : text[..nl]).TrimEnd('\r');
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}
