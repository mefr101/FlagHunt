using FlagHunt.Core.Agent;

namespace FlagHunt.Core.Tests;

/// <summary>
/// Fluent builder for synthetic session logs, shaped like what the frontend and agent
/// providers record. Each entry is stamped one second after the previous one.
/// </summary>
internal sealed class LogBuilder
{
    private static readonly DateTimeOffset Start = new(2026, 9, 28, 12, 0, 0, TimeSpan.Zero);
    private readonly List<LogEntry> _entries = [];

    public IReadOnlyList<LogEntry> Entries => _entries;

    public LogBuilder Challenge(int attachments = 0)
        => Add(LogCategory.Session, $"Challenge submitted (attachments={attachments})", LogSignal.RunStart, "challenge", attachments);

    public LogBuilder FollowUp() => Add(LogCategory.Session, "Follow-up: explain", LogSignal.RunStart, "follow-up");

    public LogBuilder Agent() => Signal(LogSignal.AgentStart, "connecting to MCP toolbox ...");

    public LogBuilder Iteration(int n) => Signal(LogSignal.IterationStart, $"-- iteration {n} --", number: n);

    public LogBuilder Usage(long tokens) => Signal(LogSignal.Usage, $"usage: {tokens}", number: tokens);

    public LogBuilder Stop(string reason) => Signal(LogSignal.StopReason, $"stop reason: {reason}", reason);

    public LogBuilder Call(string tool, string args)
        => Add(LogCategory.Agent, $"{tool}({args})", LogSignal.ToolCall, tool, kind: AgentActivityKind.ToolCall);

    public LogBuilder ToolOk(string tool, string output)
        => Add(LogCategory.Agent, output, LogSignal.ToolOk, tool, kind: AgentActivityKind.ToolResult);

    public LogBuilder ToolError(string tool, string output)
        => Add(LogCategory.Agent, output, LogSignal.ToolError, tool, kind: AgentActivityKind.ToolResult);

    public LogBuilder Signal(LogSignal signal, string text, string? value = null, long number = 0)
        => Add(LogCategory.Agent, text, signal, value, number);

    public LogBuilder Final(string answer) => Add(LogCategory.Result, answer, LogSignal.FinalAnswer);

    public LogBuilder Error(string error) => Add(LogCategory.Result, error, LogSignal.Error);

    public LogBuilder Outcome(LogSignal signal, string text) => Add(LogCategory.Result, text, signal);

    private LogBuilder Add(LogCategory category, string text, LogSignal signal, string? value = null, long number = 0,
                           AgentActivityKind kind = AgentActivityKind.Info)
    {
        _entries.Add(new LogEntry(Start.AddSeconds(_entries.Count), category, kind, text)
        {
            Signal = signal, Value = value, Number = number,
        });
        return this;
    }
}
