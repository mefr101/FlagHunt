using System.Text;

namespace FlagHunt.Core.Agent;

/// <summary>Which phase of a run a <see cref="LogEntry"/> belongs to.</summary>
public enum LogCategory
{
    /// <summary>Session milestones: provider/category chosen, challenge submitted, follow-up.</summary>
    Session,
    /// <summary>The agent's live activity stream: tool calls, results, reasoning, status.</summary>
    Agent,
    /// <summary>Run outcomes: final answer, error, stopped/cancelled.</summary>
    Result,
}

/// <summary>One timestamped line in the <see cref="SessionEventLog"/>.</summary>
public sealed record LogEntry(DateTimeOffset Time, LogCategory Category, AgentActivityKind Kind, string Text);

/// <summary>
/// Records a timestamped trail of agent decisions and results across a session so it can be
/// exported to a plain-text file. Backend-only (no UI dependency): the frontend feeds it the
/// same <see cref="AgentActivity"/> events it renders live, plus session milestones and
/// outcomes, then calls <see cref="Render"/> when the user saves the log. Thread-safe because
/// tool calls in a turn run concurrently and may report from pool threads.
/// </summary>
public sealed class SessionEventLog
{
    private readonly object _gate = new();
    private readonly List<LogEntry> _entries = new();
    private DateTimeOffset _started = DateTimeOffset.Now;

    /// <summary>Number of recorded entries.</summary>
    public int Count { get { lock (_gate) return _entries.Count; } }

    /// <summary>Appends one entry, stamped with the current time.</summary>
    public void Log(LogCategory category, string text, AgentActivityKind kind = AgentActivityKind.Info)
    {
        lock (_gate) _entries.Add(new LogEntry(DateTimeOffset.Now, category, kind, text ?? ""));
    }

    /// <summary>Records a live agent event under the <see cref="LogCategory.Agent"/> phase.</summary>
    public void LogActivity(AgentActivity a) => Log(LogCategory.Agent, a.Text, a.Kind);

    /// <summary>Drops all entries and restarts the session clock (used when the session is cleared).</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _started = DateTimeOffset.Now;
        }
    }

    /// <summary>
    /// Renders the whole trail as a plain-text report: a header block (optionally with the
    /// supplied provider/category/mode fields) followed by one aligned, timestamped line per
    /// event. Multi-line event text (e.g. a tool result) is indented under its first line.
    /// </summary>
    public string Render(IReadOnlyList<KeyValuePair<string, string>>? header = null)
    {
        LogEntry[] snapshot;
        DateTimeOffset started;
        lock (_gate)
        {
            snapshot = _entries.ToArray();
            started = _started;
        }

        var sb = new StringBuilder();
        sb.AppendLine("FlagHunt session log");
        sb.AppendLine($"{"Session started",-16}: {started:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"{"Exported",-16}: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss}");
        if (header is not null)
            foreach (var kv in header)
                sb.AppendLine($"{kv.Key,-16}: {kv.Value}");
        sb.AppendLine(new string('-', 64));

        if (snapshot.Length == 0)
        {
            sb.AppendLine("(no events recorded)");
            return sb.ToString();
        }

        // Column widths: "[HH:mm:ss.fff] " = 15 chars, then a 7-char category tag and a
        // 2-char arrow, so continuation lines line up under the first line's text.
        const int indent = 15 + 7 + 1 + 2 + 1;
        string pad = new(' ', indent);

        foreach (var e in snapshot)
        {
            string arrow = e.Kind switch
            {
                AgentActivityKind.ToolCall   => "->",
                AgentActivityKind.ToolResult => "<-",
                _                            => "  ",
            };
            string tag = e.Category.ToString().ToUpperInvariant();

            string[] lines = e.Text.Replace("\r\n", "\n").Split('\n');
            sb.AppendLine($"[{e.Time:HH:mm:ss.fff}] {tag,-7} {arrow} {lines[0]}");
            for (int i = 1; i < lines.Length; i++)
                sb.AppendLine(pad + lines[i]);
        }

        return sb.ToString();
    }
}
