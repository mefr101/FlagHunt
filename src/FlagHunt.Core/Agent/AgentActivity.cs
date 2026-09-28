namespace FlagHunt.Core.Agent;

/// <summary>What an <see cref="AgentActivity"/> describes, for UI styling.</summary>
public enum AgentActivityKind
{
    /// <summary>A status note (connecting, tool count, iteration cap reached).</summary>
    Info,
    /// <summary>The model asked to run a tool.</summary>
    ToolCall,
    /// <summary>A tool returned output.</summary>
    ToolResult,
}

/// <summary>
/// Machine-readable meaning of a log event, so the <see cref="PostmortemAnalyzer"/> can reason
/// about a run without re-parsing display text. The UI ignores it; <see cref="None"/> is a
/// plain note.
/// </summary>
public enum LogSignal
{
    None,

    // Session milestones (logged by the frontend).
    /// <summary>A challenge or follow-up was submitted. Value = "challenge" | "follow-up"; Number = attachment count.</summary>
    RunStart,
    /// <summary>An attachment could not be staged into the toolbox workspace. Value = file name.</summary>
    StageFailed,

    // Agent loop (reported by the agent providers).
    /// <summary>Connecting to the MCP toolbox -- marks the run as an agent-mode run.</summary>
    AgentStart,
    /// <summary>The MCP toolbox could not be reached. Value = error message.</summary>
    McpUnreachable,
    /// <summary>A model round-trip is starting. Number = 1-based iteration.</summary>
    IterationStart,
    /// <summary>Token usage for one model round-trip. Number = input + output tokens.</summary>
    Usage,
    /// <summary>The model ended the loop. Value = stop/finish reason (end_turn, max_tokens, length, ...).</summary>
    StopReason,
    /// <summary>The loop hit its iteration cap. Number = the cap.</summary>
    IterationCap,
    /// <summary>A model request threw mid-loop. Value = error message.</summary>
    RequestFailed,
    /// <summary>A tool call was requested. Value = tool name; Text = name(args).</summary>
    ToolCall,
    /// <summary>A tool returned normally. Value = tool name.</summary>
    ToolOk,
    /// <summary>A tool returned an error. Value = tool name.</summary>
    ToolError,

    // Run outcomes (logged by the frontend).
    /// <summary>The provider returned an answer. Text = the answer.</summary>
    FinalAnswer,
    /// <summary>The provider returned an error. Text = the error.</summary>
    Error,
    /// <summary>The user pressed Stop. Text = any partial answer.</summary>
    Stopped,
    /// <summary>The safety timeout cancelled the run. Text = any partial answer.</summary>
    TimedOut,
}

/// <summary>
/// A live event emitted during an agentic run so the frontend can show the model's
/// tool calls as they happen. Purely presentational -- the final answer is still the
/// <see cref="ChatResult"/> returned by the provider. <see cref="Signal"/>,
/// <see cref="Value"/> and <see cref="Number"/> carry structured facts for the postmortem.
/// </summary>
public sealed record AgentActivity(AgentActivityKind Kind, string Text)
{
    public LogSignal Signal { get; init; }
    public string? Value { get; init; }
    public long Number { get; init; }

    public static AgentActivity Info(string text) => new(AgentActivityKind.Info, text);
    public static AgentActivity ToolCall(string text) => new(AgentActivityKind.ToolCall, text);
    public static AgentActivity ToolResult(string text) => new(AgentActivityKind.ToolResult, text);

    /// <summary>An info note carrying a structured signal.</summary>
    public static AgentActivity Signaled(LogSignal signal, string text, string? value = null, long number = 0)
        => new(AgentActivityKind.Info, text) { Signal = signal, Value = value, Number = number };

    /// <summary>A tool call, tagged with the tool name.</summary>
    public static AgentActivity Call(string tool, string text)
        => new(AgentActivityKind.ToolCall, text) { Signal = LogSignal.ToolCall, Value = tool };

    /// <summary>A tool result, tagged with the tool name and whether it failed.</summary>
    public static AgentActivity Result(string tool, string text, bool isError)
        => new(AgentActivityKind.ToolResult, text) { Signal = isError ? LogSignal.ToolError : LogSignal.ToolOk, Value = tool };
}
