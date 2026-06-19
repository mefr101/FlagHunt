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
/// A live event emitted during an agentic run so the frontend can show the model's
/// tool calls as they happen. Purely presentational -- the final answer is still the
/// <see cref="ChatResult"/> returned by the provider.
/// </summary>
public sealed record AgentActivity(AgentActivityKind Kind, string Text)
{
    public static AgentActivity Info(string text) => new(AgentActivityKind.Info, text);
    public static AgentActivity ToolCall(string text) => new(AgentActivityKind.ToolCall, text);
    public static AgentActivity ToolResult(string text) => new(AgentActivityKind.ToolResult, text);
}
