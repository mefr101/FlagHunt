namespace FlagHunt.Core;

/// <summary>The AI backend the solver talks to.</summary>
public enum ProviderKind
{
    Anthropic,
    Ollama,
    Cursor
}

/// <summary>A single turn in the conversation sent to / received from a provider.</summary>
public sealed record ChatMessage(string Role, string Content)
{
    public static ChatMessage User(string content) => new("user", content);
    public static ChatMessage Assistant(string content) => new("assistant", content);
}

/// <summary>A file the user attached to a challenge.</summary>
public sealed record Attachment(string Path, string Name);

/// <summary>A CTF category shown in the sidebar.</summary>
public sealed record CategoryInfo(string Label, string Value);

/// <summary>Result of a provider call. <see cref="Success"/> is false for any error.</summary>
public sealed record ChatResult(bool Success, string Text)
{
    public static ChatResult Ok(string text) => new(true, text);
    public static ChatResult Error(string text) => new(false, text);
}
