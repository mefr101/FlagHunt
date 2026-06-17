namespace FlagHunt.Core.Providers;

/// <summary>A backend that can answer a CTF conversation.</summary>
public interface IChatProvider
{
    /// <summary>Display name used in the conversation role label (e.g. "claude", model name).</summary>
    string DisplayName { get; }

    /// <summary>Sends the history and returns the assistant reply, or an error result.</summary>
    Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default);
}
