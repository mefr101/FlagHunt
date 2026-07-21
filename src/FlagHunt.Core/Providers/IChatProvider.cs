namespace FlagHunt.Core.Providers;

/// <summary>A backend that can answer a CTF conversation.</summary>
public interface IChatProvider
{
    /// <summary>Display name used in the conversation role label (e.g. "claude", model name).</summary>
    string DisplayName { get; }

    /// <summary>
    /// Sends the history and returns the assistant reply, or an error result.
    /// If <paramref name="onToken"/> is supplied and the provider supports streaming, each
    /// text delta is reported as it arrives; the returned <see cref="ChatResult"/> still
    /// carries the full accumulated text. Providers that don't stream simply ignore it.
    /// </summary>
    Task<ChatResult> CompleteAsync(
        IReadOnlyList<ChatMessage> history,
        IProgress<string>? onToken = null,
        CancellationToken ct = default);
}
