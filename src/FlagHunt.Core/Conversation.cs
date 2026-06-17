namespace FlagHunt.Core;

/// <summary>Holds the running message history for a solving session.</summary>
public sealed class Conversation
{
    private readonly List<ChatMessage> _messages = [];

    public IReadOnlyList<ChatMessage> Messages => _messages;

    public void AddUser(string content) => _messages.Add(ChatMessage.User(content));

    public void AddAssistant(string content) => _messages.Add(ChatMessage.Assistant(content));

    /// <summary>Drops the most recent turn — used to roll back a user message whose reply failed.</summary>
    public void RemoveLast()
    {
        if (_messages.Count > 0) _messages.RemoveAt(_messages.Count - 1);
    }

    public void Clear() => _messages.Clear();
}
