namespace FlagHunt.Core.Providers;

public sealed record AnthropicOptions(string ApiKey)
{
    public string Model { get; init; } = "claude-sonnet-4-20250514";
    public int MaxTokens { get; init; } = 8192;
}

public sealed record OllamaOptions(string Host, string Model)
{
    public int NumPredict { get; init; } = 8192;
    public double Temperature { get; init; } = 0.7;
}

public sealed record CursorOptions(string ApiKey, string Model)
{
    public int MaxTokens { get; init; } = 8192;
    public double Temperature { get; init; } = 0.7;
}
