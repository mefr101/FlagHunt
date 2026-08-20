namespace FlagHunt.Core.Providers;

public sealed record AnthropicOptions(string ApiKey)
{
    public string Model { get; init; } = "claude-sonnet-4-20250514";
    public int MaxTokens { get; init; } = 8192;

    /// <summary>When true, Claude runs as an agent with the MCP toolbox tools available.</summary>
    public bool UseTools { get; init; }

    /// <summary>Streamable-HTTP endpoint of the CTF MCP toolbox (see <c>mcp/docker-compose.yml</c>).</summary>
    public string McpUrl { get; init; } = "http://localhost:8000/mcp";

    /// <summary>Safety cap on agent loop iterations (model turns that request tools).</summary>
    public int MaxToolIterations { get; init; } = 25;

    /// <summary>Selected CTF category; filters which toolbox tools are offered to the model.</summary>
    public string Category { get; init; } = "auto";
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

public sealed record LmStudioOptions(string Host, string Model)
{
    public int MaxTokens { get; init; } = 8192;
    public double Temperature { get; init; } = 0.7;

    /// <summary>When true, the local model runs as an agent with the MCP toolbox tools available.</summary>
    public bool UseTools { get; init; }

    /// <summary>Streamable-HTTP endpoint of the CTF MCP toolbox (see <c>mcp/docker-compose.yml</c>).</summary>
    public string McpUrl { get; init; } = "http://localhost:8000/mcp";

    /// <summary>Safety cap on agent loop iterations (model turns that request tools).</summary>
    public int MaxToolIterations { get; init; } = 25;

    /// <summary>Selected CTF category; filters which toolbox tools are offered to the model.</summary>
    public string Category { get; init; } = "auto";
}
