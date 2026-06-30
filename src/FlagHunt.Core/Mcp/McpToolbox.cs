using System.Text.Json.Nodes;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace FlagHunt.Core.Mcp;

/// <summary>
/// A connection to the containerised CTF MCP toolbox (FastMCP / Streamable HTTP).
/// Discovers the tools the server exposes and lets the agent loop invoke them.
/// The toolbox has no model and no loop -- it is just a sandboxed set of utilities;
/// the agent loop in <see cref="Providers.AnthropicAgentProvider"/> decides what to call.
/// </summary>
public sealed class McpToolbox : IAsyncDisposable
{
    private readonly McpClient _client;

    /// <summary>The tools the server advertised, in discovery order.</summary>
    public IReadOnlyList<McpClientTool> Tools { get; }

    private McpToolbox(McpClient client, IReadOnlyList<McpClientTool> tools)
    {
        _client = client;
        Tools = tools;
    }

    /// <summary>Connects to the MCP endpoint and lists its tools.</summary>
    public static async Task<McpToolbox> ConnectAsync(string url, CancellationToken ct = default)
    {
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = new Uri(url),
            Name = "ctf-toolbox",
            TransportMode = HttpTransportMode.AutoDetect,
        });

        var client = await McpClient.CreateAsync(transport, cancellationToken: ct).ConfigureAwait(false);
        var tools = await client.ListToolsAsync(cancellationToken: ct).ConfigureAwait(false);
        return new McpToolbox(client, tools.ToList());
    }

    /// <summary>Translates the discovered tools into the Anthropic Messages API tool schema.</summary>
    public JsonArray ToAnthropicTools()
    {
        var arr = new JsonArray();
        foreach (var tool in Tools)
        {
            arr.Add(new JsonObject
            {
                ["name"] = tool.Name,
                ["description"] = tool.Description ?? "",
                ["input_schema"] = JsonNode.Parse(tool.JsonSchema.GetRawText()),
            });
        }
        return arr;
    }

    /// <summary>Translates the discovered tools into the OpenAI chat-completions tool schema
    /// (used by LM Studio and other OpenAI-compatible servers).</summary>
    public JsonArray ToOpenAiTools()
    {
        var arr = new JsonArray();
        foreach (var tool in Tools)
        {
            arr.Add(new JsonObject
            {
                ["type"] = "function",
                ["function"] = new JsonObject
                {
                    ["name"] = tool.Name,
                    ["description"] = tool.Description ?? "",
                    ["parameters"] = JsonNode.Parse(tool.JsonSchema.GetRawText()),
                },
            });
        }
        return arr;
    }

    /// <summary>Runs a single tool and returns its combined text output.</summary>
    public async Task<string> CallAsync(string name, IReadOnlyDictionary<string, object?> arguments, CancellationToken ct = default)
    {
        var tool = Tools.FirstOrDefault(t => t.Name == name)
                   ?? throw new InvalidOperationException($"unknown tool: {name}");

        CallToolResult result = await tool.CallAsync(arguments, cancellationToken: ct).ConfigureAwait(false);

        string text = string.Join("\n", result.Content
            .OfType<TextContentBlock>()
            .Select(c => c.Text));

        if (string.IsNullOrEmpty(text))
            text = "[tool returned no text content]";

        return result.IsError == true ? $"tool error: {text}" : text;
    }

    public ValueTask DisposeAsync() => _client.DisposeAsync();
}
