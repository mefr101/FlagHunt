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

    /// <summary>Translates the given tools (or all discovered tools) into the Anthropic
    /// Messages API tool schema.</summary>
    public JsonArray ToAnthropicTools(IEnumerable<McpClientTool>? tools = null)
    {
        var arr = new JsonArray();
        foreach (var tool in tools ?? Tools)
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

    /// <summary>Translates the given tools (or all discovered tools) into the OpenAI
    /// chat-completions tool schema (used by LM Studio and other OpenAI-compatible servers).</summary>
    public JsonArray ToOpenAiTools(IEnumerable<McpClientTool>? tools = null)
    {
        var arr = new JsonArray();
        foreach (var tool in tools ?? Tools)
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

    // ── Category filtering ──────────────────────────────────────────────────
    // The expanded toolbox exposes ~130 tools; handing all of them to the model every
    // request bloats prefill and degrades local models. Filter to the tools relevant to
    // the chosen CTF category (plus a universal core), keyed off the server's tool-name
    // prefixes (red_/blue_/pwn_/web_/re_/net_/osint_/forens_).

    /// <summary>Triage + common decoders included for every category.</summary>
    private static readonly string[] CoreTools =
    {
        "list_workspace", "file_type", "strings_extract",
        "base64_decode", "base64_encode", "hex_decode", "url_decode",
        "rot13", "identify_hash", "hash_text",
    };

    /// <summary>Category value → (tool-name prefixes, explicit extra names) added on top of the core.</summary>
    private static readonly Dictionary<string, (string[] Prefixes, string[] Names)> CategoryMap =
        new(StringComparer.OrdinalIgnoreCase)
    {
        ["web"]           = (new[] { "web_", "red_" }, new[] { "jwt_decode", "http_fetch" }),
        ["crypto"]        = (Array.Empty<string>(),    new[] { "xor_hex", "caesar_bruteforce", "red_hash_crack", "red_jwt_forge", "jwt_decode" }),
        ["pwn"]           = (new[] { "pwn_" },         new[] { "disassemble", "checksec", "cyclic_pattern", "cyclic_find" }),
        ["reversing"]     = (new[] { "re_" },          new[] { "disassemble", "checksec", "cyclic_pattern", "cyclic_find" }),
        ["forensics"]     = (new[] { "forens_", "blue_" }, new[] { "binwalk_scan", "exif_metadata", "steghide_extract", "zsteg_scan", "wav_lsb_extract", "pcap_overview", "pcap_follow_stream" }),
        ["steganography"] = (Array.Empty<string>(),    new[] { "zsteg_scan", "wav_lsb_extract", "steghide_extract", "exif_metadata", "binwalk_scan", "forens_steghide_extract", "forens_steghide_bruteforce", "forens_zsteg_scan", "forens_image_lsb", "forens_audio_spectrogram", "forens_exif_full", "forens_carve_files", "forens_extract_chunk" }),
        ["osint"]         = (new[] { "osint_" },       Array.Empty<string>()),
        ["networking"]    = (new[] { "net_" },         new[] { "pcap_overview", "pcap_follow_stream" }),
    };

    /// <summary>Broad cross-domain triage set for "auto" / "misc" — enough to identify and
    /// make progress on most challenges without the whole 130-tool surface.</summary>
    private static readonly string[] AutoTools =
    {
        "list_workspace", "file_type", "strings_extract", "binwalk_scan", "exif_metadata",
        "base64_decode", "hex_decode", "url_decode", "rot13", "xor_hex", "caesar_bruteforce",
        "identify_hash", "hash_text",
        "zsteg_scan", "wav_lsb_extract", "steghide_extract",
        "disassemble", "checksec", "cyclic_pattern", "cyclic_find",
        "jwt_decode", "http_fetch",
        "pcap_overview", "pcap_follow_stream",
    };

    /// <summary>Selects the discovered tools relevant to a CTF category (plus the universal
    /// core). "auto"/"misc"/unknown categories get the broad triage set. If nothing matches
    /// (e.g. a slimmed server whose names differ), falls back to every tool.</summary>
    public IReadOnlyList<McpClientTool> ToolsForCategory(string category)
    {
        var wanted = new HashSet<string>(CoreTools, StringComparer.OrdinalIgnoreCase);

        if (CategoryMap.TryGetValue(category, out var map))
        {
            foreach (var name in map.Names) wanted.Add(name);
            var selected = Tools.Where(t =>
                wanted.Contains(t.Name) ||
                map.Prefixes.Any(p => t.Name.StartsWith(p, StringComparison.OrdinalIgnoreCase))).ToList();
            return selected.Count > 0 ? selected : Tools;
        }

        foreach (var name in AutoTools) wanted.Add(name);
        var triage = Tools.Where(t => wanted.Contains(t.Name)).ToList();
        return triage.Count > 0 ? triage : Tools;
    }

    /// <summary>Prefix marking a tool output as a failure (from the toolbox or the agent loop).</summary>
    public const string ErrorPrefix = "tool error: ";

    /// <summary>True when <paramref name="output"/> is a tool failure rather than real output.</summary>
    public static bool IsError(string output) => output.StartsWith(ErrorPrefix, StringComparison.Ordinal);

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

        return result.IsError == true ? ErrorPrefix + text : text;
    }

    public ValueTask DisposeAsync() => _client.DisposeAsync();
}
