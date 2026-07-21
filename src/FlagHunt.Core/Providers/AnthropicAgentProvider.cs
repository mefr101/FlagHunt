using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FlagHunt.Core.Agent;
using FlagHunt.Core.Mcp;

namespace FlagHunt.Core.Providers;

/// <summary>
/// Claude running as an agent: it discovers the CTF toolbox tools over MCP and drives
/// a tool-use loop -- call the model, run whatever tools it asks for, feed the results
/// back, repeat until it stops. Implements <see cref="IChatProvider"/> so the frontend
/// can swap it in for the plain Anthropic provider; <paramref name="progress"/> surfaces
/// each tool call live while the final write-up comes back as the <see cref="ChatResult"/>.
/// </summary>
public sealed class AnthropicAgentProvider(
    HttpClient http,
    AnthropicOptions options,
    IProgress<AgentActivity>? progress = null) : IChatProvider
{
    private const int ResultPreviewChars = 600;

    /// <summary>Cap on tool calls dispatched concurrently within a single model turn.</summary>
    private const int MaxParallelTools = 4;

    public string DisplayName => "claude (agent)";

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
    {
        string key = options.ApiKey.Trim();
        if (string.IsNullOrEmpty(key))
            return ChatResult.Error("No Anthropic API key. Paste it in the top bar.");

        McpToolbox toolbox;
        try
        {
            progress?.Report(AgentActivity.Info($"connecting to MCP toolbox at {options.McpUrl} ..."));
            toolbox = await McpToolbox.ConnectAsync(options.McpUrl, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return ChatResult.Error(
                $"Cannot reach the MCP toolbox at {options.McpUrl}\n\n" +
                "Start it first:\n  cd mcp\n  docker compose up --build\n\n" +
                $"Error: {ex.Message}");
        }

        await using (toolbox)
        {
            var tools = toolbox.ToAnthropicTools();
            progress?.Report(AgentActivity.Info(
                $"{toolbox.Tools.Count} tools ready: {string.Join(", ", toolbox.Tools.Select(t => t.Name))}"));

            var messages = new JsonArray();
            foreach (var m in history)
                messages.Add(new JsonObject { ["role"] = m.Role, ["content"] = m.Content });

            string system = CtfKnowledge.SystemPrompt + CtfKnowledge.AgentSystemAddendum;
            var finalText = new StringBuilder();

            for (int iteration = 0; ; iteration++)
            {
                if (iteration >= options.MaxToolIterations)
                {
                    progress?.Report(AgentActivity.Info(
                        $"reached the {options.MaxToolIterations}-iteration tool cap; stopping."));
                    finalText.Append("\n\n[Agent stopped after the tool-iteration cap was reached.]");
                    break;
                }

                JsonObject response;
                try
                {
                    response = await SendAsync(system, messages, tools, key, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    return finalText.Length > 0
                        ? ChatResult.Ok(finalText + $"\n\n[Run interrupted: {ex.Message}]")
                        : ChatResult.Error($"Request failed: {ex.Message}");
                }

                var content = response["content"]?.AsArray();
                if (content is null)
                    return ChatResult.Error($"API Error: {ExtractError(response)}");

                foreach (var block in content)
                {
                    if ((string?)block!["type"] == "text")
                    {
                        string text = (string?)block["text"] ?? "";
                        if (finalText.Length > 0) finalText.Append("\n\n");
                        finalText.Append(text);
                    }
                }

                // Record the assistant turn verbatim so tool_use ids line up next turn.
                messages.Add(new JsonObject { ["role"] = "assistant", ["content"] = content.DeepClone() });

                if ((string?)response["stop_reason"] != "tool_use")
                    break; // nothing more to call -- we're done.

                // Collect the tool_use blocks in order so results line up with their ids.
                var calls = content
                    .Where(b => (string?)b!["type"] == "tool_use")
                    .Select(b => (
                        id: (string)b!["id"]!,
                        name: (string)b["name"]!,
                        input: b["input"]!.AsObject()))
                    .ToList();

                foreach (var c in calls)
                    progress?.Report(AgentActivity.ToolCall($"{c.name}({Summarize(c.input)})"));

                // Run the turn's tool calls concurrently (capped) -- most CTF tools are
                // independent, so this collapses an N-tool turn from sum- to max-latency.
                // The MCP server handles concurrent requests; the cap keeps a wide fan-out
                // from thrashing the container's CPU/PID limits (see mcp/docker-compose.yml).
                using var gate = new SemaphoreSlim(MaxParallelTools);
                string[] outputs = await Task.WhenAll(calls.Select(async c =>
                {
                    await gate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        var args = c.input.ToDictionary(kv => kv.Key, kv => (object?)kv.Value?.DeepClone());
                        return await toolbox.CallAsync(c.name, args, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        return $"tool error: {ex.Message}";
                    }
                    finally
                    {
                        gate.Release();
                    }
                })).ConfigureAwait(false);

                var toolResults = new JsonArray();
                for (int i = 0; i < calls.Count; i++)
                {
                    progress?.Report(AgentActivity.ToolResult(Preview(outputs[i])));
                    toolResults.Add(new JsonObject
                    {
                        ["type"] = "tool_result",
                        ["tool_use_id"] = calls[i].id,
                        ["content"] = outputs[i],
                    });
                }

                messages.Add(new JsonObject { ["role"] = "user", ["content"] = toolResults });
            }

            return ChatResult.Ok(finalText.Length > 0
                ? finalText.ToString()
                : "[The agent finished without producing a text answer.]");
        }
    }

    /// <summary>One round-trip to the Anthropic Messages API with the toolbox tools attached.</summary>
    private async Task<JsonObject> SendAsync(string system, JsonArray messages, JsonArray tools, string key, CancellationToken ct)
    {
        // Prompt caching (GA -- no beta header). Render order is tools -> system -> messages,
        // so a cache_control breakpoint on the last system block caches the whole static
        // tools+system prefix; a second breakpoint on the last message caches the growing
        // conversation. Both are ephemeral (5-min TTL). The static prefix (system + the ~21
        // tool schemas) is resent every iteration, so this is the loop's biggest cost saving.
        var msgs = messages.DeepClone()!.AsArray();
        MarkConversationCacheBreakpoint(msgs);

        var body = new JsonObject
        {
            ["model"] = options.Model,
            ["max_tokens"] = options.MaxTokens,
            ["system"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "text",
                    ["text"] = system,
                    ["cache_control"] = new JsonObject { ["type"] = "ephemeral" },
                }
            },
            ["messages"] = msgs,
            ["tools"] = tools.DeepClone(),
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("x-api-key", key);
        req.Headers.Add("anthropic-version", "2023-06-01");

        var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"Anthropic API {(int)resp.StatusCode}: {ExtractErrorJson(json)}");

        return (JsonObject)JsonNode.Parse(json)!;
    }

    /// <summary>Attaches an ephemeral cache breakpoint to the last content block of the last
    /// message so the conversation prefix is cached across agent-loop iterations. Operates on a
    /// clone -- the persistent history stays unmarked so successive clones hash deterministically
    /// and breakpoints never accumulate past the 4-per-request cap.</summary>
    private static void MarkConversationCacheBreakpoint(JsonArray messages)
    {
        if (messages.Count == 0) return;
        var last = messages[^1]!.AsObject();

        JsonArray blocks;
        if (last["content"] is JsonArray arr)
        {
            blocks = arr;
        }
        else
        {
            // Plain-string content -> wrap as a single text block so cache_control has a home.
            blocks = new JsonArray { new JsonObject { ["type"] = "text", ["text"] = (string?)last["content"] ?? "" } };
            last["content"] = blocks;
        }

        if (blocks.Count == 0) return;
        blocks[^1]!.AsObject()["cache_control"] = new JsonObject { ["type"] = "ephemeral" };
    }

    private static string Summarize(JsonObject input)
    {
        var parts = input.Select(kv =>
        {
            string v = kv.Value?.ToJsonString() ?? "null";
            if (v.Length > 80) v = v[..80] + "...\"";
            return $"{kv.Key}={v}";
        });
        return string.Join(", ", parts);
    }

    private static string Preview(string output)
    {
        output = output.Trim();
        return output.Length > ResultPreviewChars
            ? output[..ResultPreviewChars] + $"\n... [{output.Length - ResultPreviewChars} more chars]"
            : output;
    }

    private static string ExtractError(JsonObject response)
    {
        try { return response["error"]?["message"]?.GetValue<string>() ?? response.ToJsonString(); }
        catch { return response.ToJsonString(); }
    }

    private static string ExtractErrorJson(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
