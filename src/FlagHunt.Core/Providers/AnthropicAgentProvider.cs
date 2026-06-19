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

    public string DisplayName => "claude (agent)";

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default)
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

                var toolResults = new JsonArray();
                foreach (var block in content)
                {
                    if ((string?)block!["type"] != "tool_use")
                        continue;

                    string name = (string)block["name"]!;
                    string id = (string)block["id"]!;
                    var input = block["input"]!.AsObject();
                    var args = input.ToDictionary(kv => kv.Key, kv => (object?)kv.Value?.DeepClone());

                    progress?.Report(AgentActivity.ToolCall($"{name}({Summarize(input)})"));

                    string output;
                    try
                    {
                        output = await toolbox.CallAsync(name, args, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        output = $"tool error: {ex.Message}";
                    }

                    progress?.Report(AgentActivity.ToolResult(Preview(output)));

                    toolResults.Add(new JsonObject
                    {
                        ["type"] = "tool_result",
                        ["tool_use_id"] = id,
                        ["content"] = output,
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
        var body = new JsonObject
        {
            ["model"] = options.Model,
            ["max_tokens"] = options.MaxTokens,
            ["system"] = system,
            ["messages"] = messages.DeepClone(),
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
