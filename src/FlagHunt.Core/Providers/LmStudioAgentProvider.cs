using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FlagHunt.Core.Agent;
using FlagHunt.Core.Mcp;

namespace FlagHunt.Core.Providers;

/// <summary>
/// A local LM Studio model running as an agent: it discovers the CTF toolbox tools over
/// MCP and drives an OpenAI-style tool-call loop -- call the model, run whatever tools it
/// asks for, feed the results back, repeat until it stops. Implements <see cref="IChatProvider"/>
/// so the frontend can swap it in for the plain LM Studio provider; <paramref name="progress"/>
/// surfaces each tool call live while the final write-up comes back as the <see cref="ChatResult"/>.
///
/// Tool calling only works with function-calling-capable models loaded in LM Studio
/// (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct). A model without that support will simply
/// never emit tool calls and the run degrades to a plain chat answer.
/// </summary>
public sealed class LmStudioAgentProvider(
    HttpClient http,
    LmStudioOptions options,
    IProgress<AgentActivity>? progress = null) : IChatProvider
{
    private const int ResultPreviewChars = 600;

    /// <summary>Cap on tool calls dispatched concurrently within a single model turn.</summary>
    private const int MaxParallelTools = 4;

    public string DisplayName => string.IsNullOrWhiteSpace(options.Model) ? "lm-studio (agent)" : $"{options.Model} (agent)";

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
    {
        string host = options.Host.TrimEnd('/');
        string model = options.Model.Trim();
        if (string.IsNullOrEmpty(model))
            return ChatResult.Error("No model selected. Load a model in LM Studio and click 'fetch'.");

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
            var selected = toolbox.ToolsForCategory(options.Category);
            var tools = toolbox.ToOpenAiTools(selected);
            progress?.Report(AgentActivity.Info(
                $"{selected.Count}/{toolbox.Tools.Count} tools for '{options.Category}': " +
                string.Join(", ", selected.Select(t => t.Name))));

            // OpenAI-style chat has no top-level system field: the system prompt is the
            // first message in the array.
            string system = CtfKnowledge.SystemPrompt + CtfKnowledge.AgentSystemAddendum;
            var messages = new JsonArray
            {
                new JsonObject { ["role"] = "system", ["content"] = system }
            };
            foreach (var m in history)
                messages.Add(new JsonObject { ["role"] = m.Role, ["content"] = m.Content });

            var finalText = new StringBuilder();
            bool sawAnyToolCall = false;

            for (int iteration = 0; ; iteration++)
            {
                if (iteration >= options.MaxToolIterations)
                {
                    progress?.Report(AgentActivity.Info(
                        $"reached the {options.MaxToolIterations}-iteration tool cap; stopping."));
                    finalText.Append("\n\n[Agent stopped after the tool-iteration cap was reached.]");
                    break;
                }

                progress?.Report(AgentActivity.Info($"-- iteration {iteration + 1} --"));

                JsonObject response;
                try
                {
                    response = await SendAsync(messages, tools, host, model, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    return finalText.Length > 0
                        ? ChatResult.Ok(finalText + $"\n\n[Run interrupted: {ex.Message}]")
                        : ChatResult.Error($"Request failed: {ex.Message}");
                }

                var choices = response["choices"]?.AsArray();
                if (choices is null || choices.Count == 0)
                    return ChatResult.Error($"LM Studio Error: {ExtractError(response)}");

                var choice = choices[0]!.AsObject();
                var message = choice["message"]?.AsObject();
                if (message is null)
                    return ChatResult.Error($"LM Studio returned no message: {response.ToJsonString()}");

                string? text = (string?)message["content"];
                if (!string.IsNullOrEmpty(text))
                {
                    if (finalText.Length > 0) finalText.Append("\n\n");
                    finalText.Append(text);
                }

                // Record the assistant turn verbatim so tool_call ids line up next turn.
                messages.Add(message.DeepClone());

                var usage = response["usage"]?.AsObject();
                if (usage is not null)
                    progress?.Report(AgentActivity.Info(
                        $"usage: prompt={usage["prompt_tokens"]}, completion={usage["completion_tokens"]} tokens"));

                var toolCalls = message["tool_calls"]?.AsArray();
                bool wantsTools = (string?)choice["finish_reason"] == "tool_calls"
                                  || (toolCalls is { Count: > 0 });
                if (!wantsTools || toolCalls is null || toolCalls.Count == 0)
                {
                    progress?.Report(AgentActivity.Info($"finish reason: {(string?)choice["finish_reason"] ?? "stop"}"));
                    break; // nothing more to call -- we're done.
                }

                sawAnyToolCall = true;

                // The model's rationale for the tools it is about to call this turn.
                if (!string.IsNullOrWhiteSpace(text))
                    progress?.Report(AgentActivity.Info($"reasoning: {text}"));

                // Pre-parse every tool call before dispatching. OpenAI delivers arguments as a
                // JSON *string*; local models sometimes emit malformed or empty JSON, so parse
                // defensively and feed any failure back to the model as a tool error.
                var parsed = toolCalls.Select(call =>
                {
                    var callObj = call!.AsObject();
                    string id = (string?)callObj["id"] ?? "";
                    var fn = callObj["function"]?.AsObject();
                    string name = (string?)fn?["name"] ?? "";
                    string rawArgs = (string?)fn?["arguments"] ?? "";

                    var args = new Dictionary<string, object?>();
                    string? parseError = null;
                    if (!string.IsNullOrWhiteSpace(rawArgs))
                    {
                        try
                        {
                            if (JsonNode.Parse(rawArgs) is JsonObject argObj)
                                args = argObj.ToDictionary(kv => kv.Key, kv => (object?)kv.Value?.DeepClone());
                            else
                                parseError = "arguments were not a JSON object";
                        }
                        catch (Exception ex)
                        {
                            parseError = $"could not parse arguments JSON: {ex.Message}";
                        }
                    }
                    return (id, name, rawArgs, args, parseError);
                }).ToList();

                foreach (var c in parsed)
                    progress?.Report(AgentActivity.ToolCall($"{c.name}({Summarize(c.rawArgs)})"));

                // Run the turn's tool calls concurrently (capped) -- independent CTF tools then
                // run in parallel instead of serially. Calls that failed to parse skip the
                // toolbox and return their error immediately, preserving order.
                using var gate = new SemaphoreSlim(MaxParallelTools);
                string[] outputs = await Task.WhenAll(parsed.Select(async c =>
                {
                    if (c.parseError is not null)
                        return $"tool error: {c.parseError}";

                    await gate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        return await toolbox.CallAsync(c.name, c.args, ct).ConfigureAwait(false);
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

                for (int i = 0; i < parsed.Count; i++)
                {
                    progress?.Report(AgentActivity.ToolResult(Preview(outputs[i])));
                    messages.Add(new JsonObject
                    {
                        ["role"] = "tool",
                        ["tool_call_id"] = parsed[i].id,
                        ["content"] = outputs[i],
                    });
                }
            }

            if (finalText.Length > 0)
                return ChatResult.Ok(finalText.ToString());

            return ChatResult.Ok(sawAnyToolCall
                ? "[The agent ran tools but finished without producing a text answer.]"
                : "[The model produced no answer and never called a tool. Make sure the loaded model supports tool/function calling.]");
        }
    }

    /// <summary>One round-trip to the LM Studio chat-completions API with the toolbox tools attached.</summary>
    private async Task<JsonObject> SendAsync(JsonArray messages, JsonArray tools, string host, string model, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["model"] = model,
            ["messages"] = messages.DeepClone(),
            ["tools"] = tools.DeepClone(),
            ["tool_choice"] = "auto",
            ["max_tokens"] = options.MaxTokens,
            ["temperature"] = options.Temperature,
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{host}/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };

        var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
        string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"LM Studio API {(int)resp.StatusCode}: {ExtractErrorJson(json)}");

        return (JsonObject)JsonNode.Parse(json)!;
    }

    private static string Summarize(string rawArgs)
    {
        rawArgs = rawArgs.Trim();
        return rawArgs.Length > 120 ? rawArgs[..120] + "..." : rawArgs;
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
