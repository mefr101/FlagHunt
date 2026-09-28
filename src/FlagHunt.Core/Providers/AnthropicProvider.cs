using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to the Anthropic Messages API.</summary>
public sealed class AnthropicProvider(HttpClient http, AnthropicOptions options) : IChatProvider
{
    public string DisplayName => "claude";

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
    {
        string key = options.ApiKey.Trim();
        if (string.IsNullOrEmpty(key))
            return ChatResult.Error("No Anthropic API key. Paste it in the top bar.");

        var msgArr = new JsonArray();
        foreach (var m in history)
            msgArr.Add(new JsonObject { ["role"] = m.Role, ["content"] = m.Content });

        // Prompt caching (GA -- no beta header): a breakpoint on the system prompt and one on
        // the last message cache the system + conversation prefix, so multi-turn follow-ups
        // reprocess only the newest turn. Below the model's minimum cacheable prefix it simply
        // no-ops. Render order is system -> messages, so this covers everything before the tail.
        if (msgArr.Count > 0 && msgArr[^1] is JsonObject lastMsg)
            lastMsg["content"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "text",
                    ["text"] = (string?)lastMsg["content"] ?? "",
                    ["cache_control"] = new JsonObject { ["type"] = "ephemeral" },
                }
            };

        var body = new JsonObject
        {
            ["model"] = options.Model,
            ["max_tokens"] = options.MaxTokens,
            ["system"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "text",
                    ["text"] = options.SystemPrompt ?? CtfKnowledge.SystemPrompt,
                    ["cache_control"] = new JsonObject { ["type"] = "ephemeral" },
                }
            },
            ["messages"] = msgArr,
            ["stream"] = true,
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Add("x-api-key", key);
        req.Headers.Add("anthropic-version", "2023-06-01");

        // Accumulate outside the try so a mid-stream fault (or a user Stop) keeps the partial text.
        var sb = new StringBuilder();
        try
        {
            var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                string err = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return ChatResult.Error($"API Error {(int)resp.StatusCode}: {ExtractError(err)}");
            }

            // Anthropic SSE carries typed events; text arrives as content_block_delta/text_delta.
            await foreach (string data in SseReader.ReadDataLinesAsync(resp, ct).ConfigureAwait(false))
            {
                JsonNode? evt;
                try { evt = JsonNode.Parse(data); }
                catch { continue; }

                switch ((string?)evt?["type"])
                {
                    case "content_block_delta":
                        string? text = evt!["delta"]?["text"]?.GetValue<string>();
                        if (!string.IsNullOrEmpty(text)) { sb.Append(text); onToken?.Report(text); }
                        break;
                    case "error":
                        string msg = evt!["error"]?["message"]?.GetValue<string>() ?? "stream error";
                        return sb.Length > 0
                            ? ChatResult.Ok(sb + $"\n\n[stream error: {msg}]")
                            : ChatResult.Error($"API Error: {msg}");
                    case "message_stop":
                        return ChatResult.Ok(sb.ToString());
                }
            }

            return ChatResult.Ok(sb.ToString());
        }
        catch (Exception ex)
        {
            if (sb.Length > 0)
                return ChatResult.Ok(sb + "\n\n" + (ct.IsCancellationRequested ? "[stopped]" : $"[stream interrupted: {ex.Message}]"));
            return ct.IsCancellationRequested
                ? ChatResult.Ok("[stopped]")
                : ChatResult.Error($"Request failed: {ex.Message}");
        }
    }

    private static string ExtractError(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
