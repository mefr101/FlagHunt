using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to LM Studio's OpenAI-compatible local API.</summary>
public sealed class LmStudioProvider(HttpClient http, LmStudioOptions options) : IChatProvider
{
    public string DisplayName => string.IsNullOrWhiteSpace(options.Model) ? "lm-studio" : options.Model;

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
    {
        string host = options.Host.TrimEnd('/');
        string model = options.Model.Trim();
        if (string.IsNullOrEmpty(model))
            return ChatResult.Error("No model selected. Load a model in LM Studio and click 'fetch'.");

        var msgArr = new JsonArray
        {
            new JsonObject { ["role"] = "system", ["content"] = CtfKnowledge.SystemPrompt }
        };
        foreach (var m in history)
            msgArr.Add(new JsonObject { ["role"] = m.Role, ["content"] = m.Content });

        var body = new JsonObject
        {
            ["model"] = model,
            ["messages"] = msgArr,
            ["max_tokens"] = options.MaxTokens,
            ["temperature"] = options.Temperature,
            ["stream"] = true,
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{host}/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };

        // Accumulate outside the try so a mid-stream fault can still return the partial text.
        var sb = new StringBuilder();
        try
        {
            // ResponseHeadersRead: start reading as the body streams instead of buffering it all.
            var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                string err = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return ChatResult.Error($"LM Studio Error {(int)resp.StatusCode}: {ExtractError(err)}");
            }

            await foreach (string data in SseReader.ReadDataLinesAsync(resp, ct).ConfigureAwait(false))
            {
                if (data == "[DONE]") break;

                string? delta;
                try
                {
                    // Each frame: {"choices":[{"delta":{"content":"..."}}]}. A trailing frame
                    // may carry only usage/finish_reason with no content -- skipped below.
                    delta = JsonNode.Parse(data)?["choices"]?[0]?["delta"]?["content"]?.GetValue<string>();
                }
                catch
                {
                    continue; // ignore keep-alives / malformed frames
                }

                if (!string.IsNullOrEmpty(delta))
                {
                    sb.Append(delta);
                    onToken?.Report(delta);
                }
            }

            return sb.Length > 0
                ? ChatResult.Ok(sb.ToString())
                : ChatResult.Error("LM Studio returned an empty stream. Make sure a chat (non-embedding) model is loaded.");
        }
        catch (Exception ex)
        {
            if (sb.Length > 0)
                return ChatResult.Ok(sb + "\n\n" + (ct.IsCancellationRequested ? "[stopped]" : $"[stream interrupted: {ex.Message}]"));
            if (ct.IsCancellationRequested)
                return ChatResult.Ok("[stopped]");
            return ChatResult.Error($"Cannot reach LM Studio at {host}\n\nMake sure LM Studio is running with the local server enabled.\n\nError: {ex.Message}");
        }
    }

    /// <summary>Returns the model IDs currently loaded in LM Studio, or an empty list on failure.</summary>
    public static async Task<IReadOnlyList<string>> FetchModelsAsync(HttpClient http, string host, CancellationToken ct = default)
    {
        host = host.TrimEnd('/');
        try
        {
            string json = await http.GetStringAsync($"{host}/v1/models", ct).ConfigureAwait(false);
            return JsonDocument.Parse(json).RootElement.GetProperty("data")
                .EnumerateArray()
                .Select(m => m.GetProperty("id").GetString() ?? "")
                .Where(id => id.Length > 0)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private static string ExtractError(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
