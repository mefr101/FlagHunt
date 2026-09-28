using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to the Cursor AI OpenAI-compatible chat completions API.</summary>
public sealed class CursorProvider(HttpClient http, CursorOptions options) : IChatProvider
{
    public string DisplayName => string.IsNullOrWhiteSpace(options.Model) ? "cursor-small" : options.Model;

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
    {
        string key = options.ApiKey.Trim();
        if (string.IsNullOrEmpty(key))
            return ChatResult.Error("No Cursor AI API key.\n\nGet one at: https://cursor.com/settings");
        string model = string.IsNullOrWhiteSpace(options.Model) ? "cursor-small" : options.Model.Trim();

        var msgArr = new JsonArray
        {
            new JsonObject { ["role"] = "system", ["content"] = options.SystemPrompt ?? CtfKnowledge.SystemPrompt }
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

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.cursor.sh/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);

        // Accumulate outside the try so a mid-stream fault (or a user Stop) keeps the partial text.
        var sb = new StringBuilder();
        try
        {
            var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                string err = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return ChatResult.Error($"Cursor Error {(int)resp.StatusCode}: {ExtractError(err)}");
            }

            await foreach (string data in SseReader.ReadDataLinesAsync(resp, ct).ConfigureAwait(false))
            {
                if (data == "[DONE]") break;

                string? delta;
                try { delta = JsonNode.Parse(data)?["choices"]?[0]?["delta"]?["content"]?.GetValue<string>(); }
                catch { continue; } // ignore keep-alives / malformed frames

                if (!string.IsNullOrEmpty(delta))
                {
                    sb.Append(delta);
                    onToken?.Report(delta);
                }
            }

            return sb.Length > 0
                ? ChatResult.Ok(sb.ToString())
                : ChatResult.Error("Cursor returned an empty stream.");
        }
        catch (Exception ex)
        {
            if (sb.Length > 0)
                return ChatResult.Ok(sb + "\n\n" + (ct.IsCancellationRequested ? "[stopped]" : $"[stream interrupted: {ex.Message}]"));
            return ct.IsCancellationRequested
                ? ChatResult.Ok("[stopped]")
                : ChatResult.Error($"Cursor request failed: {ex.Message}");
        }
    }

    private static string ExtractError(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
