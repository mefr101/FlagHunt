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

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default)
    {
        string key = options.ApiKey.Trim();
        if (string.IsNullOrEmpty(key))
            return ChatResult.Error("No Cursor AI API key.\n\nGet one at: https://cursor.com/settings");
        string model = string.IsNullOrWhiteSpace(options.Model) ? "cursor-small" : options.Model.Trim();

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
            ["temperature"] = options.Temperature
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.cursor.sh/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);

        try
        {
            var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
                return ChatResult.Error($"Cursor Error {(int)resp.StatusCode}: {ExtractError(json)}");

            string text = JsonDocument.Parse(json).RootElement
                .GetProperty("choices")[0]
                .GetProperty("message")
                .GetProperty("content")
                .GetString() ?? "";
            return ChatResult.Ok(text);
        }
        catch (Exception ex)
        {
            return ChatResult.Error($"Cursor request failed: {ex.Message}");
        }
    }

    private static string ExtractError(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
