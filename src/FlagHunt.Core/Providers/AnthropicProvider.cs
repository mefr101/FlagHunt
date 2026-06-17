using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to the Anthropic Messages API.</summary>
public sealed class AnthropicProvider(HttpClient http, AnthropicOptions options) : IChatProvider
{
    public string DisplayName => "claude";

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default)
    {
        string key = options.ApiKey.Trim();
        if (string.IsNullOrEmpty(key))
            return ChatResult.Error("No Anthropic API key. Paste it in the top bar.");

        var msgArr = new JsonArray();
        foreach (var m in history)
            msgArr.Add(new JsonObject { ["role"] = m.Role, ["content"] = m.Content });

        var body = new JsonObject
        {
            ["model"] = options.Model,
            ["max_tokens"] = options.MaxTokens,
            ["system"] = CtfKnowledge.SystemPrompt,
            ["messages"] = msgArr
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Add("x-api-key", key);
        req.Headers.Add("anthropic-version", "2023-06-01");

        try
        {
            var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
                return ChatResult.Error($"API Error {(int)resp.StatusCode}: {ExtractError(json)}");

            var doc = JsonDocument.Parse(json);
            var sb = new StringBuilder();
            foreach (var c in doc.RootElement.GetProperty("content").EnumerateArray())
                if (c.GetProperty("type").GetString() == "text")
                    sb.Append(c.GetProperty("text").GetString());
            return ChatResult.Ok(sb.ToString());
        }
        catch (Exception ex)
        {
            return ChatResult.Error($"Request failed: {ex.Message}");
        }
    }

    private static string ExtractError(string json)
    {
        try { return JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString() ?? json; }
        catch { return json[..Math.Min(300, json.Length)]; }
    }
}
