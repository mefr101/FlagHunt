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

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default)
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
            ["temperature"] = options.Temperature
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{host}/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };

        try
        {
            var resp = await http.SendAsync(req, ct).ConfigureAwait(false);
            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
                return ChatResult.Error($"LM Studio Error {(int)resp.StatusCode}: {ExtractError(json)}");

            string text = JsonDocument.Parse(json).RootElement
                .GetProperty("choices")[0]
                .GetProperty("message")
                .GetProperty("content")
                .GetString() ?? "";
            return ChatResult.Ok(text);
        }
        catch (Exception ex)
        {
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
