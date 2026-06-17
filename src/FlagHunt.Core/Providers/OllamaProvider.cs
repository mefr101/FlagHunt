using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to a local Ollama server's chat API.</summary>
public sealed class OllamaProvider(HttpClient http, OllamaOptions options) : IChatProvider
{
    public string DisplayName => options.Model;

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, CancellationToken ct = default)
    {
        string host = options.Host.TrimEnd('/');
        string model = options.Model.Trim();
        if (string.IsNullOrEmpty(model))
            return ChatResult.Error("No Ollama model selected. Click 'fetch'.");

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
            ["stream"] = false,
            ["options"] = new JsonObject { ["num_predict"] = options.NumPredict, ["temperature"] = options.Temperature }
        };

        try
        {
            var resp = await http.PostAsync($"{host}/api/chat",
                new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"), ct).ConfigureAwait(false);
            string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            string text = JsonDocument.Parse(json).RootElement.GetProperty("message").GetProperty("content").GetString() ?? "";
            return ChatResult.Ok(text);
        }
        catch (Exception ex)
        {
            return ChatResult.Error($"Cannot reach Ollama at {host}\n\nRun: ollama serve\n\nError: {ex.Message}");
        }
    }

    /// <summary>Returns the model names installed on the Ollama server, or an empty list on failure.</summary>
    public static async Task<IReadOnlyList<string>> FetchModelsAsync(HttpClient http, string host, CancellationToken ct = default)
    {
        host = host.TrimEnd('/');
        try
        {
            string json = await http.GetStringAsync($"{host}/api/tags", ct).ConfigureAwait(false);
            return JsonDocument.Parse(json).RootElement.GetProperty("models")
                .EnumerateArray()
                .Select(m => m.GetProperty("name").GetString() ?? "")
                .Where(n => n.Length > 0)
                .ToList();
        }
        catch
        {
            return [];
        }
    }
}
