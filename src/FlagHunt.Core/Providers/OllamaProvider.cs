using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FlagHunt.Core.Providers;

/// <summary>Talks to a local Ollama server's chat API.</summary>
public sealed class OllamaProvider(HttpClient http, OllamaOptions options) : IChatProvider
{
    public string DisplayName => options.Model;

    public async Task<ChatResult> CompleteAsync(IReadOnlyList<ChatMessage> history, IProgress<string>? onToken = null, CancellationToken ct = default)
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
            ["stream"] = true,
            ["options"] = new JsonObject { ["num_predict"] = options.NumPredict, ["temperature"] = options.Temperature }
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, $"{host}/api/chat")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };

        // Accumulate outside the try so a mid-stream fault (or a user Stop) keeps the partial text.
        var sb = new StringBuilder();
        try
        {
            var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                string err = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                return ChatResult.Error($"Ollama Error {(int)resp.StatusCode}: {err[..Math.Min(300, err.Length)]}");
            }

            // Ollama streams newline-delimited JSON objects (not SSE): one {message:{content},done}
            // per line, terminated by a final object with "done": true.
            using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
            {
                if (line.Length == 0) continue;

                JsonNode? obj;
                try { obj = JsonNode.Parse(line); }
                catch { continue; }

                string? delta = obj?["message"]?["content"]?.GetValue<string>();
                if (!string.IsNullOrEmpty(delta)) { sb.Append(delta); onToken?.Report(delta); }

                if (obj?["done"]?.GetValue<bool>() == true) break;
            }

            return sb.Length > 0
                ? ChatResult.Ok(sb.ToString())
                : ChatResult.Error("Ollama returned an empty stream.");
        }
        catch (Exception ex)
        {
            if (sb.Length > 0)
                return ChatResult.Ok(sb + "\n\n" + (ct.IsCancellationRequested ? "[stopped]" : $"[stream interrupted: {ex.Message}]"));
            return ct.IsCancellationRequested
                ? ChatResult.Ok("[stopped]")
                : ChatResult.Error($"Cannot reach Ollama at {host}\n\nRun: ollama serve\n\nError: {ex.Message}");
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
