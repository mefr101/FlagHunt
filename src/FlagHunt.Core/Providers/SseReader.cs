using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;

namespace FlagHunt.Core.Providers;

/// <summary>Reads a Server-Sent Events (SSE) stream, yielding each event's <c>data:</c> payload.</summary>
internal static class SseReader
{
    /// <summary>
    /// Streams the <c>data:</c> payloads from an SSE HTTP response, one per yielded string.
    /// Blank lines (event delimiters), comments, and non-data fields are skipped; the caller
    /// decides what the payloads mean (e.g. OpenAI JSON deltas, or the literal <c>[DONE]</c>
    /// sentinel). Used by the OpenAI-compatible (LM Studio, Cursor) and Anthropic providers.
    /// </summary>
    public static async IAsyncEnumerable<string> ReadDataLinesAsync(
        HttpResponseMessage response,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var reader = new StreamReader(stream);

        string? line;
        while ((line = await reader.ReadLineAsync(ct).ConfigureAwait(false)) is not null)
        {
            if (line.Length == 0) continue;                                   // event delimiter
            if (!line.StartsWith("data:", StringComparison.Ordinal)) continue; // skip event:/id:/comments
            yield return line["data:".Length..].TrimStart();
        }
    }
}
