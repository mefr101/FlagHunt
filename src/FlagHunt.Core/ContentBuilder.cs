using System.Text;

namespace FlagHunt.Core;

/// <summary>Turns the challenge text + attachments + category into a single prompt string.</summary>
public static class ContentBuilder
{
    private const int MaxTextChars = 60000;
    private const int MaxBase64Chars = 25000;

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".py", ".js", ".c", ".cpp", ".java", ".sh", ".php", ".rb", ".go", ".rs",
        ".asm", ".s", ".md", ".json", ".xml", ".html", ".css", ".csv", ".log", ".hex",
        ".yml", ".yaml", ".toml", ".ini", ".cfg", ".pl", ".lua", ".ts", ".kt", ".swift"
    };

    /// <summary>
    /// Builds the user message content. Text/code files are inlined as-is; everything else is
    /// base64-encoded. A non-"auto" category is prepended as a hint, mirroring the original app.
    /// </summary>
    public static string Build(string category, string challenge, IEnumerable<Attachment> attachments)
    {
        var files = attachments.ToList();
        if (files.Count == 0)
            return category != "auto" ? $"\n[Category: {category.ToUpperInvariant()}]\n{challenge}" : challenge;

        var sb = new StringBuilder();
        foreach (var file in files)
        {
            try
            {
                string ext = Path.GetExtension(file.Name);
                if (TextExtensions.Contains(ext))
                {
                    string txt = File.ReadAllText(file.Path);
                    if (txt.Length > MaxTextChars) txt = txt[..MaxTextChars];
                    sb.AppendLine($"\n--- FILE: {file.Name} ---\n{txt}\n--- END ---");
                }
                else
                {
                    string b64 = Convert.ToBase64String(File.ReadAllBytes(file.Path));
                    if (b64.Length > MaxBase64Chars) b64 = b64[..MaxBase64Chars];
                    sb.AppendLine($"\n--- BINARY: {file.Name} (base64) ---\n{b64}\n--- END ---");
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine($"[Could not read {file.Name}: {ex.Message}]");
            }
        }

        if (category != "auto") sb.AppendLine($"\n[Category: {category.ToUpperInvariant()}]");
        sb.Append(challenge);
        return sb.ToString();
    }
}
