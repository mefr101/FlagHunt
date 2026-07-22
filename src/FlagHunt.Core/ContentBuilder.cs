using System.Text;

namespace FlagHunt.Core;

/// <summary>Turns the challenge text + attachments + category into a single prompt string.</summary>
public static class ContentBuilder
{
    private const int MaxTextChars = 40000;     // cap on inlined text/source per file
    private const int SmallBinaryBytes = 8192;  // binaries this size or smaller inline as full base64
    private const int HexPreviewBytes = 256;    // larger binaries: hex/ascii head only

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".py", ".js", ".c", ".cpp", ".java", ".sh", ".php", ".rb", ".go", ".rs",
        ".asm", ".s", ".md", ".json", ".xml", ".html", ".css", ".csv", ".log", ".hex",
        ".yml", ".yaml", ".toml", ".ini", ".cfg", ".pl", ".lua", ".ts", ".kt", ".swift"
    };

    /// <summary>
    /// Builds the user message content.
    /// <para>
    /// In <paramref name="agentMode"/> the attachments are already staged into the toolbox
    /// workspace, so only a filename/size manifest is emitted -- the model reads the files
    /// through the workspace tools instead of receiving their bytes in the prompt.
    /// </para>
    /// <para>
    /// Otherwise text/code files are inlined (capped), small binaries are base64-encoded, and
    /// large binaries are reduced to a magic-byte type guess plus a short hex/ascii preview
    /// rather than a full base64 dump. This keeps the prompt small so prefill stays fast.
    /// </para>
    /// A non-"auto" category is prepended as a hint, mirroring the original app.
    /// </summary>
    public static string Build(string category, string challenge, IEnumerable<Attachment> attachments, bool agentMode = false)
    {
        var files = attachments.ToList();
        if (files.Count == 0)
            return category != "auto" ? $"\n[Category: {category.ToUpperInvariant()}]\n{challenge}" : challenge;

        var sb = new StringBuilder();

        if (agentMode)
            AppendWorkspaceManifest(sb, files);
        else
            foreach (var file in files)
                AppendInlineFile(sb, file);

        if (category != "auto") sb.AppendLine($"\n[Category: {category.ToUpperInvariant()}]");
        sb.Append(challenge);
        return sb.ToString();
    }

    /// <summary>Agent mode: list the staged files by name and size; the tools do the reading.</summary>
    private static void AppendWorkspaceManifest(StringBuilder sb, IReadOnlyList<Attachment> files)
    {
        sb.AppendLine("[Attached files are staged in the workspace. Call list_workspace, then read each by name:]");
        foreach (var file in files)
        {
            long size = -1;
            try { size = new FileInfo(file.Path).Length; } catch { /* fall through to name only */ }
            sb.AppendLine(size >= 0 ? $"- {file.Name} ({size:N0} bytes)" : $"- {file.Name}");
        }
    }

    /// <summary>Chat mode: inline text, small binaries as base64, large binaries as a preview.</summary>
    private static void AppendInlineFile(StringBuilder sb, Attachment file)
    {
        try
        {
            string ext = Path.GetExtension(file.Name);
            if (TextExtensions.Contains(ext))
            {
                string txt = File.ReadAllText(file.Path);
                bool truncated = txt.Length > MaxTextChars;
                if (truncated) txt = txt[..MaxTextChars];
                sb.AppendLine($"\n--- FILE: {file.Name} ---\n{txt}");
                if (truncated) sb.AppendLine("[truncated]");
                sb.AppendLine("--- END ---");
                return;
            }

            byte[] bytes = File.ReadAllBytes(file.Path);
            if (bytes.Length <= SmallBinaryBytes)
            {
                sb.AppendLine($"\n--- BINARY: {file.Name} ({bytes.Length:N0} bytes, base64) ---");
                sb.AppendLine(Convert.ToBase64String(bytes));
                sb.AppendLine("--- END ---");
                return;
            }

            // Large binary: a magic-byte type guess plus a short hex/ascii head carries the
            // identifying header at a fraction of the tokens a base64 dump would cost.
            string type = GuessType(bytes);
            int n = Math.Min(HexPreviewBytes, bytes.Length);
            sb.AppendLine($"\n--- BINARY: {file.Name} ({bytes.Length:N0} bytes, type: {type}) ---");
            sb.AppendLine($"hex head (first {n} bytes):");
            sb.AppendLine(HexDump(bytes.AsSpan(0, n)));
            sb.AppendLine("[truncated -- attach in Agent mode for full tool-based analysis]");
            sb.AppendLine("--- END ---");
        }
        catch (Exception ex)
        {
            sb.AppendLine($"[Could not read {file.Name}: {ex.Message}]");
        }
    }

    /// <summary>Names a file's type from its leading magic bytes (best-effort).</summary>
    private static string GuessType(ReadOnlySpan<byte> head) => head switch
    {
        [0x7F, (byte)'E', (byte)'L', (byte)'F', ..] => "ELF",
        [0x4D, 0x5A, ..] => "PE/DOS (MZ)",
        [0x89, (byte)'P', (byte)'N', (byte)'G', ..] => "PNG",
        [0xFF, 0xD8, 0xFF, ..] => "JPEG",
        [(byte)'G', (byte)'I', (byte)'F', (byte)'8', ..] => "GIF",
        [0x25, 0x50, 0x44, 0x46, ..] => "PDF",
        [0x50, 0x4B, 0x03, 0x04, ..] => "ZIP/Office/JAR",
        [0x1F, 0x8B, ..] => "gzip",
        [(byte)'B', (byte)'Z', (byte)'h', ..] => "bzip2",
        [0x37, 0x7A, 0xBC, 0xAF, ..] => "7-Zip",
        [0xD4, 0xC3, 0xB2, 0xA1, ..] or [0xA1, 0xB2, 0xC3, 0xD4, ..] => "pcap",
        [0x0A, 0x0D, 0x0D, 0x0A, ..] => "pcapng",
        [(byte)'R', (byte)'I', (byte)'F', (byte)'F', ..] => "RIFF (WAV/AVI)",
        _ => "unknown",
    };

    /// <summary>Two-byte-per-group hex with a trailing printable-ASCII rendering.</summary>
    private static string HexDump(ReadOnlySpan<byte> data)
    {
        var hex = new StringBuilder(data.Length * 3);
        var ascii = new StringBuilder(data.Length);
        for (int i = 0; i < data.Length; i++)
        {
            hex.Append(data[i].ToString("x2"));
            if (i % 2 == 1) hex.Append(' ');
            ascii.Append(data[i] is >= 0x20 and < 0x7F ? (char)data[i] : '.');
        }
        return $"{hex.ToString().TrimEnd()}\nascii: {ascii}";
    }
}
