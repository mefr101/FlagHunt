using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace FlagHunt;

public partial class MainWindow : Window
{
    // ── System prompt ──────────────────────────────────────────────────────
    private const string SYSTEM_PROMPT = """
        You are an elite CTF (Capture The Flag) solver with encyclopedic knowledge of all security domains.
        You ALWAYS solve every challenge -- you never refuse, never say "I can't", never give up.
        Every challenge is solvable and you treat it that way.

        Domains you master:

        CRYPTOGRAPHY: All classical ciphers (Caesar, Vigenere, ROT13, Atbash, Rail Fence, Playfair, Beaufort),
        modern crypto (RSA, AES, DES, ChaCha20, RC4, Salsa20), elliptic curve, hash cracking (MD5/SHA/bcrypt),
        padding oracle, CBC bit-flip, ECB block shuffling, frequency analysis, XOR (single/multi-byte),
        all base encodings (base64/32/16/58/85/91), Wiener's attack, Hastad's broadcast, CRT, ECDSA nonce reuse.

        WEB EXPLOITATION: SQL injection (UNION/blind/time-based), XSS (reflected/stored/DOM), CSRF, SSRF,
        SSTI (Jinja2/Twig/Smarty), LFI/RFI (php wrappers), path traversal, command injection, XXE,
        deserialization, JWT (none alg, weak HS256, RS256->HS256), OAuth, IDOR, prototype pollution,
        HTTP request smuggling, CORS, GraphQL, CRLF injection.

        BINARY EXPLOITATION: Stack overflows, heap overflows, ret2libc, ret2plt, ret2win, ROP chains,
        format string, heap exploitation (fastbin dup, tcache poisoning, UAF, double-free),
        GOT/PLT hijacking, ASLR/PIE bypass, stack canary bypass, shellcode, SROP, one-gadget.

        REVERSE ENGINEERING: x86/x64/ARM/RISC-V assembly, decompiler output (Ghidra/IDA/Binary Ninja),
        anti-debugging, obfuscation, VM-based protectors, UPX/custom packers, Python pyc, Java class,
        .NET IL, WebAssembly, Angr/Z3 symbolic execution.

        FORENSICS: File magic/format ID, file carving, metadata (EXIF/PDF XMP), pcap analysis,
        memory forensics (Volatility3), disk forensics (MFT/registry), browser artifacts, log analysis, ZIP tricks.

        STEGANOGRAPHY: LSB in PNG/BMP/GIF, DCT in JPEG (steghide/outguess), audio spectrograms,
        whitespace stego (SNOW), zero-width chars, Unicode homoglyphs, color channel isolation.

        OSINT: Username enum, geolocation, reverse image search, WHOIS/DNS, Google dorking,
        Wayback Machine, cert transparency (crt.sh), Shodan/Censys, email header analysis.

        NETWORKING: Pcap analysis, Wireshark filters, TCP/UDP reconstruction, DNS exfiltration,
        ICMP tunneling, WiFi (WPA2 handshake -> hashcat, PMKID, WPS), Bluetooth, ARP anomalies.

        MISC: QR codes, barcodes, Morse, Braille, esoteric languages (Brainfuck/Malbolge/Whitespace/Ook!/Piet),
        blockchain (Solidity analysis, private key from weak RNG), PRNG prediction.

        Response format -- always use:
        ANALYSIS
        [Identify challenge type, key observations, attack vectors]

        SOLUTION
        [Step-by-step. Exact commands. Full working code.]

        FLAG
        [The flag, or best derived answer, or exact script to extract it]

        EXPLANATION
        [Why this worked]

        Non-negotiable rules:
        - Always write complete, runnable code
        - Never truncate with "# rest of exploit here" -- write everything
        - If you cannot determine the exact flag, write the complete tool to find it
        - Never say cannot, unable, refuse, or impossible -- always push forward
        """;

    // ── Categories ─────────────────────────────────────────────────────────
    private static readonly (string Label, string Value)[] CATEGORIES =
    [
        ("Auto",      "auto"),
        ("Web",       "web"),
        ("Crypto",    "crypto"),
        ("Pwn",       "pwn"),
        ("Forensics", "forensics"),
        ("Reversing", "reversing"),
        ("Stego",     "steganography"),
        ("OSINT",     "osint"),
        ("Network",   "networking"),
        ("Misc",      "misc"),
    ];

    // ── Colour helpers ─────────────────────────────────────────────────────
    private static SolidColorBrush B(string hex)
    {
        var c = (Color)ColorConverter.ConvertFromString(hex);
        return new SolidColorBrush(c);
    }

    // ── State ──────────────────────────────────────────────────────────────
    private string _provider = "anthropic";
    private string _cat      = "auto";
    private readonly List<(string Path, string Name)>    _files   = [];
    private readonly List<(string Role, string Content)> _history = [];
    private bool _loading = false;

    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(300) };

    private readonly Dictionary<string, Button> _catBtns = [];

    // Placeholder state
    private bool   _chPh = true;
    private bool   _fuPh = true;
    private const string ChPh = "Paste challenge, ciphertext, hex dump, code, or anything...";
    private const string FuPh = "Ask a follow-up question...";

    // Thinking animation
    private DispatcherTimer? _thinkTimer;
    private StackPanel?      _thinkFrame;
    private TextBlock?       _thinkLbl;
    private int              _thinkI;
    private static readonly string[] Dots = ["|", "/", "-", "\\"];

    // ── Constructor ────────────────────────────────────────────────────────
    public MainWindow()
    {
        InitializeComponent();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        BuildCategoryButtons();
        ShowWelcome();
    }

    // ── Category grid ──────────────────────────────────────────────────────
    private void BuildCategoryButtons()
    {
        CatGrid.Children.Clear();
        _catBtns.Clear();
        foreach (var (label, val) in CATEGORIES)
        {
            var btn = new Button { Content = label, Style = (Style)FindResource("CatBtn"), Tag = val };
            btn.Click += (s, _) => SelectCategory((string)((Button)s).Tag);
            _catBtns[val] = btn;
            CatGrid.Children.Add(btn);
        }
        SelectCategory("auto");
    }

    // ── Provider switching ─────────────────────────────────────────────────
    private void RbAnthropic_Checked(object sender, RoutedEventArgs e)
    {
        if (AnthropicCfg is null) return;
        _provider = "anthropic";
        AnthropicCfg.Visibility = Visibility.Visible;
        OllamaCfg.Visibility    = Visibility.Collapsed;
        CursorCfg.Visibility    = Visibility.Collapsed;
        SetStatus("anthropic  ready", "#00E5B0");
    }

    private void RbOllama_Checked(object sender, RoutedEventArgs e)
    {
        if (OllamaCfg is null) return;
        _provider = "ollama";
        AnthropicCfg.Visibility = Visibility.Collapsed;
        OllamaCfg.Visibility    = Visibility.Visible;
        CursorCfg.Visibility    = Visibility.Collapsed;
        SetStatus("ollama  connecting...", "#9B6DFF");
        _ = FetchOllamaModels();
    }

    private void RbCursor_Checked(object sender, RoutedEventArgs e)
    {
        if (CursorCfg is null) return;
        _provider = "cursor";
        AnthropicCfg.Visibility = Visibility.Collapsed;
        OllamaCfg.Visibility    = Visibility.Collapsed;
        CursorCfg.Visibility    = Visibility.Visible;
        SetStatus("cursor ai  ready", "#E879F9");
    }

    // ── Ollama model fetch ─────────────────────────────────────────────────
    private async Task FetchOllamaModels()
    {
        string host = TbOllamaHost.Text.TrimEnd('/');
        try
        {
            string json  = await _http.GetStringAsync($"{host}/api/tags");
            var    doc   = JsonDocument.Parse(json);
            var    names = doc.RootElement.GetProperty("models")
                              .EnumerateArray()
                              .Select(m => m.GetProperty("name").GetString() ?? "")
                              .Where(n => n.Length > 0)
                              .ToList();
            Dispatcher.Invoke(() =>
            {
                CbOllamaModel.ItemsSource = names;
                if (names.Count > 0 && !names.Contains(CbOllamaModel.Text))
                    CbOllamaModel.Text = names[0];
                SetStatus($"ollama  {names.Count} model(s) ready", "#9B6DFF");
            });
        }
        catch
        {
            Dispatcher.Invoke(() => SetStatus("ollama: cannot connect -- run: ollama serve", "#FF3B5C"));
        }
    }

    private async void BtnFetchModels_Click(object sender, RoutedEventArgs e)
        => await FetchOllamaModels();

    // ── Category selection ─────────────────────────────────────────────────
    private void SelectCategory(string val)
    {
        _cat = val;
        foreach (var (v, btn) in _catBtns)
        {
            if (v == val)
            {
                btn.Background   = B("#2E3A52");
                btn.Foreground   = B("#00E5B0");
                btn.BorderBrush  = B("#00E5B0");
            }
            else
            {
                btn.Background   = B("#1E2535");
                btn.Foreground   = B("#5A6A85");
                btn.BorderBrush  = B("#252D40");
            }
        }
        string label = CATEGORIES.FirstOrDefault(c => c.Value == val).Label ?? val;
        ChatTitle.Text = $"  analysis  .  {label.ToLower()}  .  ready";
    }

    // ── File attachments ───────────────────────────────────────────────────
    private void BtnAttach_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Attach CTF Files", Multiselect = true, Filter = "All Files (*.*)|*.*" };
        if (dlg.ShowDialog() != true) return;
        foreach (string path in dlg.FileNames)
        {
            if (_files.Any(f => f.Path == path)) continue;
            string name = Path.GetFileName(path);
            _files.Add((path, name));
            AddFileChip(path, name);
        }
    }

    private void AddFileChip(string path, string name)
    {
        string ext = name.Contains('.') ? name.Split('.').Last().ToUpper() : "FILE";
        if (ext.Length > 5) ext = ext[..5];

        var chip = new Border
        {
            Background      = B("#1E2535"),
            BorderBrush     = B("#252D40"),
            BorderThickness = new Thickness(1),
            Margin          = new Thickness(0, 2, 0, 0)
        };

        var row = new DockPanel { LastChildFill = true };

        var badge = new Border { Background = B("#00E5B0"), Padding = new Thickness(4, 3, 4, 3), Margin = new Thickness(0, 0, 6, 0) };
        badge.Child = new TextBlock { Text = $" {ext} ", Foreground = Brushes.Black, FontFamily = new FontFamily("Segoe UI"), FontSize = 8, FontWeight = FontWeights.Bold };
        DockPanel.SetDock(badge, Dock.Left);
        row.Children.Add(badge);

        var rm = new Button
        {
            Content         = "x",
            Background      = Brushes.Transparent,
            Foreground      = B("#3D4F6A"),
            BorderThickness = new Thickness(0),
            Padding         = new Thickness(6, 3, 6, 3),
            Cursor          = Cursors.Hand,
            FontFamily      = new FontFamily("Segoe UI"),
            FontSize        = 11
        };
        rm.Click += (_, _) => { _files.RemoveAll(f => f.Path == path); FilesList.Children.Remove(chip); };
        DockPanel.SetDock(rm, Dock.Right);
        row.Children.Add(rm);

        row.Children.Add(new TextBlock
        {
            Text              = name.Length > 26 ? name[..26] + "..." : name,
            Foreground        = B("#DDE6F5"),
            FontFamily        = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize          = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Padding           = new Thickness(0, 4, 0, 4)
        });

        chip.Child = row;
        FilesList.Children.Add(chip);
    }

    // ── Placeholder helpers ────────────────────────────────────────────────
    private void ChallengeTxt_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_chPh) return;
        ChallengeTxt.Text       = "";
        ChallengeTxt.Foreground = B("#DDE6F5");
        _chPh = false;
    }

    private void ChallengeTxt_LostFocus(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(ChallengeTxt.Text)) return;
        ChallengeTxt.Text       = ChPh;
        ChallengeTxt.Foreground = B("#5A6A85");
        _chPh = true;
    }

    private void FuEntry_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_fuPh) return;
        FuEntry.Text       = "";
        FuEntry.Foreground = B("#DDE6F5");
        _fuPh = false;
    }

    private void FuEntry_LostFocus(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(FuEntry.Text)) return;
        FuEntry.Text       = FuPh;
        FuEntry.Foreground = B("#5A6A85");
        _fuPh = true;
    }

    private void FuEntry_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Return) BtnSend_Click(sender, e);
    }

    // ── Status LED ─────────────────────────────────────────────────────────
    private void SetStatus(string text, string hex)
    {
        var brush       = B(hex);
        StatusLabel.Text       = text;
        StatusLabel.Foreground = brush;
        LedEllipse.Fill        = brush;
    }

    // ── Welcome screen ─────────────────────────────────────────────────────
    private void ShowWelcome()
    {
        ConvPanel.Children.Clear();

        var outer = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 80, 0, 0), Tag = "welcome" };

        outer.Children.Add(new TextBlock
        {
            Text                = "FlagHunt",
            Foreground          = B("#DDE6F5"),
            FontFamily          = new FontFamily("Segoe UI"),
            FontSize            = 32,
            FontWeight          = FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Center
        });

        outer.Children.Add(new TextBlock
        {
            Text                = "AI-Powered CTF Solver  (C# / WPF)",
            Foreground          = B("#00E5B0"),
            FontFamily          = new FontFamily("Segoe UI"),
            FontSize            = 13,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin              = new Thickness(0, 2, 0, 16)
        });

        var pills = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Center };
        foreach (string t in new[] { "Anthropic", "Ollama", "Cursor AI", "Web", "Crypto", "Pwn", "Forensics", "Reversing", "Stego", "OSINT", "Networking" })
        {
            var pill = new Border { Background = B("#1E2535"), BorderBrush = B("#2E3A52"), BorderThickness = new Thickness(1), Margin = new Thickness(3), Padding = new Thickness(8, 3, 8, 3) };
            pill.Child = new TextBlock { Text = t, Foreground = B("#5A6A85"), FontFamily = new FontFamily("Segoe UI"), FontSize = 9 };
            pills.Children.Add(pill);
        }
        outer.Children.Add(pills);

        outer.Children.Add(new TextBlock
        {
            Text                = "\nPaste a challenge, attach files, pick a category, hit Solve",
            Foreground          = B("#5A6A85"),
            FontFamily          = new FontFamily("Segoe UI"),
            FontSize            = 10,
            HorizontalAlignment = HorizontalAlignment.Center
        });

        ConvPanel.Children.Add(outer);
    }

    private void RemoveWelcome()
    {
        var w = ConvPanel.Children.OfType<StackPanel>().FirstOrDefault(p => (string?)p.Tag == "welcome");
        if (w is not null) ConvPanel.Children.Remove(w);
    }

    // ── Message rendering ──────────────────────────────────────────────────
    private void AddMessage(string role, string text)
    {
        RemoveWelcome();

        string roleLabel = role == "user" ? "YOU" :
                           _provider == "ollama" ? $"OLLAMA  {CbOllamaModel.Text}" :
                           _provider == "cursor" ? $"CURSOR AI  {CbCursorModel.Text}" : "AI SOLVER  claude";

        string roleHex  = role == "user" ? "#4488FF" :
                          _provider == "ollama" ? "#9B6DFF" :
                          _provider == "cursor" ? "#E879F9" : "#00E5B0";

        string bodyBg   = role == "user" ? "#0E1420" : "#12151C";
        string bodyBorder = role == "user" ? "#4488FF" :
                            _provider == "ollama" ? "#9B6DFF" :
                            _provider == "cursor" ? "#E879F9" : "#252D40";

        var outer = new StackPanel { Margin = new Thickness(20, 0, 20, 12) };

        // Role label strip
        var labelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        labelRow.Children.Add(new Border { Width = 3, Background = B(roleHex), Margin = new Thickness(0, 0, 4, 0) });
        labelRow.Children.Add(new TextBlock
        {
            Text              = $"  {roleLabel}",
            Foreground        = B(roleHex),
            FontFamily        = new FontFamily("Segoe UI"),
            FontSize          = 8,
            FontWeight        = FontWeights.Bold,
            VerticalAlignment = VerticalAlignment.Center
        });
        outer.Children.Add(labelRow);

        // Body bubble
        var body = new Border
        {
            Background      = B(bodyBg),
            BorderBrush     = B(bodyBorder),
            BorderThickness = new Thickness(1),
            Padding         = new Thickness(14, 12, 14, 12)
        };

        var tb = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            FontFamily   = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize     = 10,
            Foreground   = B("#DDE6F5"),
            LineHeight   = 18
        };

        RenderText(tb, text);
        body.Child = tb;
        outer.Children.Add(body);

        ConvPanel.Children.Add(outer);
        ChatScroll.ScrollToEnd();
    }

    private static void RenderText(TextBlock tb, string text)
    {
        bool inCode = false;
        string[] lines = text.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0) tb.Inlines.Add(new LineBreak());
            string line = lines[i];

            // Code fence
            if (line.TrimStart().StartsWith("```"))
            {
                inCode = !inCode;
                tb.Inlines.Add(new Run(line) { Foreground = B("#7EC8A4"), Background = B("#0D1018") });
                continue;
            }
            if (inCode)
            {
                tb.Inlines.Add(new Run(line) { Foreground = B("#7EC8A4"), Background = B("#0D1018") });
                continue;
            }

            // Flag highlight
            var fm = Regex.Match(line, @"((?:flag|ctf|CTF|FLAG)\{[^}]+\})");
            if (fm.Success)
            {
                if (fm.Index > 0) tb.Inlines.Add(new Run(line[..fm.Index]));
                tb.Inlines.Add(new Run($"  {fm.Value}  ") { Background = B("#091E18"), Foreground = B("#00E5B0"), FontWeight = FontWeights.Bold, FontSize = 11 });
                if (fm.Index + fm.Length < line.Length) tb.Inlines.Add(new Run(line[(fm.Index + fm.Length)..]));
                continue;
            }

            // Bold **text**
            if (line.Contains("**"))
            {
                var parts = Regex.Split(line, @"\*\*(.*?)\*\*");
                for (int j = 0; j < parts.Length; j++)
                    tb.Inlines.Add(j % 2 == 1
                        ? new Run(parts[j]) { FontWeight = FontWeights.Bold }
                        : new Run(parts[j]));
                continue;
            }

            // Inline code `text`
            if (line.Contains('`'))
            {
                var parts = Regex.Split(line, @"`([^`]+)`");
                for (int j = 0; j < parts.Length; j++)
                    tb.Inlines.Add(j % 2 == 1
                        ? new Run(parts[j]) { Foreground = B("#7EC8A4"), Background = B("#0D1018") }
                        : new Run(parts[j]));
                continue;
            }

            tb.Inlines.Add(new Run(line));
        }
    }

    // ── Thinking spinner ───────────────────────────────────────────────────
    private void AddThinking()
    {
        RemoveWelcome();
        string rc = _provider == "ollama" ? "#9B6DFF" : _provider == "cursor" ? "#E879F9" : "#00E5B0";

        var outer = new StackPanel { Margin = new Thickness(20, 0, 20, 12), Tag = "thinking" };

        var labelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        labelRow.Children.Add(new Border { Width = 3, Background = B(rc), Margin = new Thickness(0, 0, 4, 0) });
        labelRow.Children.Add(new TextBlock { Text = "  AI SOLVER", Foreground = B(rc), FontFamily = new FontFamily("Segoe UI"), FontSize = 8, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center });
        outer.Children.Add(labelRow);

        _thinkLbl = new TextBlock
        {
            Text       = "|  analyzing challenge...",
            Foreground = B("#5A6A85"),
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize   = 10
        };

        var body = new Border { Background = B("#12151C"), BorderBrush = B("#252D40"), BorderThickness = new Thickness(1), Padding = new Thickness(14, 12, 14, 12) };
        body.Child = _thinkLbl;
        outer.Children.Add(body);

        ConvPanel.Children.Add(outer);
        ChatScroll.ScrollToEnd();

        _thinkFrame = outer;
        _thinkI     = 0;
        _thinkTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _thinkTimer.Tick += (_, _) =>
        {
            if (_thinkLbl is not null)
                _thinkLbl.Text = $"{Dots[_thinkI++ % Dots.Length]}  analyzing challenge...";
        };
        _thinkTimer.Start();
    }

    private void StopThinking()
    {
        _thinkTimer?.Stop();
        _thinkTimer = null;
        if (_thinkFrame is not null) { ConvPanel.Children.Remove(_thinkFrame); _thinkFrame = null; }
        _thinkLbl = null;
    }

    // ── Clear / Copy ───────────────────────────────────────────────────────
    private void BtnClear_Click(object sender, RoutedEventArgs e)
    {
        _history.Clear(); _files.Clear(); FilesList.Children.Clear();
        ShowWelcome();
        SetStatus("cleared  ready", "#5A6A85");
    }

    private void BtnCopy_Click(object sender, RoutedEventArgs e)
    {
        var sb = new StringBuilder();
        foreach (var sp in ConvPanel.Children.OfType<StackPanel>())
        {
            if ((string?)sp.Tag == "welcome") continue;
            foreach (var border in sp.Children.OfType<Border>())
                if (border.Child is TextBlock tb)
                {
                    foreach (var r in tb.Inlines.OfType<Run>()) sb.Append(r.Text);
                    sb.AppendLine();
                }
            sb.AppendLine("---");
        }
        if (sb.Length > 0) { Clipboard.SetText(sb.ToString()); SetStatus("copied to clipboard", "#00E5B0"); }
    }

    // ── Build message content ──────────────────────────────────────────────
    private string BuildContent(string challenge)
    {
        if (_files.Count == 0)
        {
            return _cat != "auto" ? $"\n[Category: {_cat.ToUpper()}]\n{challenge}" : challenge;
        }

        var textExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".txt",".py",".js",".c",".cpp",".java",".sh",".php",".rb",".go",".rs",
            ".asm",".s",".md",".json",".xml",".html",".css",".csv",".log",".hex",
            ".yml",".yaml",".toml",".ini",".cfg",".pl",".lua",".ts",".kt",".swift"
        };

        var sb = new StringBuilder();
        foreach (var (path, name) in _files)
        {
            try
            {
                string ext = Path.GetExtension(name);
                if (textExts.Contains(ext))
                {
                    string txt = File.ReadAllText(path);
                    if (txt.Length > 60000) txt = txt[..60000];
                    sb.AppendLine($"\n--- FILE: {name} ---\n{txt}\n--- END ---");
                }
                else
                {
                    byte[] bytes = File.ReadAllBytes(path);
                    string b64   = Convert.ToBase64String(bytes);
                    if (b64.Length > 25000) b64 = b64[..25000];
                    sb.AppendLine($"\n--- BINARY: {name} (base64) ---\n{b64}\n--- END ---");
                }
            }
            catch (Exception ex) { sb.AppendLine($"[Could not read {name}: {ex.Message}]"); }
        }

        if (_cat != "auto") sb.AppendLine($"\n[Category: {_cat.ToUpper()}]");
        sb.Append(challenge);
        return sb.ToString();
    }

    // ── API dispatch ───────────────────────────────────────────────────────
    private Task<string> CallApi(List<(string Role, string Content)> msgs) => _provider switch
    {
        "ollama" => CallOllama(msgs),
        "cursor" => CallCursor(msgs),
        _        => CallAnthropic(msgs)
    };

    // ── Anthropic ──────────────────────────────────────────────────────────
    private async Task<string> CallAnthropic(List<(string Role, string Content)> msgs)
    {
        string key = PbAnthropicKey.Password.Trim();
        if (string.IsNullOrEmpty(key)) return "ERROR: No Anthropic API key. Paste it in the top bar.";

        var msgArr = new JsonArray();
        foreach (var (r, c) in msgs) msgArr.Add(new JsonObject { ["role"] = r, ["content"] = c });

        var body = new JsonObject
        {
            ["model"]      = "claude-sonnet-4-20250514",
            ["max_tokens"] = 8192,
            ["system"]     = SYSTEM_PROMPT,
            ["messages"]   = msgArr
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.anthropic.com/v1/messages")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Add("x-api-key", key);
        req.Headers.Add("anthropic-version", "2023-06-01");

        var resp = await _http.SendAsync(req);
        string json = await resp.Content.ReadAsStringAsync();

        if (!resp.IsSuccessStatusCode)
        {
            try { return $"API Error {(int)resp.StatusCode}: {JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString()}"; }
            catch { return $"API Error {(int)resp.StatusCode}: {json[..Math.Min(300, json.Length)]}"; }
        }

        var doc = JsonDocument.Parse(json);
        var sb  = new StringBuilder();
        foreach (var c in doc.RootElement.GetProperty("content").EnumerateArray())
            if (c.GetProperty("type").GetString() == "text")
                sb.Append(c.GetProperty("text").GetString());
        return sb.ToString();
    }

    // ── Ollama ─────────────────────────────────────────────────────────────
    private async Task<string> CallOllama(List<(string Role, string Content)> msgs)
    {
        string host  = TbOllamaHost.Text.TrimEnd('/');
        string model = CbOllamaModel.Text.Trim();
        if (string.IsNullOrEmpty(model)) return "ERROR: No Ollama model selected. Click 'fetch'.";

        var msgArr = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = SYSTEM_PROMPT } };
        foreach (var (r, c) in msgs) msgArr.Add(new JsonObject { ["role"] = r, ["content"] = c });

        var body = new JsonObject
        {
            ["model"]    = model,
            ["messages"] = msgArr,
            ["stream"]   = false,
            ["options"]  = new JsonObject { ["num_predict"] = 8192, ["temperature"] = 0.7 }
        };

        try
        {
            var resp = await _http.PostAsync($"{host}/api/chat",
                new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"));
            string json = await resp.Content.ReadAsStringAsync();
            return JsonDocument.Parse(json).RootElement.GetProperty("message").GetProperty("content").GetString() ?? "";
        }
        catch (Exception ex) { return $"Cannot reach Ollama at {host}\n\nRun: ollama serve\n\nError: {ex.Message}"; }
    }

    // ── Cursor AI ──────────────────────────────────────────────────────────
    private async Task<string> CallCursor(List<(string Role, string Content)> msgs)
    {
        string key   = PbCursorKey.Password.Trim();
        string model = CbCursorModel.Text.Trim();
        if (string.IsNullOrEmpty(key)) return "ERROR: No Cursor AI API key.\n\nGet one at: https://cursor.com/settings";
        if (string.IsNullOrEmpty(model)) model = "cursor-small";

        var msgArr = new JsonArray { new JsonObject { ["role"] = "system", ["content"] = SYSTEM_PROMPT } };
        foreach (var (r, c) in msgs) msgArr.Add(new JsonObject { ["role"] = r, ["content"] = c });

        var body = new JsonObject
        {
            ["model"]       = model,
            ["messages"]    = msgArr,
            ["max_tokens"]  = 8192,
            ["temperature"] = 0.7
        };

        using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.cursor.sh/v1/chat/completions")
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key);

        try
        {
            var resp = await _http.SendAsync(req);
            string json = await resp.Content.ReadAsStringAsync();

            if (!resp.IsSuccessStatusCode)
            {
                try { return $"Cursor Error {(int)resp.StatusCode}: {JsonDocument.Parse(json).RootElement.GetProperty("error").GetProperty("message").GetString()}"; }
                catch { return $"Cursor Error {(int)resp.StatusCode}: {json[..Math.Min(300, json.Length)]}"; }
            }

            return JsonDocument.Parse(json).RootElement
                               .GetProperty("choices")[0]
                               .GetProperty("message")
                               .GetProperty("content")
                               .GetString() ?? "";
        }
        catch (Exception ex) { return $"Cursor request failed: {ex.Message}"; }
    }

    // ── Solve ──────────────────────────────────────────────────────────────
    private async void BtnSolve_Click(object sender, RoutedEventArgs e)
    {
        if (_loading) return;

        string ch = _chPh ? "" : ChallengeTxt.Text.Trim();
        if (string.IsNullOrEmpty(ch) && _files.Count == 0)
        {
            MessageBox.Show("Enter a challenge description or attach files.", "Nothing to solve",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _loading = true;
        BtnSolve.IsEnabled = false;
        BtnSolve.Content   = "  Analyzing...";
        SetStatus("running...", "#FFC14D");

        string display = string.IsNullOrEmpty(ch) ? $"[Analyzing {_files.Count} attached file(s)]" : ch;
        AddMessage("user", display);

        string content = BuildContent(string.IsNullOrEmpty(ch)
            ? "Analyze the attached files and solve this CTF challenge." : ch);
        _history.Add(("user", content));
        AddThinking();

        try
        {
            string reply = await CallApi(new List<(string, string)>(_history));
            StopThinking();
            if (reply.StartsWith("ERROR:"))
            {
                AddMessage("assistant", reply);
                _history.RemoveAt(_history.Count - 1);
            }
            else
            {
                _history.Add(("assistant", reply));
                AddMessage("assistant", reply);
            }
        }
        catch (Exception ex)
        {
            StopThinking();
            AddMessage("assistant", $"Error: {ex.Message}");
            _history.RemoveAt(_history.Count - 1);
        }

        _loading           = false;
        BtnSolve.IsEnabled = true;
        BtnSolve.Content   = "SOLVE CHALLENGE";
        SetStatus("complete  ready", "#00E5B0");
    }

    // ── Follow-up ──────────────────────────────────────────────────────────
    private async void BtnSend_Click(object sender, RoutedEventArgs e)
    {
        if (_loading || _fuPh) return;
        string text = FuEntry.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;

        FuEntry.Text       = FuPh;
        FuEntry.Foreground = B("#5A6A85");
        _fuPh = true;

        _loading          = true;
        BtnSend.IsEnabled = false;

        AddMessage("user", text);
        _history.Add(("user", text));
        AddThinking();

        try
        {
            string reply = await CallApi(new List<(string, string)>(_history));
            StopThinking();
            if (reply.StartsWith("ERROR:"))
            {
                AddMessage("assistant", reply);
                _history.RemoveAt(_history.Count - 1);
            }
            else
            {
                _history.Add(("assistant", reply));
                AddMessage("assistant", reply);
            }
        }
        catch (Exception ex)
        {
            StopThinking();
            AddMessage("assistant", $"Error: {ex.Message}");
            _history.RemoveAt(_history.Count - 1);
        }

        _loading          = false;
        BtnSend.IsEnabled = true;
        SetStatus("ready", "#00E5B0");
    }
}
