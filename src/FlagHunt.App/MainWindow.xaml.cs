using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using FlagHunt.Core;
using FlagHunt.Core.Agent;
using FlagHunt.Core.Providers;
using Microsoft.Win32;

namespace FlagHunt;

/// <summary>
/// Frontend only: builds the UI, manages presentation state, and delegates all CTF/AI work
/// (prompt, providers, content building, conversation history) to the FlagHunt.Core backend.
/// </summary>
public partial class MainWindow : Window
{
    // ── Colour helper ──────────────────────────────────────────────────────
    private static SolidColorBrush B(string hex) =>
        new((Color)ColorConverter.ConvertFromString(hex));

    // ── Backend state ──────────────────────────────────────────────────────
    private readonly Conversation _conv = new();
    private readonly List<Attachment> _files = [];

    // Prefill on a large prompt or a slow local model can take minutes; a fixed HTTP timeout
    // capped time-to-first-token and killed legitimate long runs. Let requests run unbounded
    // and govern them with the Stop button (CancellationToken), plus a generous safety cap so
    // a truly hung request still ends on its own. The cap cancels the same token the Stop
    // button uses, so a timeout is handled exactly like a manual stop.
    private static readonly HttpClient _http = new() { Timeout = Timeout.InfiniteTimeSpan };
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromMinutes(20);
    private static readonly TimeSpan ReviewTimeout = TimeSpan.FromMinutes(5);

    // ── UI state ───────────────────────────────────────────────────────────
    private string _provider = "anthropic";
    private string _cat = "auto";
    private bool _loading;
    private CancellationTokenSource? _cts;
    private bool _userStopped;   // distinguishes a Stop click from the RequestTimeout cap
    private bool _agentMode;
    private bool _lmStudioAgentMode;
    private StackPanel? _agentLog;
    private readonly SessionEventLog _log = new();
    private readonly Dictionary<string, Button> _catBtns = [];

    private bool _chPh = true;
    private bool _fuPh = true;
    private const string ChPh = "Paste challenge, ciphertext, hex dump, code, or anything...";
    private const string FuPh = "Ask a follow-up question...";

    // Thinking animation
    private DispatcherTimer? _thinkTimer;
    private StackPanel? _thinkFrame;
    private TextBlock? _thinkLbl;
    private int _thinkI;
    private static readonly string[] Dots = ["|", "/", "-", "\\"];

    // Streaming: a timer coalesces token deltas into ~50ms UI re-renders.
    private DispatcherTimer? _streamTimer;
    private bool _streamDirty;

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
        foreach (var cat in CtfKnowledge.Categories)
        {
            var btn = new Button { Content = cat.Label, Style = (Style)FindResource("CatBtn"), Tag = cat.Value };
            btn.Click += (s, _) => SelectCategory((string)((Button)s).Tag);
            _catBtns[cat.Value] = btn;
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
        OllamaCfg.Visibility = Visibility.Collapsed;
        CursorCfg.Visibility = Visibility.Collapsed;
        LmStudioCfg.Visibility = Visibility.Collapsed;
        SetStatus("anthropic  ready", "#00E5B0");
    }

    private void RbOllama_Checked(object sender, RoutedEventArgs e)
    {
        if (OllamaCfg is null) return;
        _provider = "ollama";
        AnthropicCfg.Visibility = Visibility.Collapsed;
        OllamaCfg.Visibility = Visibility.Visible;
        CursorCfg.Visibility = Visibility.Collapsed;
        LmStudioCfg.Visibility = Visibility.Collapsed;
        SetStatus("ollama  connecting...", "#9B6DFF");
        _ = FetchOllamaModels();
    }

    private void RbCursor_Checked(object sender, RoutedEventArgs e)
    {
        if (CursorCfg is null) return;
        _provider = "cursor";
        AnthropicCfg.Visibility = Visibility.Collapsed;
        OllamaCfg.Visibility = Visibility.Collapsed;
        LmStudioCfg.Visibility = Visibility.Collapsed;
        CursorCfg.Visibility = Visibility.Visible;
        SetStatus("cursor ai  ready", "#E879F9");
    }

    private void RbLmStudio_Checked(object sender, RoutedEventArgs e)
    {
        if (LmStudioCfg is null) return;
        _provider = "lmstudio";
        AnthropicCfg.Visibility = Visibility.Collapsed;
        OllamaCfg.Visibility = Visibility.Collapsed;
        CursorCfg.Visibility = Visibility.Collapsed;
        LmStudioCfg.Visibility = Visibility.Visible;
        SetStatus("lm studio  connecting...", "#FF6B35");
        _ = FetchLmStudioModels();
    }

    // ── Agent mode toggle ──────────────────────────────────────────────────
    private void ChkAgent_Changed(object sender, RoutedEventArgs e)
    {
        if (AgentCfg is null) return;
        _agentMode = ChkAgent.IsChecked == true;
        AgentCfg.Visibility = _agentMode ? Visibility.Visible : Visibility.Collapsed;
        SetStatus(_agentMode ? "anthropic  agent mode (MCP tools)" : "anthropic  ready", "#00E5B0");
    }

    private void ChkLmStudioAgent_Changed(object sender, RoutedEventArgs e)
    {
        if (LmStudioAgentCfg is null) return;
        _lmStudioAgentMode = ChkLmStudioAgent.IsChecked == true;
        LmStudioAgentCfg.Visibility = _lmStudioAgentMode ? Visibility.Visible : Visibility.Collapsed;
        SetStatus(_lmStudioAgentMode ? "lm studio  agent mode (MCP tools)" : "lm studio  ready", "#FF6B35");
    }

    // ── Ollama model fetch (delegates to backend) ──────────────────────────
    private async Task FetchOllamaModels()
    {
        var names = await OllamaProvider.FetchModelsAsync(_http, TbOllamaHost.Text);
        if (names.Count == 0)
        {
            SetStatus("ollama: cannot connect -- run: ollama serve", "#FF3B5C");
            return;
        }
        CbOllamaModel.ItemsSource = names;
        if (!names.Contains(CbOllamaModel.Text))
            CbOllamaModel.Text = names[0];
        SetStatus($"ollama  {names.Count} model(s) ready", "#9B6DFF");
    }

    private async void BtnFetchModels_Click(object sender, RoutedEventArgs e)
        => await FetchOllamaModels();

    // ── LM Studio model fetch ──────────────────────────────────────────────
    private async Task FetchLmStudioModels()
    {
        var names = await LmStudioProvider.FetchModelsAsync(_http, TbLmStudioHost.Text);
        if (names.Count == 0)
        {
            SetStatus("lm studio: no models loaded -- start the local server in LM Studio", "#FF3B5C");
            return;
        }
        CbLmStudioModel.ItemsSource = names;
        if (!names.Contains(CbLmStudioModel.Text))
            CbLmStudioModel.Text = names[0];
        SetStatus($"lm studio  {names.Count} model(s) ready", "#FF6B35");
    }

    private async void BtnFetchLmStudioModels_Click(object sender, RoutedEventArgs e)
        => await FetchLmStudioModels();

    // ── Category selection ─────────────────────────────────────────────────
    private void SelectCategory(string val)
    {
        _cat = val;
        foreach (var (v, btn) in _catBtns)
        {
            if (v == val)
            {
                btn.Background = B("#2E3A52");
                btn.Foreground = B("#00E5B0");
                btn.BorderBrush = B("#00E5B0");
            }
            else
            {
                btn.Background = B("#1E2535");
                btn.Foreground = B("#5A6A85");
                btn.BorderBrush = B("#252D40");
            }
        }
        string label = CtfKnowledge.Categories.FirstOrDefault(c => c.Value == val)?.Label ?? val;
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
            _files.Add(new Attachment(path, name));
            AddFileChip(path, name);
        }
    }

    private void AddFileChip(string path, string name)
    {
        string ext = name.Contains('.') ? name.Split('.').Last().ToUpper() : "FILE";
        if (ext.Length > 5) ext = ext[..5];

        var chip = new Border
        {
            Background = B("#1E2535"),
            BorderBrush = B("#252D40"),
            BorderThickness = new Thickness(1),
            Margin = new Thickness(0, 2, 0, 0)
        };

        var row = new DockPanel { LastChildFill = true };

        var badge = new Border { Background = B("#00E5B0"), Padding = new Thickness(4, 3, 4, 3), Margin = new Thickness(0, 0, 6, 0) };
        badge.Child = new TextBlock { Text = $" {ext} ", Foreground = Brushes.Black, FontFamily = new FontFamily("Segoe UI"), FontSize = 8, FontWeight = FontWeights.Bold };
        DockPanel.SetDock(badge, Dock.Left);
        row.Children.Add(badge);

        var rm = new Button
        {
            Content = "x",
            Background = Brushes.Transparent,
            Foreground = B("#3D4F6A"),
            BorderThickness = new Thickness(0),
            Padding = new Thickness(6, 3, 6, 3),
            Cursor = Cursors.Hand,
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 11
        };
        rm.Click += (_, _) => { _files.RemoveAll(f => f.Path == path); FilesList.Children.Remove(chip); };
        DockPanel.SetDock(rm, Dock.Right);
        row.Children.Add(rm);

        row.Children.Add(new TextBlock
        {
            Text = name.Length > 26 ? name[..26] + "..." : name,
            Foreground = B("#DDE6F5"),
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize = 10,
            VerticalAlignment = VerticalAlignment.Center,
            Padding = new Thickness(0, 4, 0, 4)
        });

        chip.Child = row;
        FilesList.Children.Add(chip);
    }

    // ── Placeholder helpers ────────────────────────────────────────────────
    private void ChallengeTxt_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_chPh) return;
        ChallengeTxt.Text = "";
        ChallengeTxt.Foreground = B("#DDE6F5");
        _chPh = false;
    }

    private void ChallengeTxt_LostFocus(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(ChallengeTxt.Text)) return;
        ChallengeTxt.Text = ChPh;
        ChallengeTxt.Foreground = B("#5A6A85");
        _chPh = true;
    }

    private void FuEntry_GotFocus(object sender, RoutedEventArgs e)
    {
        if (!_fuPh) return;
        FuEntry.Text = "";
        FuEntry.Foreground = B("#DDE6F5");
        _fuPh = false;
    }

    private void FuEntry_LostFocus(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(FuEntry.Text)) return;
        FuEntry.Text = FuPh;
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
        var brush = B(hex);
        StatusLabel.Text = text;
        StatusLabel.Foreground = brush;
        LedEllipse.Fill = brush;
    }

    // ── Welcome screen ─────────────────────────────────────────────────────
    private void ShowWelcome()
    {
        ConvPanel.Children.Clear();

        var outer = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 80, 0, 0), Tag = "welcome" };

        outer.Children.Add(new TextBlock
        {
            Text = "FlagHunt",
            Foreground = B("#DDE6F5"),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 32,
            FontWeight = FontWeights.Bold,
            HorizontalAlignment = HorizontalAlignment.Center
        });

        outer.Children.Add(new TextBlock
        {
            Text = "AI-Powered CTF Solver",
            Foreground = B("#00E5B0"),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 13,
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 2, 0, 16)
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
            Text = "\nPaste a challenge, attach files, pick a category, hit Solve",
            Foreground = B("#5A6A85"),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 10,
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
        var tb = BeginMessage(role);
        RenderText(tb, text);
    }

    /// <summary>
    /// Builds an empty message frame, adds it to the conversation, and returns its TextBlock so
    /// the caller can fill it in once (<see cref="AddMessage"/>) or incrementally (streaming).
    /// </summary>
    private TextBlock BeginMessage(string role)
    {
        RemoveWelcome();

        string roleLabel = role == "user" ? "YOU" :
                           _provider == "ollama" ? $"OLLAMA  {CbOllamaModel.Text}" :
                           _provider == "cursor" ? $"CURSOR AI  {CbCursorModel.Text}" :
                           _provider == "lmstudio" ? $"LM STUDIO  {CbLmStudioModel.Text}{(_lmStudioAgentMode ? " (agent)" : "")}" :
                           _agentMode ? "AI SOLVER  claude (agent)" : "AI SOLVER  claude";

        string roleHex = role == "user" ? "#4488FF" :
                          _provider == "ollama" ? "#9B6DFF" :
                          _provider == "cursor" ? "#E879F9" :
                          _provider == "lmstudio" ? "#FF6B35" : "#00E5B0";

        string bodyBg = role == "user" ? "#0E1420" : "#12151C";
        string bodyBorder = role == "user" ? "#4488FF" :
                            _provider == "ollama" ? "#9B6DFF" :
                            _provider == "cursor" ? "#E879F9" :
                            _provider == "lmstudio" ? "#FF6B35" : "#252D40";

        var outer = new StackPanel { Margin = new Thickness(20, 0, 20, 12) };

        var labelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        labelRow.Children.Add(new Border { Width = 3, Background = B(roleHex), Margin = new Thickness(0, 0, 4, 0) });
        labelRow.Children.Add(new TextBlock
        {
            Text = $"  {roleLabel}",
            Foreground = B(roleHex),
            FontFamily = new FontFamily("Segoe UI"),
            FontSize = 8,
            FontWeight = FontWeights.Bold,
            VerticalAlignment = VerticalAlignment.Center
        });
        outer.Children.Add(labelRow);

        var body = new Border
        {
            Background = B(bodyBg),
            BorderBrush = B(bodyBorder),
            BorderThickness = new Thickness(1),
            Padding = new Thickness(14, 12, 14, 12)
        };

        var tb = new TextBlock
        {
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize = 10,
            Foreground = B("#DDE6F5"),
            LineHeight = 18
        };

        body.Child = tb;
        outer.Children.Add(body);

        ConvPanel.Children.Add(outer);
        ChatScroll.ScrollToEnd();
        return tb;
    }

    private static void RenderText(TextBlock tb, string text)
    {
        bool inCode = false;
        string[] lines = text.Split('\n');

        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0) tb.Inlines.Add(new LineBreak());
            string line = lines[i];

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

            var fm = Regex.Match(line, @"((?:flag|ctf|CTF|FLAG)\{[^}]+\})");
            if (fm.Success)
            {
                if (fm.Index > 0) tb.Inlines.Add(new Run(line[..fm.Index]));
                tb.Inlines.Add(new Run($"  {fm.Value}  ") { Background = B("#091E18"), Foreground = B("#00E5B0"), FontWeight = FontWeights.Bold, FontSize = 11 });
                if (fm.Index + fm.Length < line.Length) tb.Inlines.Add(new Run(line[(fm.Index + fm.Length)..]));
                continue;
            }

            if (line.Contains("**"))
            {
                var parts = Regex.Split(line, @"\*\*(.*?)\*\*");
                for (int j = 0; j < parts.Length; j++)
                    tb.Inlines.Add(j % 2 == 1
                        ? new Run(parts[j]) { FontWeight = FontWeights.Bold }
                        : new Run(parts[j]));
                continue;
            }

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
        string rc = _provider == "ollama" ? "#9B6DFF" : _provider == "cursor" ? "#E879F9" : _provider == "lmstudio" ? "#FF6B35" : "#00E5B0";

        var outer = new StackPanel { Margin = new Thickness(20, 0, 20, 12), Tag = "thinking" };

        var labelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
        labelRow.Children.Add(new Border { Width = 3, Background = B(rc), Margin = new Thickness(0, 0, 4, 0) });
        labelRow.Children.Add(new TextBlock { Text = "  AI SOLVER", Foreground = B(rc), FontFamily = new FontFamily("Segoe UI"), FontSize = 8, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center });
        outer.Children.Add(labelRow);

        _thinkLbl = new TextBlock
        {
            Text = "|  analyzing challenge...",
            Foreground = B("#5A6A85"),
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize = 10
        };

        var body = new Border { Background = B("#12151C"), BorderBrush = B("#252D40"), BorderThickness = new Thickness(1), Padding = new Thickness(14, 12, 14, 12) };
        body.Child = _thinkLbl;
        outer.Children.Add(body);

        ConvPanel.Children.Add(outer);
        ChatScroll.ScrollToEnd();

        _thinkFrame = outer;
        _thinkI = 0;
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

    // ── Streaming render ────────────────────────────────────────────────────
    /// <summary>
    /// Starts a timer that re-renders <paramref name="target"/> from <paramref name="buffer"/>
    /// at most every ~50ms while tokens stream in, so a fast token rate can't thrash the UI.
    /// RenderText re-parses the whole accumulated text each tick, which keeps multi-line
    /// markdown (code fences, bold, flag highlighting) correct as tokens straddle boundaries.
    /// </summary>
    private void StartStreamTimer(TextBlock target, StringBuilder buffer)
    {
        _streamDirty = false;
        _streamTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(50) };
        _streamTimer.Tick += (_, _) =>
        {
            if (!_streamDirty) return;
            _streamDirty = false;
            target.Inlines.Clear();
            RenderText(target, buffer.ToString());
            ChatScroll.ScrollToEnd();
        };
        _streamTimer.Start();
    }

    private void StopStreamTimer()
    {
        _streamTimer?.Stop();
        _streamTimer = null;
    }

    // ── Agent activity log (live MCP tool calls) ────────────────────────────
    /// <summary>Renders one agent event into a live "AGENT" card, creating it on first use.</summary>
    private void OnAgentActivity(AgentActivity a)
    {
        _log.LogActivity(a);
        if (_agentLog is null)
        {
            RemoveWelcome();
            var outer = new StackPanel { Margin = new Thickness(20, 0, 20, 12) };

            var labelRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
            labelRow.Children.Add(new Border { Width = 3, Background = B("#FFC14D"), Margin = new Thickness(0, 0, 4, 0) });
            labelRow.Children.Add(new TextBlock { Text = "  AGENT  mcp toolbox", Foreground = B("#FFC14D"), FontFamily = new FontFamily("Segoe UI"), FontSize = 8, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center });
            outer.Children.Add(labelRow);

            var body = new Border { Background = B("#12151C"), BorderBrush = B("#2E3A52"), BorderThickness = new Thickness(1), Padding = new Thickness(14, 10, 14, 10) };
            _agentLog = new StackPanel();
            body.Child = _agentLog;
            outer.Children.Add(body);

            // Insert the activity card just above the thinking spinner if present.
            int idx = _thinkFrame is not null ? ConvPanel.Children.IndexOf(_thinkFrame) : ConvPanel.Children.Count;
            ConvPanel.Children.Insert(Math.Max(0, idx), outer);
        }

        (string prefix, string hex) = a.Kind switch
        {
            AgentActivityKind.ToolCall   => ("-> ", "#00E5B0"),
            AgentActivityKind.ToolResult => ("   ", "#5A6A85"),
            _                            => (".  ", "#9B6DFF"),
        };

        _agentLog.Children.Add(new TextBlock
        {
            Text = prefix + a.Text,
            Foreground = B(hex),
            FontFamily = new FontFamily("Cascadia Code, Consolas, monospace"),
            FontSize = 10,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 1, 0, 1)
        });
        ChatScroll.ScrollToEnd();
    }

    /// <summary>
    /// Resolves the host folder that the MCP toolbox mounts read-only at /workspace.
    /// Order: FLAGHUNT_CHALLENGES_DIR env var, then a discovered <c>mcp/challenges</c>
    /// next to <c>docker-compose.yml</c>, else a <c>challenges</c> folder beside the app.
    /// </summary>
    private static string ResolveChallengesDir()
    {
        string? env = Environment.GetEnvironmentVariable("FLAGHUNT_CHALLENGES_DIR");
        if (!string.IsNullOrWhiteSpace(env)) return env;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "mcp", "challenges");
            if (File.Exists(Path.Combine(dir.FullName, "mcp", "docker-compose.yml")))
                return candidate;
        }
        return Path.Combine(AppContext.BaseDirectory, "challenges");
    }

    /// <summary>Copies attached files into the toolbox workspace so the file tools can see them.</summary>
    private string CopyAttachmentsToWorkspace()
    {
        string dir = ResolveChallengesDir();
        Directory.CreateDirectory(dir);
        foreach (var f in _files)
        {
            try { File.Copy(f.Path, Path.Combine(dir, f.Name), overwrite: true); }
            catch (Exception ex) { OnAgentActivity(AgentActivity.Signaled(LogSignal.StageFailed, $"could not stage {f.Name}: {ex.Message}", f.Name)); }
        }
        return dir;
    }

    // ── Clear / Copy ───────────────────────────────────────────────────────
    private void BtnClear_Click(object sender, RoutedEventArgs e)
    {
        _conv.Clear();
        _files.Clear();
        FilesList.Children.Clear();
        _log.Clear();
        ShowWelcome();
        SetStatus("cleared  ready", "#5A6A85");
    }

    /// <summary>Deletes challenge files staged into the MCP toolbox workspace (mcp/challenges)
    /// so the agent's file tools don't see leftovers from a previous challenge. Keeps the
    /// folder's README.txt. Does not touch the current attachment chips or the conversation.</summary>
    private void BtnClearWorkspace_Click(object sender, RoutedEventArgs e)
    {
        string dir = ResolveChallengesDir();
        if (!Directory.Exists(dir))
        {
            SetStatus("workspace already empty", "#5A6A85");
            return;
        }

        // Everything staged for the toolbox, minus the README the folder ships with.
        var entries = Directory.EnumerateFileSystemEntries(dir)
            .Where(p => !string.Equals(Path.GetFileName(p), "README.txt", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (entries.Count == 0)
        {
            SetStatus("workspace already empty", "#5A6A85");
            return;
        }

        var confirm = MessageBox.Show(
            $"Delete {entries.Count} staged item(s) from the toolbox workspace?\n\n{dir}\n\nThis cannot be undone.",
            "Clear workspace", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes) return;

        int removed = 0;
        var failures = new List<string>();
        foreach (var p in entries)
        {
            try
            {
                if (Directory.Exists(p)) Directory.Delete(p, recursive: true);
                else File.Delete(p);
                removed++;
            }
            catch (Exception ex)
            {
                failures.Add($"{Path.GetFileName(p)}: {ex.Message}");
            }
        }

        if (failures.Count > 0)
            MessageBox.Show("Some items could not be deleted:\n\n" + string.Join("\n", failures),
                            "Clear workspace", MessageBoxButton.OK, MessageBoxImage.Warning);

        SetStatus($"cleared {removed} item(s) from workspace", "#00E5B0");
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

    /// <summary>Writes the timestamped session event log (agent decisions, tool results, and
    /// outcomes, plus the rule-based postmortem) to a user-chosen .txt file. When the
    /// "AI review" box is checked, this log also gets a model-written review appended.</summary>
    private async void BtnSaveLog_Click(object sender, RoutedEventArgs e)
    {
        if (_log.Count == 0)
        {
            SetStatus("nothing to log yet", "#5A6A85");
            return;
        }

        var dlg = new SaveFileDialog
        {
            Title = "Save session log",
            FileName = $"flaghunt-log-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            Filter = "Text file (*.txt)|*.txt|All files (*.*)|*.*",
            DefaultExt = ".txt",
        };
        if (dlg.ShowDialog() != true) return;

        bool review = ChkAiReview.IsChecked == true;
        var header = new[]
        {
            new KeyValuePair<string, string>("Provider", _provider),
            new KeyValuePair<string, string>("Category", _cat),
            new KeyValuePair<string, string>("Agent mode",
                ((_provider == "anthropic" && _agentMode) || (_provider == "lmstudio" && _lmStudioAgentMode)) ? "on" : "off"),
            new KeyValuePair<string, string>("AI review", review ? "on" : "off"),
        };

        string text = _log.Render(header);
        bool reviewFailed = false;
        if (review)
        {
            BtnSaveLog.IsEnabled = false;
            ChkAiReview.IsEnabled = false;
            SetStatus($"reviewing log with {_provider}...", "#FFC14D");
            try
            {
                // Own token: a log review must not be cancelled by (or cancel) a running solve.
                using var cts = new CancellationTokenSource(ReviewTimeout);
                var result = await LogReviewer.ReviewAsync(BuildChatProvider(LogReviewer.SystemPrompt), text, cts.Token);
                reviewFailed = !result.Success;
                text = LogReviewer.Append(text, result);
            }
            finally
            {
                BtnSaveLog.IsEnabled = true;
                ChkAiReview.IsEnabled = true;
            }
        }

        try
        {
            File.WriteAllText(dlg.FileName, text);
            SetStatus(reviewFailed ? $"log saved, AI review failed  {Path.GetFileName(dlg.FileName)}"
                                   : $"log saved  {Path.GetFileName(dlg.FileName)}",
                      reviewFailed ? "#FFC14D" : "#00E5B0");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Could not save the log:\n\n{ex.Message}", "Save log",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            SetStatus("log save failed", "#FF6B6B");
        }
    }

    // ── Provider construction (frontend config -> backend provider) ─────────
    private IChatProvider BuildProvider()
    {
        switch (_provider)
        {
            case "lmstudio" when _lmStudioAgentMode:
                var lmOpts = new LmStudioOptions(TbLmStudioHost.Text, CbLmStudioModel.Text.Trim())
                {
                    UseTools = true, McpUrl = TbLmStudioMcpUrl.Text.Trim(), Category = _cat,
                };
                // Progress is captured on the UI thread, so handlers run there too.
                var lmProgress = new Progress<AgentActivity>(OnAgentActivity);
                return new LmStudioAgentProvider(_http, lmOpts, lmProgress);
            case "anthropic" when _agentMode:
                var anthOpts = new AnthropicOptions(PbAnthropicKey.Password)
                {
                    UseTools = true, McpUrl = TbMcpUrl.Text.Trim(), Category = _cat,
                };
                // Progress is captured on the UI thread, so handlers run there too.
                var progress = new Progress<AgentActivity>(OnAgentActivity);
                return new AnthropicAgentProvider(_http, anthOpts, progress);
            default:
                return BuildChatProvider();
        }
    }

    /// <summary>The selected backend as a plain chat provider (never an agent). A non-null
    /// <paramref name="systemPrompt"/> replaces the CTF-solver prompt and lowers the temperature,
    /// for analytical calls such as the AI log review.</summary>
    private IChatProvider BuildChatProvider(string? systemPrompt = null)
    {
        const double analyticalTemperature = 0.2;
        switch (_provider)
        {
            case "ollama":
                var ollama = new OllamaOptions(TbOllamaHost.Text, CbOllamaModel.Text.Trim()) { SystemPrompt = systemPrompt };
                if (systemPrompt is not null) ollama = ollama with { Temperature = analyticalTemperature };
                return new OllamaProvider(_http, ollama);
            case "cursor":
                var cursor = new CursorOptions(PbCursorKey.Password, CbCursorModel.Text.Trim()) { SystemPrompt = systemPrompt };
                if (systemPrompt is not null) cursor = cursor with { Temperature = analyticalTemperature };
                return new CursorProvider(_http, cursor);
            case "lmstudio":
                var lm = new LmStudioOptions(TbLmStudioHost.Text, CbLmStudioModel.Text.Trim()) { SystemPrompt = systemPrompt };
                if (systemPrompt is not null) lm = lm with { Temperature = analyticalTemperature };
                return new LmStudioProvider(_http, lm);
            default:
                return new AnthropicProvider(_http, new AnthropicOptions(PbAnthropicKey.Password) { SystemPrompt = systemPrompt });
        }
    }

    // ── Busy state (also turns the Solve button into a Stop control) ────────
    private void EnterBusy()
    {
        _loading = true;
        _userStopped = false;
        _cts = new CancellationTokenSource();
        _cts.CancelAfter(RequestTimeout);   // safety cap; a manual Stop cancels the same token
        BtnSolve.Content = "  STOP";
        BtnSolve.IsEnabled = true;   // stays clickable so a click cancels the run
        BtnSend.IsEnabled = false;
    }

    private void ExitBusy()
    {
        _loading = false;
        _cts?.Dispose();
        _cts = null;
        BtnSolve.Content = "SOLVE CHALLENGE";
        BtnSolve.IsEnabled = true;
        BtnSend.IsEnabled = true;
    }

    // ── Solve ──────────────────────────────────────────────────────────────
    private async void BtnSolve_Click(object sender, RoutedEventArgs e)
    {
        if (_loading) { _userStopped = true; _cts?.Cancel(); return; }   // second click = Stop

        string ch = _chPh ? "" : ChallengeTxt.Text.Trim();
        if (string.IsNullOrEmpty(ch) && _files.Count == 0)
        {
            MessageBox.Show("Enter a challenge description or attach files.", "Nothing to solve",
                            MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        EnterBusy();
        SetStatus("running...", "#FFC14D");

        string display = string.IsNullOrEmpty(ch) ? $"[Analyzing {_files.Count} attached file(s)]" : ch;
        AddMessage("user", display);

        bool agentModeOn = (_provider == "anthropic" && _agentMode)
                          || (_provider == "lmstudio" && _lmStudioAgentMode);
        _log.Log(LogCategory.Session,
            $"Challenge submitted (provider={_provider}, category={_cat}, agent mode={(agentModeOn ? "on" : "off")}, " +
            $"attachments={_files.Count}): {display}",
            signal: LogSignal.RunStart, value: "challenge", number: _files.Count);

        // In agent mode, stage attachments into the toolbox workspace so the file
        // tools (list_workspace, file_type, strings_extract, ...) can read them.
        _agentLog = null;
        bool agentActive = (_provider == "anthropic" && _agentMode)
                           || (_provider == "lmstudio" && _lmStudioAgentMode);
        if (agentActive && _files.Count > 0)
        {
            string dir = CopyAttachmentsToWorkspace();
            OnAgentActivity(AgentActivity.Info($"staged {_files.Count} file(s) into workspace: {dir}"));
        }

        string content = ContentBuilder.Build(
            _cat,
            string.IsNullOrEmpty(ch) ? "Analyze the attached files and solve this CTF challenge." : ch,
            _files,
            agentMode: agentActive);
        _conv.AddUser(content);
        AddThinking();

        await RunCompletion(_cts!.Token);

        bool stopped = _cts?.IsCancellationRequested == true;
        ExitBusy();
        SetStatus(stopped ? "stopped  ready" : "complete  ready", stopped ? "#FFC14D" : "#00E5B0");
    }

    // ── Follow-up ──────────────────────────────────────────────────────────
    private async void BtnSend_Click(object sender, RoutedEventArgs e)
    {
        if (_loading || _fuPh) return;
        string text = FuEntry.Text.Trim();
        if (string.IsNullOrEmpty(text)) return;

        FuEntry.Text = FuPh;
        FuEntry.Foreground = B("#5A6A85");
        _fuPh = true;

        EnterBusy();

        AddMessage("user", text);
        _conv.AddUser(text);
        _log.Log(LogCategory.Session, $"Follow-up: {text}", signal: LogSignal.RunStart, value: "follow-up");
        _agentLog = null;
        AddThinking();

        await RunCompletion(_cts!.Token);

        bool stopped = _cts?.IsCancellationRequested == true;
        ExitBusy();
        SetStatus(stopped ? "stopped  ready" : "ready", stopped ? "#FFC14D" : "#00E5B0");
    }

    /// <summary>Runs the configured provider against the current history and renders the reply,
    /// streaming tokens into a live message frame when the provider supports it.</summary>
    private async Task RunCompletion(CancellationToken ct)
    {
        var provider = BuildProvider();
        var sb = new StringBuilder();
        TextBlock? live = null;

        // Progress is created on the UI thread, so this callback runs there too -- safe to
        // touch controls. The live frame is created lazily on the first streamed token.
        var onToken = new Progress<string>(delta =>
        {
            if (live is null)
            {
                StopThinking();
                live = BeginMessage("assistant");
                StartStreamTimer(live, sb);
            }
            sb.Append(delta);
            _streamDirty = true;
        });

        try
        {
            ChatResult result = await provider.CompleteAsync(_conv.Messages, onToken, ct);
            StopStreamTimer();
            StopThinking();

            // Providers usually swallow cancellation and return the partial text as a success,
            // so check the token to record a Stop or timeout rather than a "final answer".
            if (ct.IsCancellationRequested)
                LogStopped(result.Text);
            else if (result.Success)
                _log.Log(LogCategory.Result, $"Final answer:\n{result.Text}", signal: LogSignal.FinalAnswer);
            else
                _log.Log(LogCategory.Result, $"Error: {result.Text}", signal: LogSignal.Error);

            if (live is null)
            {
                // Provider didn't stream (agent mode, or it errored before any token).
                AddMessage("assistant", result.Text);
            }
            else
            {
                // Final authoritative render: replaces the streamed text with the full result.
                live.Inlines.Clear();
                RenderText(live, result.Text);
                ChatScroll.ScrollToEnd();
            }

            if (result.Success) _conv.AddAssistant(result.Text);
            else _conv.RemoveLast();
        }
        catch (OperationCanceledException)
        {
            // Providers usually swallow cancellation and return partial text; this guards the
            // agent path or any provider that lets it propagate. Keep whatever streamed so far.
            StopStreamTimer();
            StopThinking();
            string partial = sb.ToString();
            LogStopped(partial);
            if (live is not null && partial.Length > 0)
            {
                live.Inlines.Clear();
                RenderText(live, partial + "\n\n[stopped]");
                ChatScroll.ScrollToEnd();
                _conv.AddAssistant(partial);
            }
            else
            {
                _conv.RemoveLast();
            }
        }
        catch (Exception ex)
        {
            StopStreamTimer();
            StopThinking();
            _log.Log(LogCategory.Result, $"Error: {ex.Message}", signal: LogSignal.Error);
            AddMessage("assistant", $"Error: {ex.Message}");
            _conv.RemoveLast();
        }
    }

    /// <summary>Records a cancelled run as a user Stop or a safety timeout, keeping any partial answer.</summary>
    private void LogStopped(string partial)
    {
        string why = _userStopped ? "Stopped by user" : $"Timed out after {RequestTimeout.TotalMinutes:0} min";
        _log.Log(LogCategory.Result,
                 partial.Length > 0 ? $"{why}. Partial answer kept:\n{partial}" : $"{why} before any answer streamed.",
                 signal: _userStopped ? LogSignal.Stopped : LogSignal.TimedOut);
    }
}
