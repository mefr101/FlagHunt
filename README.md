# FlagHunt — AI-Powered CTF Solver

A Windows desktop app that sends Capture-The-Flag challenges (text, code, files) to an
AI model and renders the analysis, solution, flag, and explanation. Built with C# / .NET 8
(WPF) with a clean **frontend / backend split**.

Supports three providers:

- **Anthropic** (cloud) — Claude
- **Ollama** (local / offline)
- **Cursor AI** (cloud)

---

## Project layout

```
FlagHunt.slnx                  Solution
src/
  FlagHunt.Core/               Backend — no UI dependencies (net8.0)
    Models.cs                  ChatMessage, Attachment, CategoryInfo, ChatResult
    CtfKnowledge.cs            System prompt + category list
    Conversation.cs            Message-history state
    ContentBuilder.cs          Packs challenge text + attachments into a prompt
    Providers/                 IChatProvider + Anthropic / Ollama / Cursor
  FlagHunt.App/                Frontend — WPF GUI (net8.0-windows), references Core
    App.xaml                   Color palette resources
    MainWindow.xaml            Layout
    MainWindow.xaml.cs         UI logic; delegates all AI work to FlagHunt.Core
```

The frontend contains no HTTP/JSON/prompt logic — it reads the UI configuration, asks
`FlagHunt.Core` to build the request and run the selected provider, then renders the result.
The backend has no WPF reference, so it can be reused from a CLI or web host.

---

## Requirements

- Windows 10 or 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (or newer) to build
- The .NET 8 Desktop Runtime to run a published build on another machine
- Internet connection for Anthropic / Cursor, or [Ollama](https://ollama.com) running locally

---

## Build

From the repository root:

```powershell
# Restore and compile the whole solution
dotnet build FlagHunt.slnx

# Run directly (Debug)
dotnet run --project src/FlagHunt.App
```

### Produce a distributable build

```powershell
# Framework-dependent (small; target machine needs the .NET 8 Desktop Runtime)
dotnet publish src/FlagHunt.App -c Release -r win-x64

# Self-contained single .exe (large; no runtime install needed on the target)
dotnet publish src/FlagHunt.App -c Release -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true
```

The resulting `FlagHunt.exe` is written under
`src/FlagHunt.App/bin/Release/net8.0-windows/win-x64/publish/`.

---

## Operation

### 1. Pick a provider (top bar)

**Anthropic (cloud)**
- Select **Anthropic**
- Paste your API key (get one at [console.anthropic.com](https://console.anthropic.com); it starts with `sk-ant-`)
- Uses `claude-sonnet` — fast and capable

**Ollama (local / offline)**
- Install Ollama from [ollama.com](https://ollama.com)
- Start the server: `ollama serve`
- Pull a model: `ollama pull llama3`
- Select **Ollama (local)**, then click **fetch** to load your installed models
- Good CTF models: `llama3`, `deepseek-r1`, `qwen2.5-coder`, `mistral`

**Cursor AI (cloud)**
- Select **Cursor AI**
- Paste your API key (from [cursor.com/settings](https://cursor.com/settings))
- Pick a model from the dropdown (e.g. `cursor-small`, `gpt-4o`, `claude-3-5-sonnet`)

### 2. Solve a challenge

1. Pick a category in the sidebar, or leave it on **Auto** to let the AI detect the type.
2. Paste the challenge text — ciphertext, hex dump, source code, or a description.
3. Optionally **Attach Files** (binaries, pcaps, images, scripts).
4. Hit **SOLVE CHALLENGE**.
5. Use the follow-up bar at the bottom to ask questions or dig deeper.

Use **clear** to start a fresh session and **copy all** to copy the full conversation.

### File attachments

- Text / code files (`.py`, `.js`, `.c`, `.php`, …) are inlined as-is (up to ~60 KB each).
- Other files (binaries, pcaps, images, unknown formats) are base64-encoded and sent (truncated for size).

---

## Categories

| Category   | What it covers                                          |
|------------|---------------------------------------------------------|
| Auto       | Let the AI detect the challenge type                    |
| Web        | SQLi, XSS, SSRF, SSTI, JWT, deserialization, etc.       |
| Crypto     | Ciphers, RSA, AES, XOR, hash cracking, padding oracle   |
| Pwn        | Buffer overflows, ROP chains, heap exploitation         |
| Forensics  | File carving, pcap, memory/disk forensics               |
| Reversing  | Assembly, decompilation, anti-debug, packers            |
| Stego      | LSB, DCT, audio spectrograms, whitespace encoding       |
| OSINT      | Username enum, geolocation, WHOIS, Google dorking       |
| Networking | Pcap analysis, WiFi, protocol dissection                |
| Misc       | QR codes, Morse, esoteric languages, blockchain         |

---

## Troubleshooting

**Build fails: SDK not found**
→ Install the .NET 8 SDK and confirm with `dotnet --info`.

**"Cannot reach Ollama"**
→ Make sure `ollama serve` is running and the **HOST** field matches (default `http://localhost:11434`).

**Anthropic API key error**
→ Check the key at console.anthropic.com — it should start with `sk-ant-`.

**Cursor AI key error**
→ Get a key at cursor.com/settings and confirm the selected model is available to your account.
