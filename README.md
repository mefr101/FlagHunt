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
mcp/                           Optional MCP toolbox for agent mode (see below)
  docker-compose.yml           Runs the toolbox with sandboxing flags
  server/server.py             FastMCP server + the benign CTF analysis tools
  challenges/                  Attached files are staged here (mounted read-only)
```

In addition to single-shot chat, the Anthropic path has an optional **agent mode**:
`FlagHunt.Core` connects to the MCP toolbox (`Mcp/McpToolbox.cs`) and
`Providers/AnthropicAgentProvider.cs` runs a tool-use loop so Claude actually
*runs* decoders and file inspectors instead of only describing them.

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

## Agent mode (MCP toolbox)

Single-shot chat tells you *how* to solve a challenge. **Agent mode** lets Claude
*do* it: a sandboxed [MCP](https://modelcontextprotocol.io) server exposes benign
CTF analysis tools (encoding/crypto decoders, `file`/`strings`/`binwalk`/`exiftool`/
`steghide`, image & audio LSB stego via `zsteg`/`wav_lsb_extract`, pcap triage and
stream reassembly via `tshark`, `objdump`/`checksec`/pwntools, `jwt_decode`/`http_fetch`),
and FlagHunt
runs a tool-use loop — call the model, run whatever tools it asks for, feed the
results back, repeat — until the flag drops out. Tool calls stream live into the
conversation as they run.

The toolbox ships no exploit code, only analysis primitives; the model composes them.

### 1. Start the toolbox

```bash
cd mcp
docker compose up --build
```

This builds the sandboxed image and serves the Streamable HTTP endpoint at
`http://localhost:8000/mcp` (localhost only). The container runs non-root with a
read-only root filesystem, all Linux capabilities dropped, and resource caps;
challenge files are mounted **read-only**. See [mcp/README.md](mcp/README.md) for
the full security model and how to cut off network egress.

> Requires Docker + Docker Compose. Agent mode only changes the **Anthropic**
> path; Ollama and Cursor stay single-shot.

### 2. Turn on agent mode

- Select **Anthropic** and paste your API key.
- Tick **Agent mode**. The **MCP** endpoint defaults to `http://localhost:8000/mcp`.
- Attach files and/or paste the challenge, then **SOLVE CHALLENGE**.

Attached files are copied into the toolbox workspace (`mcp/challenges/`) so the
file tools can read them by name. FlagHunt locates that folder automatically; you
can override it with the `FLAGHUNT_CHALLENGES_DIR` environment variable.

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

**Agent mode: "Cannot reach the MCP toolbox"**
→ Start it first with `cd mcp && docker compose up --build`, and confirm the **MCP**
field matches the endpoint (default `http://localhost:8000/mcp`). The server binds to
`0.0.0.0` inside the container so Docker's published port works; if you customise it,
keep it reachable from the host.
