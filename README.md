# FlagHunt — AI-Powered CTF Solver

A Windows desktop app that sends Capture-The-Flag challenges (text, code, files) to an
AI model and renders the analysis, solution, flag, and explanation. Built with C# / .NET 8
(WPF) with a clean **frontend / backend split**.

Supports four providers:

- **Anthropic** (cloud) — Claude
- **Ollama** (local / offline)
- **LM Studio** (local / offline) — any model loaded in LM Studio's OpenAI-compatible server
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
    Providers/                 IChatProvider + Anthropic / Ollama / LM Studio / Cursor
  FlagHunt.App/                Frontend — WPF GUI (net8.0-windows), references Core
    App.xaml                   Color palette resources
    MainWindow.xaml            Layout
    MainWindow.xaml.cs         UI logic; delegates all AI work to FlagHunt.Core
mcp/                           Optional MCP toolbox for agent mode (see below)
  docker-compose.yml           Runs the toolbox with sandboxing flags
  server/server.py             FastMCP server + the benign CTF analysis tools
  challenges/                  Attached files are staged here (mounted read-only)
```

In addition to single-shot chat, the **Anthropic** and **LM Studio** paths have an
optional **agent mode**: `FlagHunt.Core` connects to the MCP toolbox
(`Mcp/McpToolbox.cs`) and runs a tool-use loop so the model actually *runs*
decoders and file inspectors instead of only describing them.
`Providers/AnthropicAgentProvider.cs` drives Claude (Anthropic `tool_use` format)
and `Providers/LmStudioAgentProvider.cs` drives a local model (OpenAI `tool_calls`
format) — both reuse the same sandboxed toolbox.

The frontend contains no HTTP/JSON/prompt logic — it reads the UI configuration, asks
`FlagHunt.Core` to build the request and run the selected provider, then renders the result.
The backend has no WPF reference, so it can be reused from a CLI or web host.

---

## Requirements

- Windows 10 or 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) (or newer) to build
- The .NET 8 Desktop Runtime to run a published build on another machine
- Internet connection for Anthropic / Cursor, or [Ollama](https://ollama.com) / [LM Studio](https://lmstudio.ai) running locally
- For **LM Studio agent mode**: a function-calling-capable model loaded (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct) plus Docker for the toolbox

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
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

The resulting `FlagHunt.exe` is written under
`src/FlagHunt.App/bin/Release/net8.0-windows/win-x64/publish/`.

**Notes for the self-contained build:**

- It is not a *strictly* single file — WPF's native libraries can't all be
  embedded, so a few DLLs may sit beside the `.exe`.
  `-p:IncludeNativeLibrariesForSelfExtract=true` pulls as many as possible into
  the executable (they're unpacked to a temp folder at launch).
- Expect roughly **~150 MB**: a self-contained build bundles the entire .NET
  runtime. If the target machines already have the **.NET 8 Desktop Runtime**,
  use the framework-dependent build above for a much smaller output.
- **Do not enable trimming** (`-p:PublishTrimmed=true`) for this app. WPF relies
  heavily on reflection, and trimming routinely breaks XAML loading and data
  binding at runtime.

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

**LM Studio (local / offline)**
- Install [LM Studio](https://lmstudio.ai) and download a model.
- Start its OpenAI-compatible server: **Developer / Local Server** tab → **Start** (defaults to `http://localhost:1234`).
- Select **LM Studio (local)**, then click **fetch** to load the models currently served.
- The dropdown lists every served model, including embedding models — pick a **chat/instruct** model, not an embedding one.
- For **agent mode** (below) the model must support **function/tool calling** (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct).

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

The answer **streams in live** as the model generates it (all four providers). While
a response is running, **SOLVE CHALLENGE** turns into **STOP** — click it to cancel;
whatever streamed so far is kept.

**Header buttons:**

- **clear ws** — deletes challenge files staged in the MCP toolbox workspace
  (`mcp/challenges`) so agent-mode runs don't see leftovers from a previous
  challenge. Keeps the folder's `README.txt`; asks to confirm first; doesn't touch
  the current attachments or the conversation.
- **clear** — starts a fresh session (clears the conversation and attachments).
- **copy all** — copies the full conversation to the clipboard.

### File attachments

- Text / code files (`.py`, `.js`, `.c`, `.php`, …) are inlined as-is (up to ~60 KB each).
- Other files (binaries, pcaps, images, unknown formats) are base64-encoded and sent (truncated for size).

---

## Agent mode (MCP toolbox)

Single-shot chat tells you *how* to solve a challenge. **Agent mode** lets the
model *do* it: a sandboxed [MCP](https://modelcontextprotocol.io) server exposes
benign CTF analysis tools (encoding/crypto decoders, `file`/`strings`/`binwalk`/`exiftool`/
`steghide`, image & audio LSB stego via `zsteg`/`wav_lsb_extract`, pcap triage and
stream reassembly via `tshark`, `objdump`/`checksec`/pwntools, `jwt_decode`/`http_fetch`),
and FlagHunt
runs a tool-use loop — call the model, run whatever tools it asks for, feed the
results back, repeat — until the flag drops out. Tool calls stream live into the
conversation as they run, and independent tools requested in the same turn run
**in parallel**. On the Anthropic path, the system prompt and tool schemas are
**prompt-cached**, so each loop iteration reprocesses only the new turn.

Agent mode works with both **Anthropic** (Claude, cloud) and **LM Studio** (a
local model, fully offline). Both drive the *same* toolbox; only the tool-call
wire format differs (Anthropic `tool_use` vs OpenAI `tool_calls`). The toolbox
ships no exploit code, only analysis primitives; the model composes them.

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

> Requires Docker + Docker Compose. Agent mode is available on the **Anthropic**
> and **LM Studio** paths; Ollama and Cursor stay single-shot.

### 2. Turn on agent mode

**With Anthropic (Claude, cloud):**
- Select **Anthropic** and paste your API key.
- Tick **Agent mode**. The **MCP** endpoint defaults to `http://localhost:8000/mcp`.
- Attach files and/or paste the challenge, then **SOLVE CHALLENGE**.

**With LM Studio (local, offline):**
- Start LM Studio's local server with a **function-calling-capable** model loaded
  (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct). Plain chat/base models won't call tools.
- Select **LM Studio (local)** and click **fetch**; pick the loaded model.
- Tick **Agent mode**. The **MCP** endpoint defaults to `http://localhost:8000/mcp`.
- Attach files and/or paste the challenge, then **SOLVE CHALLENGE**.

In both cases attached files are copied into the toolbox workspace (`mcp/challenges/`)
so the file tools can read them by name. FlagHunt locates that folder automatically;
you can override it with the `FLAGHUNT_CHALLENGES_DIR` environment variable.

> **Tip:** to confirm the whole loop end to end, drop a file with a base64 blob into
> `mcp/challenges/` and ask *"There's a file `secret.txt` in the workspace. Find the
> flag."* A passing run shows live `list_workspace` → `base64_decode` tool calls in
> the AGENT card before the answer.

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

**"Cannot reach LM Studio" / empty model list**
→ Start LM Studio's local server (Developer / Local Server → Start) and confirm the
**HOST** field matches (default `http://localhost:1234`). Click **fetch** after a
model is loaded.

**LM Studio agent mode: model answers in prose but never calls a tool**
→ The loaded model doesn't support function calling. Load a tool-capable instruct
model (Qwen2.5-Instruct, Llama-3.1-Instruct). FlagHunt also prints a hint when a run
finishes without any tool call.

**Anthropic API key error**
→ Check the key at console.anthropic.com — it should start with `sk-ant-`.

**Cursor AI key error**
→ Get a key at cursor.com/settings and confirm the selected model is available to your account.

**Agent mode: "Cannot reach the MCP toolbox"**
→ Start it first with `cd mcp && docker compose up --build`, and confirm the **MCP**
field matches the endpoint (default `http://localhost:8000/mcp`). The server binds to
`0.0.0.0` inside the container so Docker's published port works; if you customise it,
keep it reachable from the host.
