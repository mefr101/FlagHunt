# CTF MCP toolbox

A sandboxed toolbox for an AI agent that helps solve Capture-the-Flag
challenges. A containerised **MCP server** (Python / FastMCP) exposes
general-purpose analysis utilities; a small **C# client** discovers those tools,
drives an Anthropic model through an agent loop, and runs whatever the model
asks for.

```
ctf-mcp-toolbox/
├── docker-compose.yml         # runs the server with sandboxing flags
├── challenges/                # drop challenge files here (mounted read-only)
├── server/
│   ├── server.py              # FastMCP server + the CTF tools
│   ├── requirements.txt
│   └── Dockerfile             # non-root image with the CLI tools installed
└── client/
    ├── CtfAgent.csproj        # references the MCP C# SDK
    ├── Program.cs             # MCP connection + agent loop
    └── AnthropicClient.cs     # Messages API wrapper (raw HTTP)
```

## How the pieces fit

The model lives behind the Anthropic API and decides *which* tool to call. The
**agent loop in `Program.cs`** is what actually runs: it calls the model, gets
back `tool_use` requests, dispatches them to the MCP server, feeds the
`tool_result` back, and repeats until the model stops. The **MCP server** has no
model and no loop — it is just a well-described, sandboxed set of utilities.

## Prerequisites

- Docker + Docker Compose
- .NET 8 SDK (for the client)
- An Anthropic API key in `ANTHROPIC_API_KEY`

## Run the server

```bash
docker compose up --build
```

This builds the image, starts the toolbox, and exposes the Streamable HTTP
endpoint at `http://localhost:8000/mcp` (localhost only).

## Run the client

```bash
cd client
export ANTHROPIC_API_KEY=sk-ant-...        # you set this yourself; the code only reads it
dotnet run
```

Then describe the challenge, e.g. *"There's a file `challenge.bin` in the
workspace — find the flag."* The agent will list the workspace, inspect the
file, and chain tools as needed.

Overridable env vars: `CTF_MCP_URL` (default `http://localhost:8000/mcp`),
`CTF_MODEL` (default `claude-sonnet-4-6`).

## Tools exposed

| Category   | Tools |
|------------|-------|
| Encoding / crypto | `base64_decode`, `base64_encode`, `hex_decode`, `rot13`, `caesar_bruteforce`, `xor_hex`, `url_decode`, `identify_hash`, `hash_text` |
| Forensics  | `list_workspace`, `file_type`, `strings_extract`, `binwalk_scan`, `exif_metadata`, `steghide_extract` |
| Steganography | `zsteg_scan` (image LSB detection, PNG/BMP), `wav_lsb_extract` (audio LSB extraction) |
| Reversing / pwn | `disassemble`, `checksec`, `cyclic_pattern`, `cyclic_find` |
| Networking (pcap) | `pcap_overview` (triage: protocol hierarchy + conversations), `pcap_follow_stream` (reassemble one TCP/UDP stream) |
| Web        | `jwt_decode`, `http_fetch` |

These are deliberately benign analysis primitives — decoders, file inspection,
disassembly, offset-finding. There is no exploit code; the model composes these
building blocks itself.

## Security model

The container is treated as hostile and the host as precious:

- **Read-only root filesystem** (`read_only: true`); the only writable area is a
  RAM-backed `tmpfs` at `/tmp` that vanishes on stop.
- **Non-root** user, **all Linux capabilities dropped**, and
  `no-new-privileges` to block setuid escalation.
- **Resource caps** (CPU, memory, PID count) to contain a runaway tool.
- **Challenge files mounted read-only**, and every path argument is validated to
  stay inside `/workspace` so a tool call can't read `/etc/shadow`.
- The endpoint is bound to **localhost only**.

For maximum containment with challenge sets that need no network, set
`internal: true` on the `ctfnet` network in `docker-compose.yml` to cut off
egress entirely. For per-challenge isolation, run a fresh container per session
and tear it down afterward rather than reusing one long-lived container.

## Authorisation

Point this only at CTF infrastructure you are authorised to use — your own
challenges, a CTF platform's scoped targets, or intentionally vulnerable
practice machines. The `http_fetch` tool in particular reaches the network; keep
it aimed at in-scope hosts. The sandboxing above protects your host *and* keeps
the tooling from being accidentally aimed at systems outside the competition.

## Extending it

Add a tool by writing a function decorated with `@mcp.tool()` in `server.py`.
The docstring becomes the description the model reads, so make it specific. The
client needs no changes — it discovers tools dynamically at startup.

If you want recon tooling (port scans, directory brute-forcing), add it as a
separate, clearly-scoped tool with an explicit target allowlist, and prefer
running it against a network that can only reach the challenge host.

## Version notes

- The MCP **C# SDK** is at v1.0 but evolving; if `HttpClientTransport` /
  `HttpClientTransportOptions` don't resolve, check the names for your installed
  version (older previews used `SseClientTransport` with `UseStreamableHttp`).
- The **Anthropic** model string and Messages API tool-use format change over
  time — verify against https://docs.claude.com/en/api/overview.
