# CTF MCP toolbox

A sandboxed toolbox for an AI agent that helps solve Capture-the-Flag
challenges. A containerised **MCP server** (Python / FastMCP) exposes
general-purpose analysis utilities; a small **C# client** discovers those tools,
drives a model through an agent loop, and runs whatever the model asks for.

The toolbox is **model-agnostic**: the FlagHunt app can drive it with either the
Anthropic API (`AnthropicAgentProvider`) or a fully-local LM Studio model
(`LmStudioAgentProvider`). The only difference is the tool-call wire format
(Anthropic `tool_use` vs OpenAI `tool_calls`); the server, tools, and sandbox
are identical. Tool calling with LM Studio requires a function-calling-capable
model (e.g. Qwen2.5-Instruct, Llama-3.1-Instruct) loaded with the local server
enabled.

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

The model decides *which* tool to call. The **agent loop** (in the app's
`AnthropicAgentProvider` / `LmStudioAgentProvider`) is what actually runs: it
calls the model, gets back tool-call requests, dispatches them to the MCP
server, feeds the results back, and repeats until the model stops. The **MCP
server** has no model and no loop — it is just a well-described, sandboxed set
of utilities, so the same server backs both providers.

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

The server exposes ~130 tools grouped into domain toolboxes. Tool names are
prefixed by toolbox so the client can filter them (see *Category filtering* below).

| Toolbox | Prefix | Examples |
|---------|--------|----------|
| Core encoding / crypto | *(none)* | `base64_decode`, `hex_decode`, `rot13`, `caesar_bruteforce`, `xor_hex`, `identify_hash`, `hash_text` |
| Core forensics / stego | *(none)* | `list_workspace`, `file_type`, `strings_extract`, `binwalk_scan`, `exif_metadata`, `steghide_extract`, `zsteg_scan`, `wav_lsb_extract` |
| Core reversing / pwn | *(none)* | `disassemble`, `checksec`, `cyclic_pattern`, `cyclic_find` |
| Core web / net | *(none)* | `jwt_decode`, `http_fetch`, `pcap_overview`, `pcap_follow_stream` |
| Pwn | `pwn_` | `pwn_elf_info`, `pwn_find_gadgets`, `pwn_rop_chain`, `pwn_shellcode`, `pwn_format_string` |
| Web exploitation | `web_` | `web_sqli_test`, `web_jwt_attacks`, `web_ssti_detect`, `web_lfi_test`, `web_ssrf_payloads` |
| Reverse engineering | `re_` | `re_disassemble_function`, `re_decompile_hint`, `re_angr_solve`, `re_z3_constraint_solve` |
| Networking | `net_` | `net_port_scan`, `net_banner_grab`, `net_dns_lookup`, `net_pcap_extract_creds`, `net_ssl_info` |
| OSINT | `osint_` | `osint_username_search`, `osint_domain_recon`, `osint_ip_investigate`, `osint_wayback_urls` |
| Forensics | `forens_` | `forens_carve_files`, `forens_image_lsb`, `forens_audio_spectrogram`, `forens_yara_hunt`, `forens_timeline` |
| Red team (offensive) | `red_` | `red_sql_payloads`, `red_xss_payloads`, `red_ssti_payloads`, `red_jwt_forge`, `red_reverse_shell` |
| Blue team (defensive) | `blue_` | `blue_ioc_extract`, `blue_yara_scan`, `blue_detect_webshell`, `blue_log_hunt` |

Most tools are analysis primitives (decoders, file inspection, disassembly), but
this set is **broader than the original benign-only toolbox** — the `red_` tools
generate offensive payloads/wordlists, and the `net_` / `osint_` tools perform
**active network scanning and live external recon** (see *Authorisation*).

### Category filtering (client side)

Handing all ~130 tool schemas to the model on every request bloats prefill and
degrades local models. The FlagHunt app filters the discovered tools by the CTF
**category** selected in the sidebar (`McpToolbox.ToolsForCategory`): a universal
core (triage + decoders) plus the tools whose prefix matches the category, so the
model typically sees 15–40 tools rather than all 130. `Auto`/`Misc` get a broad
cross-domain triage set. This is purely a client-side view — the server still
exposes every tool.

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

**Only point this at CTF infrastructure you are explicitly authorised to test** —
your own challenges, a CTF platform's scoped targets, or intentionally vulnerable
practice machines. This matters more than it did for the original benign toolbox,
because several tools now reach or attack external systems:

- **Active network tools** (`net_port_scan`, `net_banner_grab`, `net_traceroute`,
  `http_fetch`) connect to whatever host you point them at — scanning hosts you
  don't own is likely illegal.
- **OSINT tools** (`osint_domain_recon`, `osint_username_search`, `osint_ip_investigate`,
  …) make live requests to third-party sites and services.
- **Red-team tools** (`red_*`) generate offensive payloads/wordlists for use only
  against authorised targets.

Because these need outbound access, the container is **not** run with
`internal: true` by default. For challenge sets that are purely offline
(crypto/forensics/rev/stego files), uncomment `internal: true` in
`docker-compose.yml` to cut egress entirely — the strongest containment. The
sandboxing above protects your *host*; it does not stop a tool from reaching an
out-of-scope target on the network, so that restraint is on you.

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
