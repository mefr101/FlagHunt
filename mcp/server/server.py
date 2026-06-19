#!/usr/bin/env python3
"""CTF toolbox MCP server.

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


if __name__ == "__main__":
    # Host/port are read from FASTMCP_HOST / FASTMCP_PORT (set in the Dockerfile).
    mcp.run(transport="streamable-http")
