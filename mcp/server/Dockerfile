FROM python:3.12-slim

# CLI utilities that the forensics / reversing / stego / pcap tools shell out to.
# tshark is preseeded to NOT install setuid dumpcap -- we only read capture files,
# never sniff live traffic, so it never needs capture privileges.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        file \
        binutils \
        binwalk \
        libimage-exiftool-perl \
        steghide \
        tshark \
        ruby \
        john \
        yara \
        gdb \
        gcc \
        nasm \
        python3-dev \
        build-essential \
    && gem install --no-document zsteg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .

# Serve Streamable HTTP on all interfaces *inside* the container; the host
# only exposes it on localhost (see docker-compose.yml). XDG_CACHE_HOME points
# pwntools' cache at the writable tmpfs since the root filesystem is read-only.
ENV FASTMCP_HOST=0.0.0.0 \
    FASTMCP_PORT=8000 \
    CTF_WORKSPACE=/workspace \
    CTF_SCRATCH=/tmp/ctf \
    XDG_CACHE_HOME=/tmp/.cache \
    PWNLIB_NOTERM=1

# Drop to an unprivileged user.
RUN useradd --create-home --uid 10001 runner
USER runner

EXPOSE 8000
CMD ["python", "server.py"]
