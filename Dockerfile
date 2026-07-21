# =============================================================================
# Reynard — Kali Linux Docker Environment
# =============================================================================
# Headless Kali container with full pentesting toolkit.
#
# Build:  docker compose build
# Run:    docker compose up -d
# Exec:   docker exec -it reynard-kali bash
# =============================================================================

FROM kalilinux/kali-rolling

LABEL maintainer="reynard"
LABEL description="Headless Kali Linux with Z4nzu hackingtool + full pentesting suite"

# ---------------------------------------------------------------------------
# 1. Prevent interactive prompts during package installation
# ---------------------------------------------------------------------------
ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# ---------------------------------------------------------------------------
# 2. Update repos and install core system dependencies
# ---------------------------------------------------------------------------
# tshark is non-interactive-safe when dumpcap is not setuid (we only read pcaps).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    # Core utilities
    git curl wget unzip jq tree vim nano tmux \
    # Networking
    net-tools iputils-ping dnsutils nmap netcat-openbsd socat \
    # Languages & runtimes
    python3 python3-pip python3-venv python3-dev \
    golang ruby ruby-dev \
    # JRE for ysoserial (Java deserialization) + PHP CLI for phpggc gadget chains
    default-jre-headless php-cli \
    # Build tools
    build-essential cmake pkg-config libssl-dev libffi-dev \
    # Web testing
    sqlmap nikto dirb gobuster wfuzz whatweb \
    # Exploitation
    metasploit-framework exploitdb \
    # Proxy & interception
    proxychains4 tor \
    # Wireless (useful for some tools even in containers)
    aircrack-ng \
    # Reverse engineering + debugging (pwn/rev workflows)
    radare2 binwalk gdb gdb-multiarch \
    # Password cracking
    john hashcat hydra \
    # Forensics (steghide/foremost + exiftool metadata + tshark for pcap)
    foremost steghide libimage-exiftool-perl tshark \
    # Man-in-the-middle
    bettercap ettercap-text-only \
    # Android tools
    adb apktool jadx \
    # Misc Kali tools
    seclists wordlists \
    # SSL/TLS
    sslscan testssl.sh \
    # Container/process tools
    procps \
    # Frida for Android instrumentation + pwntools for binary exploitation
    && pip3 install --break-system-packages frida-tools objection pwntools \
    # zsteg (Ruby) for PNG/BMP LSB steganography
    && gem install zsteg \
    # Make rockyou immediately usable for hash_crack (Kali ships it gzipped)
    && (gzip -dkf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true) \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 3. Install Z4nzu hackingtool
# ---------------------------------------------------------------------------
RUN git clone https://github.com/Z4nzu/hackingtool.git /opt/hackingtool \
    && cd /opt/hackingtool \
    && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true \
    && chmod +x hackingtool.py 2>/dev/null || true

# ---------------------------------------------------------------------------
# 4. Install additional Go-based tools
# ---------------------------------------------------------------------------
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# Fail the build loudly if any required Go tool does not install — a silently
# missing binary here breaks recon at runtime and is much harder to diagnose.
RUN go install github.com/tomnomnom/httprobe@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client

# Verify every required Go binary is present and on PATH; abort the build if not.
RUN set -eux; \
    for bin in httprobe waybackurls nuclei subfinder httpx ffuf interactsh-client; do \
        command -v "$bin" >/dev/null 2>&1 \
            || { echo "FATAL: required Go tool '$bin' missing after install" >&2; exit 1; }; \
    done

# ---------------------------------------------------------------------------
# 4b. Class-specific OSS tools (JWT / deserialization / SSTI)
#     Each is verified below; a missing REQUIRED tool aborts the build.
# ---------------------------------------------------------------------------
# jwt_tool (ticarpi) — JWT analysis / cracking / alg-confusion exploitation.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip3 install --break-system-packages termcolor cryptography pycryptodomex requests \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

# phpggc (ambionics) — PHP object-injection / deserialization gadget chains.
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc \
    && ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc

# SSTImap (vladko312) — maintained Python 3 fork of tplmap for SSTI detection.
RUN git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap \
    && pip3 install --break-system-packages -r /opt/sstimap/requirements.txt 2>/dev/null || true \
    && printf '#!/bin/sh\nexec python3 /opt/sstimap/sstimap.py "$@"\n' > /usr/local/bin/sstimap \
    && chmod +x /usr/local/bin/sstimap

# ysoserial (frohoff) — Java deserialization payload generator (large; pinned).
# NOTE: this is a ~1MB fat JAR pulled from a pinned release; if the release URL
# changes, update YSOSERIAL_VERSION. Marked required — the build fails if absent.
ENV YSOSERIAL_VERSION=0.0.6
RUN mkdir -p /opt/ysoserial \
    && wget -q -O /opt/ysoserial/ysoserial.jar \
        "https://github.com/frohoff/ysoserial/releases/download/v${YSOSERIAL_VERSION}/ysoserial-all.jar" \
    && test -s /opt/ysoserial/ysoserial.jar

# Verify every REQUIRED class-specific tool is present; abort the build if not.
RUN set -eux; \
    command -v jwt_tool >/dev/null 2>&1 || { echo "FATAL: jwt_tool missing" >&2; exit 1; }; \
    command -v phpggc >/dev/null 2>&1 || { echo "FATAL: phpggc missing" >&2; exit 1; }; \
    command -v sstimap >/dev/null 2>&1 || { echo "FATAL: sstimap (tplmap) missing" >&2; exit 1; }; \
    command -v java >/dev/null 2>&1 || { echo "FATAL: java (ysoserial runtime) missing" >&2; exit 1; }; \
    test -s /opt/ysoserial/ysoserial.jar || { echo "FATAL: ysoserial.jar missing" >&2; exit 1; }; \
    command -v sqlmap >/dev/null 2>&1 || { echo "FATAL: sqlmap missing" >&2; exit 1; }; \
    command -v interactsh-client >/dev/null 2>&1 || { echo "FATAL: interactsh-client missing" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 5. Create persistent data directories
# ---------------------------------------------------------------------------
RUN mkdir -p /data/cookies /data/loot /data/scripts /data/logs \
    /data/methodologies /data/sessions /data/reports /data/oob

# ---------------------------------------------------------------------------
# 6. Install headless Chromium via Playwright (real DOM/JS + alert() capture)
#    The browser runs INSIDE this container; tools.py drives it over docker exec.
# ---------------------------------------------------------------------------
RUN pip3 install --break-system-packages playwright \
    && playwright install --with-deps chromium

# Verify Playwright + Chromium are usable; abort the build loudly if not.
RUN set -eux; \
    python3 -c "from playwright.sync_api import sync_playwright; \
p=sync_playwright().start(); b=p.chromium.launch(args=['--no-sandbox']); \
b.close(); p.stop(); print('playwright chromium OK')"

# ---------------------------------------------------------------------------
# 7. Configure cookie jar for curl
# ---------------------------------------------------------------------------
RUN touch /data/cookies/cookies.txt

# ---------------------------------------------------------------------------
# 8. Set working directory
# ---------------------------------------------------------------------------
WORKDIR /data

# ---------------------------------------------------------------------------
# 8. Keep container alive (headless mode)
# ---------------------------------------------------------------------------
CMD ["tail", "-f", "/dev/null"]
