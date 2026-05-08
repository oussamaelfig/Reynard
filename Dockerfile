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
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    # Core utilities
    git curl wget unzip jq tree vim nano tmux \
    # Networking
    net-tools iputils-ping dnsutils nmap netcat-openbsd socat \
    # Languages & runtimes
    python3 python3-pip python3-venv python3-dev \
    golang ruby ruby-dev \
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
    # Reverse engineering
    radare2 binwalk \
    # Password cracking
    john hashcat hydra \
    # Forensics
    foremost steghide \
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
    # Frida for Android instrumentation
    && pip3 install --break-system-packages frida-tools objection \
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

RUN go install github.com/tomnomnom/httprobe@latest 2>/dev/null || true \
    && go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true \
    && go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true \
    && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || true \
    && ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Create persistent data directories
# ---------------------------------------------------------------------------
RUN mkdir -p /data/cookies /data/loot /data/scripts /data/logs \
    /data/methodologies /data/sessions /data/reports /data/oob

# ---------------------------------------------------------------------------
# 6. Install Lightpanda headless browser (AI-optimized, JS via v8)
#    https://github.com/lightpanda-io/browser
# ---------------------------------------------------------------------------
RUN curl -L -o /usr/local/bin/lightpanda \
    https://github.com/lightpanda-io/browser/releases/download/nightly/lightpanda-x86_64-linux \
    && chmod +x /usr/local/bin/lightpanda

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
