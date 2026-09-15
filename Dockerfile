# =============================================================================
# Reynard — Web-focused runtime (Kali) with optional tool profiles
# =============================================================================
# The DEFAULT image is a lean WEB security runtime: recon (ProjectDiscovery
# toolchain), web scanners, class-specific web tools (JWT/deserialization/SSTI),
# and headless Chromium. Unrelated CTF/binary/mobile/wireless/forensics tooling
# is OFF by default and enabled per-profile via build args, so a bug-bounty /
# pentest image stays small and fast to build.
#
# Build (web-only, default):
#   docker compose build
# Build with extra profiles:
#   docker compose build --build-arg PROFILE_PWN=1 --build-arg PROFILE_FORENSICS=1
#   # or set them in docker-compose.yml build.args
#
# Profiles: PROFILE_PWN, PROFILE_MOBILE, PROFILE_WIRELESS, PROFILE_FORENSICS,
#           PROFILE_METASPLOIT, PROFILE_HACKINGTOOL  (each "1" to enable)
# =============================================================================

FROM kalilinux/kali-rolling

LABEL maintainer="reynard"
LABEL description="Web-focused autonomous security runtime (optional CTF/mobile/wireless/forensics profiles)"

ENV DEBIAN_FRONTEND=noninteractive
ENV TERM=xterm-256color

# ---- optional profile switches (off by default) ----------------------------
ARG PROFILE_PWN=0
ARG PROFILE_MOBILE=0
ARG PROFILE_WIRELESS=0
ARG PROFILE_FORENSICS=0
ARG PROFILE_METASPLOIT=0
ARG PROFILE_HACKINGTOOL=0

# tshark is non-interactive-safe when dumpcap is not setuid (we only read pcaps).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

# ---------------------------------------------------------------------------
# 1. WEB BASE — always installed
# ---------------------------------------------------------------------------
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    # Core utilities
    git curl wget unzip jq tree vim nano tmux \
    # Networking (recon reaches the target over these)
    net-tools iputils-ping dnsutils nmap netcat-openbsd socat \
    # libpcap for naabu (fast port scanning)
    libpcap-dev \
    # Languages & runtimes
    python3 python3-pip python3-venv python3-dev \
    golang ruby ruby-dev \
    # JRE for ysoserial + PHP CLI for phpggc gadget chains (web deserialization)
    default-jre-headless php-cli \
    # Build tools
    build-essential cmake pkg-config libssl-dev libffi-dev \
    # Web testing
    sqlmap nikto dirb gobuster wfuzz whatweb \
    # Auth brute-force + credential/JWT cracking (web-adjacent)
    hydra john \
    # Proxy & interception
    proxychains4 tor \
    # Wordlists
    seclists wordlists \
    # SSL/TLS
    sslscan testssl.sh \
    # Container/process tools
    procps \
    && (gzip -dkf /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true) \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. WEB BASE — Go recon toolchain (ProjectDiscovery + friends)
# ---------------------------------------------------------------------------
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

RUN go install github.com/tomnomnom/httprobe@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
    && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/ffuf/ffuf/v2@latest \
    && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
    && ln -sf /root/go/bin/interactsh-client /usr/local/bin/interactsh-client

RUN set -eux; \
    for bin in httprobe waybackurls nuclei subfinder httpx dnsx naabu katana ffuf interactsh-client; do \
        command -v "$bin" >/dev/null 2>&1 \
            || { echo "FATAL: required Go tool '$bin' missing after install" >&2; exit 1; }; \
    done

# ---------------------------------------------------------------------------
# 3. WEB BASE — class-specific OSS tools (JWT / deserialization / SSTI)
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip3 install --break-system-packages termcolor cryptography pycryptodomex requests \
    && chmod +x /opt/jwt_tool/jwt_tool.py \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc \
    && ln -sf /opt/phpggc/phpggc /usr/local/bin/phpggc

RUN git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap \
    && pip3 install --break-system-packages -r /opt/sstimap/requirements.txt 2>/dev/null || true \
    && printf '#!/bin/sh\nexec python3 /opt/sstimap/sstimap.py "$@"\n' > /usr/local/bin/sstimap \
    && chmod +x /usr/local/bin/sstimap

ENV YSOSERIAL_VERSION=0.0.6
RUN mkdir -p /opt/ysoserial \
    && wget -q -O /opt/ysoserial/ysoserial.jar \
        "https://github.com/frohoff/ysoserial/releases/download/v${YSOSERIAL_VERSION}/ysoserial-all.jar" \
    && test -s /opt/ysoserial/ysoserial.jar

RUN set -eux; \
    command -v jwt_tool >/dev/null 2>&1 || { echo "FATAL: jwt_tool missing" >&2; exit 1; }; \
    command -v phpggc >/dev/null 2>&1 || { echo "FATAL: phpggc missing" >&2; exit 1; }; \
    command -v sstimap >/dev/null 2>&1 || { echo "FATAL: sstimap (tplmap) missing" >&2; exit 1; }; \
    command -v java >/dev/null 2>&1 || { echo "FATAL: java (ysoserial runtime) missing" >&2; exit 1; }; \
    test -s /opt/ysoserial/ysoserial.jar || { echo "FATAL: ysoserial.jar missing" >&2; exit 1; }; \
    command -v sqlmap >/dev/null 2>&1 || { echo "FATAL: sqlmap missing" >&2; exit 1; }; \
    command -v interactsh-client >/dev/null 2>&1 || { echo "FATAL: interactsh-client missing" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 4. WEB BASE — headless Chromium (real DOM/JS + alert() capture + app mapping)
# ---------------------------------------------------------------------------
RUN pip3 install --break-system-packages playwright \
    && playwright install --with-deps chromium

RUN set -eux; \
    python3 -c "from playwright.sync_api import sync_playwright; \
p=sync_playwright().start(); b=p.chromium.launch(args=['--no-sandbox']); \
b.close(); p.stop(); print('playwright chromium OK')"

# ---------------------------------------------------------------------------
# 5. OPTIONAL PROFILE — binary / pwn / reverse engineering
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_PWN" = "1" ]; then \
        apt-get update && apt-get install -y \
            radare2 binwalk gdb gdb-multiarch exploitdb hashcat \
        && pip3 install --break-system-packages pwntools \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# 6. OPTIONAL PROFILE — mobile (Android)
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_MOBILE" = "1" ]; then \
        apt-get update && apt-get install -y adb apktool jadx \
        && pip3 install --break-system-packages frida-tools objection \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# 7. OPTIONAL PROFILE — wireless / MITM
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_WIRELESS" = "1" ]; then \
        apt-get update && apt-get install -y aircrack-ng bettercap ettercap-text-only \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# 8. OPTIONAL PROFILE — forensics / stego
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_FORENSICS" = "1" ]; then \
        apt-get update && apt-get install -y \
            foremost steghide libimage-exiftool-perl tshark \
        && gem install zsteg \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# 9. OPTIONAL PROFILE — Metasploit framework (heavy)
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_METASPLOIT" = "1" ]; then \
        apt-get update && apt-get install -y metasploit-framework \
        && apt-get clean && rm -rf /var/lib/apt/lists/*; \
    fi

# ---------------------------------------------------------------------------
# 10. OPTIONAL PROFILE — Z4nzu hackingtool meta-toolkit
# ---------------------------------------------------------------------------
RUN if [ "$PROFILE_HACKINGTOOL" = "1" ]; then \
        git clone https://github.com/Z4nzu/hackingtool.git /opt/hackingtool \
        && cd /opt/hackingtool \
        && pip3 install --break-system-packages -r requirements.txt 2>/dev/null || true \
        && chmod +x hackingtool.py 2>/dev/null || true; \
    fi

# ---------------------------------------------------------------------------
# 11. Persistent data directories + cookie jar
# ---------------------------------------------------------------------------
RUN mkdir -p /data/cookies /data/loot /data/scripts /data/logs \
    /data/methodologies /data/sessions /data/reports /data/oob \
    && touch /data/cookies/cookies.txt

WORKDIR /data

# Keep container alive (headless mode)
CMD ["tail", "-f", "/dev/null"]
