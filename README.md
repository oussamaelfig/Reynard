# 🦊 Reynard

<p align="center">
  <b>Autonomous AI agent for CTF labs and authorized security testing</b>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-Kali%20Runtime-2496ED?style=for-the-badge&logo=docker&logoColor=white">
  <img alt="Kali" src="https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white">
  <img alt="CTF" src="https://img.shields.io/badge/CTF-Ready-00C853?style=for-the-badge">
  <img alt="Authorized Use" src="https://img.shields.io/badge/Authorized%20Use-Only-E53935?style=for-the-badge">
</p>

Reynard is a structured multi-agent hacking assistant that runs against **authorized CTF, lab, and pentest targets**. It combines LLM reasoning with a Kali Docker runtime, live dashboard, persistent memory, payload deduplication, web research, Caido local/Cloud integrations, optional Burp MCP fallback hooks, and a curated tool-selection catalog.

> **Use only on systems you own, intentionally vulnerable labs, CTF infrastructure, or targets where you have explicit written authorization.**

---

## ✨ Highlights

- 🧠 **Multi-agent workflow**: coordinator, bounded bootstrap subagents, recon, analyst, exploitation, validator, reporter.
- 🛠️ **Kali tool runtime**: `sqlmap`, `nmap`, `ffuf`, `nuclei`, `gobuster`, `nikto`, `john`, `hashcat`, `radare2`, `binwalk`, `frida`, `objection`, and more.
- 🧰 **Z4nzu HackingTool awareness**: `/opt/hackingtool/hackingtool.py` is available inside the container, with direct tools preferred for automation.
- 👀 **Live dashboard**: watch decisions, tool calls, findings, memory, and validation while the agent runs.
- 🔎 **Web research**: CTF writeups, public CVEs, advisories, and official docs via `web_search` / `web_fetch`.
- 🧾 **Memory and deduplication**: remembers payloads, failed attempts, facts, knowledge graph entities, and lessons.
- 🔁 **PoC validation**: validator replays successful payloads and demotes weak findings.
- 🧪 **Expert lab playbooks**: deterministic priors for PortSwigger practitioner/expert classes including JWT, request smuggling, cache poisoning, SSTI, prototype pollution, GraphQL, race conditions, and business logic labs.
- 📏 **Offline lab readiness eval**: `reynard-lab-eval` checks target parsing, profile detection, prerequisites, and evidence plan before a live run.
- 🧵 **Bounded subagents**: safe profile/readiness/analysis lanes run in parallel; exploitation remains serialized unless a race-condition playbook explicitly opts in.
- ☁️ **Caido support**: local Replay/history bridge for testing plus Cloud API for user/team/workspace/subscription/PAT operations.
- 🧩 **Burp MCP fallback**: traffic/repeater/intruder/collaborator tools when the Burp MCP extension is online.

---

## ⚠️ Scope And Safety

Reynard is designed for:

- ✅ PortSwigger Web Security Academy labs
- ✅ Hack The Box / TryHackMe / CTF boxes you are allowed to attack
- ✅ Local vulnerable apps such as DVWA, Juice Shop, WebGoat, intentionally vulnerable Docker labs
- ✅ Authorized pentest environments with a defined scope

Do not use Reynard for:

- ❌ Targets without permission
- ❌ DDoS, phishing, RAT, credential stuffing, or social engineering outside a sanctioned lab
- ❌ Wireless deauth or disruptive testing unless explicitly in scope
- ❌ Production testing without rate limits, test windows, and written approval

---

## 🧭 Architecture

```mermaid
flowchart LR
    User["User Objective"] --> Orchestrator["Multi-Agent Orchestrator"]
    Orchestrator --> Coordinator["Coordinator"]
    Coordinator --> Recon["Recon"]
    Coordinator --> Analyst["Analyst"]
    Coordinator --> Exploit["Exploitation"]
    Coordinator --> Validator["Validator"]
    Coordinator --> Reporter["Reporter"]
    Recon --> Memory["Knowledge Graph + Memory"]
    Analyst --> Memory
    Exploit --> Evidence["PoC Evidence Store"]
    Validator --> Evidence
    Exploit --> Tools["Kali Docker Tools"]
    Recon --> Tools
    Tools --> Docker["reynard-kali"]
    Orchestrator --> UI["Live Dashboard"]
```

---

## 📁 Project Structure

```text
reynard/
|-- agent.py                 # Single-agent compatibility launcher
|-- orchestrator.py          # Multi-agent launcher
|-- Dockerfile               # Kali image with tools, Lightpanda, Z4nzu HackingTool
|-- docker-compose.yml       # Starts container named reynard-kali
|-- requirements.txt         # Python dependencies
|-- pyproject.toml           # Package metadata
|-- .env.example             # Safe environment template
|-- methodologies/           # Bug-class playbooks mounted to /data/methodologies
|-- logs/                    # Run logs, ignored by git
|-- tests/                   # Tests and fixtures
`-- src/hacking_agent/
    |-- agents/              # coordinator, recon, analyst, exploitation, validator, reporter
    |-- cli/                 # CLI entry points
    |-- core/                # memory, schemas, tools, state machine, providers
    |-- integrations/        # Burp and Caido clients
    `-- ui/                  # Live dashboard
```

---

## 🚀 Quick Start On Windows PowerShell

### 1. Configure environment

```powershell
Copy-Item .env.example .env
notepad .env
```

Set at least one LLM provider key. Example for DeepSeek/OpenAI-compatible:

```env
LLM_DEFAULT_PROVIDER=openai-compatible
LLM_DEFAULT_MODEL=deepseek-v4-pro
LLM_DEFAULT_BASE_URL=https://api.deepseek.com/v1
LLM_DEFAULT_API_KEY=sk-your-key
```

### 2. Install Python dependencies

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Build and start the Kali runtime

```powershell
docker compose build
docker compose up -d
docker ps --filter "name=reynard-kali"
```

The container is named:

```text
reynard-kali
```

The image can be large and the first build can take a long time because it installs Kali packages, Go tools, Lightpanda, and the Z4nzu HackingTool repository.

### 4. Run the multi-agent orchestrator

```powershell
python orchestrator.py --ui --no-oob --max-iterations 25 "Solve this authorized CTF/lab target: https://TARGET"
```

Bounded bootstrap subagents are enabled by default:

```powershell
python orchestrator.py --max-subagents 4 "Authorized lab: https://TARGET"
python orchestrator.py --no-subagents "Authorized lab: https://TARGET"
```

The dashboard opens at:

```text
http://127.0.0.1:8765
```

---

## 🏁 Running Against A CTF Or Lab

### PortSwigger lab example

Run a quick offline readiness check first:

```powershell
reynard-lab-eval --case "JWT authentication bypass lab. Target: https://YOUR-LAB.web-security-academy.net/" --pretty
reynard-lab-eval --pretty
```

The default evaluator suite covers every PortSwigger topic mapped in
`docs/portswigger-coverage-matrix.md`.

```powershell
python orchestrator.py --ui --no-oob --max-iterations 25 "Solve this authorized PortSwigger Web Security Academy lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data. Target: https://YOUR-LAB.web-security-academy.net/"
```

### CTF web challenge example

```powershell
python orchestrator.py --ui --max-iterations 40 "Authorized CTF target: http://10.10.10.10/. Scope: this single host only. Goal: enumerate the web app, identify the intended vulnerability, and capture the flag."
```

### CTF box with multiple services

```powershell
python orchestrator.py --ui --max-iterations 60 "Authorized CTF box: 10.10.10.10. Scope: single host only. Perform service recon, web enumeration, vulnerability analysis, exploitation proof, and report the flag path."
```

Recommended CTF flags:

- Use `--ui` so you can watch reasoning and tool calls.
- Use `--no-oob` for simple labs where blind callbacks are not needed.
- Set a clear scope in the prompt: host, domain, lab URL, allowed ports, and goal.
- Keep `--max-iterations` lower for simple web labs and higher for full boxes.

---

## 🛡️ Running In An Authorized Pentest Environment

Use a clear scope and rules of engagement in the prompt:

```powershell
python orchestrator.py --ui --max-iterations 60 "Authorized pentest assessment for https://app.example.com. Scope: app.example.com only. Test OWASP Top 10 classes. Avoid destructive actions, brute force, phishing, DDoS, persistence, and data modification. Produce reproducible PoCs and a final report."
```

With authenticated sessions:

```powershell
python orchestrator.py --ui --auth-file .\auth-sessions.json --max-iterations 60 "Authorized pentest assessment for https://app.example.com. Scope: app.example.com only. Test access control using the configured user sessions."
```

Example `auth-sessions.json`:

```json
{
  "sessions": {
    "user1": {
      "headers": {
        "Cookie": "session=USER1_COOKIE"
      }
    },
    "user2": {
      "headers": {
        "Cookie": "session=USER2_COOKIE"
      }
    }
  }
}
```

Pentest guidance:

- Define scope explicitly: domains, IPs, roles, test accounts, time window.
- State what is forbidden: brute force, destructive payloads, persistence, phishing, DDoS.
- Use `--auth-file` for IDOR and authorization testing.
- Keep the dashboard open and stop the run if it drifts outside scope.

---

## 👀 Live Dashboard

Start with `--ui`:

```powershell
python orchestrator.py --ui "Authorized lab: https://TARGET"
```

The dashboard shows:

- live model plan/decision trace
- coordinator routing
- specialist dispatches
- tool calls and blocked duplicate payloads
- web research events
- memory facts and knowledge graph updates
- PoC evidence and validation results
- provider and schema errors

Provider-hidden reasoning is not exposed unless the model provider explicitly returns a reasoning stream. The UI shows the agent's visible reasoning, decisions, and tool activity.

---

## 🧰 Tool Runtime

Reynard uses a Docker container named `reynard-kali`. Tools are executed through `run_shell`, and the agent can call `tool_inventory` to decide what to use.

Check inventory manually:

```powershell
$env:PYTHONPATH="src"
python -c "from hacking_agent.core.tools import execute_tool; print(execute_tool('tool_inventory', {'role':'general','check_container':True}))"
```

### Preferred direct tools

| Goal | Preferred tools |
|---|---|
| HTTP proof payloads | `http_request`, `curl` |
| SQL injection | `curl` for simple proof, `sqlmap` for blind/complex extraction |
| Web content discovery | `ffuf`, `gobuster`, `dirb`, `wfuzz` |
| Known CVEs and misconfig | `nuclei`, `nikto`, `whatweb` |
| Port/service recon | `nmap`, `masscan` or `rustscan` if available |
| JS/API endpoint discovery | `extract_js_endpoints`, `katana`, `gospider`, `SecretFinder` if available |
| XSS testing | `browser_execute_js`, `dalfox`, `XSStrike` if available |
| Secrets in repos/files | `trufflehog`, `gitleaks`, `SecretFinder` if available |
| Password/hash work | `john`, `hashcat`, `haiti` if available |
| AD labs | `impacket`, `nxc`, `BloodHound`, `Certipy`, `Kerbrute` if available |
| Cloud/container labs | `prowler`, `pacu`, `ScoutSuite`, `trivy` if available |
| Reversing/mobile | `radare2`, `ghidra`, `jadx`, `apktool`, `frida`, `objection` |
| Forensics/stego | `binwalk`, `foremost`, `steghide`, `volatility3` if available |

---

## 🧰 Z4nzu HackingTool

The Dockerfile clones:

```text
https://github.com/Z4nzu/hackingtool.git
```

Inside the container:

```text
/opt/hackingtool/hackingtool.py
```

Run manually:

```powershell
docker exec -it reynard-kali bash
python3 /opt/hackingtool/hackingtool.py
```

Reynard is aware of this wrapper and its major categories:

- 🛡️ anonymity / proxying helpers
- 🔍 information gathering
- 📚 wordlist and hash tools
- 🌐 web attack tools
- 🧩 SQL injection tools
- 💥 XSS tools
- 🕵️ forensics and stego tools
- 🔁 reverse engineering tools
- 📱 mobile security tools
- 🏢 Active Directory tools
- ☁️ cloud security tools
- 🔧 post-exploitation tooling for authorized labs

Important automation rule:

> The agent should prefer direct non-interactive commands such as `sqlmap`, `ffuf`, `nuclei`, `nmap`, `dalfox`, `trufflehog`, `john`, or `hashcat` when available. The Z4nzu menu is useful as a wrapper/reference, but interactive menus are less reliable for autonomous runs.

Risk-controlled categories such as phishing, DDoS, RATs, social brute force, and wireless deauth are not appropriate for normal autonomous runs unless the lab explicitly authorizes that exact behavior.

---

## ☁️ Caido

Reynard separates **Caido Cloud** from **Caido Local Bridge**:

- `caido_local_api` is the preferred path for API testing, Replay, HTTP
  history, request collections, and manual-review artifacts when the local
  bridge plugin is running.
- `caido_cloud_api` is only for Caido account/team/workspace/PAT operations.

Configure Cloud API:

```env
CAIDO_PAT=caido_YOUR_PERSONAL_ACCESS_TOKEN
CAIDO_API_BASE_URL=https://api.caido.io
```

Configure the local bridge:

```env
CAIDO_LOCAL_BRIDGE_URL=http://127.0.0.1:17650
CAIDO_LOCAL_BRIDGE_TOKEN=optional-shared-secret
```

Cloud API support:

- Caido Cloud status
- user/team information
- invitations
- workspaces
- subscriptions
- vouchers
- PAT lifecycle helpers
- raw Cloud API fallback paths

Local bridge support:

- bridge status
- send raw requests through Caido Replay
- create/send Replay sessions
- search HTTP history
- fetch history items
- create Caido findings from agent evidence

See `docs/caido-local-bridge.md` for the expected bridge contract.

---

## 🧩 Burp MCP

Burp MCP is now a fallback for Burp-specific workflows. If your Burp MCP
extension is running, Reynard can use:

- send raw HTTP/1.1 requests
- read scanner issues
- generate Collaborator payloads
- poll Collaborator interactions
- create Repeater tabs
- send requests to Intruder

If Burp MCP is offline, the agent falls back to Caido Local Bridge,
`http_request`, `curl`, OOB callbacks, and differential analysis.

---

## 🔎 Web Research

Optional search providers:

```env
BRAVE_SEARCH_API_KEY=YOUR_BRAVE_KEY
SERPAPI_API_KEY=YOUR_SERPAPI_KEY
```

The agent uses `web_search` and `web_fetch` when:

- a challenge/box name is known
- a service/version banner is discovered
- a CVE or public exploit may apply
- a command is missing or install syntax is unclear
- a tool returns an unknown flag/usage error
- it gets stuck after targeted attempts
- official docs or writeups can reduce guessing

For best search quality, configure Brave or SerpAPI. If neither key is set,
Reynard falls back to DuckDuckGo HTML search.

For blind XXE/SSRF/CMDi labs, do **not** use `--no-oob`; the agent needs OOB
callbacks through `interactsh-client`, Burp Collaborator, or another approved
callback service.

---

## 🤖 LLM Providers

| Provider | Required key env | Notes |
|---|---|---|
| `deepseek` | `DEEPSEEK_API_KEY` | OpenAI-compatible DeepSeek API |
| `openai` / `gpt` | `OPENAI_API_KEY` | OpenAI models |
| `anthropic` / `claude` | `ANTHROPIC_API_KEY` | Claude Messages API |
| `qwen` / `dashscope` | `QWEN_API_KEY` or `DASHSCOPE_API_KEY` | Qwen/DashScope |
| `local` | optional | OpenAI-compatible local server at `http://localhost:8000/v1` |
| `ollama` | optional | OpenAI-compatible Ollama at `http://localhost:11434/v1` |
| `openai-compatible` | `LLM_DEFAULT_API_KEY` | Custom OpenAI-compatible gateway |

Reasoning controls:

```env
LLM_DEFAULT_REASONING_EFFORT=high
LLM_ANALYST_REASONING_EFFORT=high
LLM_EXPLOITATION_REASONING_EFFORT=high
LLM_COORDINATOR_THINKING=true
LLM_COORDINATOR_THINKING_BUDGET=8000
LLM_DEFAULT_ENABLE_THINKING_PARAM=false
```

Unsupported provider-specific reasoning parameters are downgraded automatically at runtime.

---

## 🧪 Common Commands

Start runtime:

```powershell
docker compose up -d
```

Check runtime:

```powershell
docker ps --filter "name=reynard-kali"
```

Open a shell in Kali:

```powershell
docker exec -it reynard-kali bash
```

Run multi-agent mode:

```powershell
python orchestrator.py --ui --max-iterations 40 "Authorized target: https://TARGET"
```

Run single-agent mode:

```powershell
python agent.py --ui "Authorized target: https://TARGET"
```

Stop runtime:

```powershell
docker compose down
```

---

## 🧾 Logs And Output

Runtime logs are written under:

```text
logs/
```

The agent records:

- tool calls
- payload history
- failed attempts
- knowledge graph entities
- facts and relationships
- PoC evidence
- validation outcomes
- final report summaries

---

## ✅ Recommended Workflow

1. Start Docker: `docker compose up -d`
2. Run with `--ui`
3. Give an explicit authorized scope
4. Watch the dashboard
5. Let the validator replay any successful PoC
6. Review the final report
7. Save useful lessons into methodologies if the agent struggled

---

## Legal Notice

Reynard is for education, CTFs, research labs, and authorized security assessments only. You are responsible for ensuring that every target, technique, and tool invocation is permitted by the applicable rules of engagement and law.
